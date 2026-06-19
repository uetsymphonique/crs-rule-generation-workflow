#!/usr/bin/env python3
"""parse_targets.py — project Stage-1 variant-handoff.json + probe.json to crs-variant-gen whitelist.

Usage:
    python .claude/skills/crs-variant-gen/tools/parse_targets.py \
        <variant-handoff.json> <probe.json> <variant-context.json> \
        [--gen-variants=class-only|root-cause-only|all-triggered-rules]

variant-handoff.json is written by crs-retrieve-analyze (stage VARIANT-HANDOFF)
after INSPECT-ROOT-CAUSE (covered) or after adjudication (not-covered), before
RETRIEVE runs. It contains the model's judgment (root_cause_rules, top-level
rule_analysis, classification, payload_samples) without candidate_rules (not yet
computed). rule_analysis is a flat array here — the wrapping recommendation object
(with summary/pl_coverage) only exists later in analysis.json. probe.json supplies
matched_rules and paranoia from the engine oracle.

Because variant-handoff.json + probe.json exist at the same point in both the
bg-agent path (spawned mid-Stage-1) and the standalone path (invoked after Stage-1
completes), there is no need for two CLI modes — this single signature covers both.

crs-variant-gen does NOT depend on crs-rule-author's parse_verdict.py / author-context.json.
The "regex target rule" set is MODE-GATED by `--gen-variants` (proposal §4) —
candidate_rules is deliberately NOT used here:
  - class-only (default) : targets = []. No rule anchors at all — the skill crafts
    breadth from classification.families + payload_samples + template mechanism
    (technique enumeration). Use when CRS has no useful "fall-outside-this-regex"
    signal, or to brainstorm bypass ways straight from the template.
  - root-cause-only : targets = root_cause_rules ⨝ rule_analysis (by id, both
    top-level). The root-cause regex is ALREADY in variant-handoff as pattern_excerpt.
    Falls back to class-only when there are no root_cause_rules (not-covered).
  - all-triggered-rules : targets = probe.matched_rules (all fired rules, incl.
    off-class SQLi/XSS/protocol). Targets hold id+tags only; the skill resolves
    id→file/line via the Stage-1 index tsv and Reads the .conf block for @rx pattern.
    Falls back to class-only when no rule fired (matched_rules empty).

FALLBACK RULE (proposal): root-cause-only / all-triggered-rules need a field that may
be absent (no root_cause_rules / no matched_rules). When that field is empty, the
requested mode cannot anchor anything, so the script DOWNGRADES mode to "class-only"
with targets=[] — the skill then crafts from family/mechanism instead of from rules.
There is no PoC-only passthrough here: gen-variants=off is handled upstream by
crs-retrieve-analyze (it writes a PoC-only extended-requests.json without spawning
this skill), so whenever parse_targets runs the skill always crafts variants.

Output schema (everything the skill reads, nothing else):
    {
      "template_id", "template_path",
      "classification": { families, injection_point, injection_slot, protocol },
      "payload_samples": [ {label, value} ],
      "paranoia": 2,                       # from probe result → Lane-4 Verify PL
      "mode": "class-only" | "root-cause-only" | "all-triggered-rules",
      "targets": [
        # class-only         : []  (no rule anchors; skill crafts from families/payload_samples)
        # root-cause-only    : {id, msg, operator, transforms, pattern_excerpt, matched_at, trigger_explanation}
        # all-triggered-rules: {id, msg, tags, paranoia_level, matched_var}
      ],
      "scope_gate_decision": "in-scope" | "virtual-patch-only" | "out-of-scope-structural" | null
        # null = covered verdict (gate not entered). non-null only on not-covered path.
        # skill halts on virtual-patch-only / out-of-scope-structural (same guard as bg-agent spawn).
    }
"""
import json
import sys

CLASS_KEYS = ("families", "injection_point", "injection_slot", "protocol")
RC_ANALYSIS_KEYS = ("operator", "transforms", "pattern_excerpt", "matched_at", "trigger_explanation")
MATCHED_KEYS = ("id", "msg", "tags", "paranoia_level", "matched_var")

GEN_VARIANTS_DEFAULT = "class-only"
GEN_VARIANTS_CHOICES = ("class-only", "root-cause-only", "all-triggered-rules")


def parse_gen_variants(argv):
    """Read --gen-variants=<mode>; default class-only. (off is handled upstream, never here.)"""
    for a in argv:
        if a.startswith("--gen-variants="):
            v = a.split("=", 1)[1].strip()
            if v not in GEN_VARIANTS_CHOICES:
                sys.exit(f"--gen-variants must be one of {GEN_VARIANTS_CHOICES} (got {v!r})")
            return v
    return GEN_VARIANTS_DEFAULT


def build_rootcause_targets(root_causes):
    """root_cause_rules ⨝ rule_analysis by id (both top-level) — pattern is inline."""
    if not root_causes:
        return []
    rc = root_causes.get("root_cause_rules") or []
    analysis = {a.get("id"): a for a in (root_causes.get("rule_analysis") or [])}
    targets = []
    for r in rc:
        a = analysis.get(r.get("id"), {})
        # root_cause_rules entries are {id, reason}; msg lives on the rule_analysis
        # side (crs-retrieve-analyze writes it there). Prefer root_cause_rules.msg
        # if a producer ever adds it, else fall back to the rule_analysis match.
        t = {"id": r.get("id"), "msg": r.get("msg") or a.get("msg")}
        t.update({k: a.get(k) for k in RC_ANALYSIS_KEYS})
        targets.append(t)
    return targets


def build_alltriggered_targets(probe):
    """All fired rules — id+tags only; skill resolves pattern via index + .conf."""
    out = []
    for r in (probe or {}).get("matched_rules") or []:
        out.append({k: r.get(k) for k in MATCHED_KEYS})
    return out


def load_inputs(handoff_path, probe_path):
    """Load variant-handoff.json + probe.json → normalized dict for downstream functions."""
    with open(handoff_path, encoding="utf-8") as f:
        ho = json.load(f)
    with open(probe_path, encoding="utf-8") as f:
        probe_raw = json.load(f)
    exploit_idx = ho.get("exploit_index", 0)
    results = probe_raw.get("results") or []
    probe = next((r for r in results if r.get("index") == exploit_idx),
                 results[0] if results else {})
    return {
        "template_id": ho.get("template_id"),
        "template_path": ho.get("template_path"),
        "classification": ho.get("classification"),
        "payload_samples": ho.get("payload_samples"),
        "scope_gate": ho.get("scope_gate"),
        "root_causes": {
            "root_cause_rules": ho.get("root_cause_rules") or [],
            "rule_analysis": ho.get("rule_analysis") or [],
        },
        "probe": probe,
    }


def main():
    argv = sys.argv[1:]
    gv = parse_gen_variants(argv)
    pos = [a for a in argv if not a.startswith("--")]

    if len(pos) != 3:
        sys.exit("usage: parse_targets.py <variant-handoff.json> <probe.json> <variant-context.json> "
                 "[--gen-variants=class-only|root-cause-only|all-triggered-rules]")

    v = load_inputs(pos[0], pos[1])
    out_path = pos[2]

    classification = v.get("classification") or {}
    probe = v.get("probe") or {}

    if gv == "root-cause-only":
        targets = build_rootcause_targets(v.get("root_causes"))
        mode = "root-cause-only" if targets else "class-only"  # fallback: no root cause field
    elif gv == "all-triggered-rules":
        targets = build_alltriggered_targets(probe)
        mode = "all-triggered-rules" if targets else "class-only"  # fallback: nothing fired
    else:  # class-only
        mode, targets = "class-only", []

    scope_gate = v.get("scope_gate") or {}
    out = {
        "template_id": v.get("template_id"),
        "template_path": v.get("template_path"),
        "classification": {k: classification.get(k) for k in CLASS_KEYS},
        "payload_samples": v.get("payload_samples") or [],
        "paranoia": probe.get("paranoia"),
        "mode": mode,
        "targets": targets,
        "scope_gate_decision": scope_gate.get("decision"),
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    if mode == "class-only" and gv != "class-only":
        note = f" (no anchors for {gv} -> fallback class-only: craft from families/payload_samples)"
    elif mode == "class-only":
        note = " (class-based craft from families/payload_samples/template)"
    else:
        note = ""
    print(f"{out_path} — mode={mode}, targets={len(targets)}, paranoia={out['paranoia']}{note}")


if __name__ == "__main__":
    main()
