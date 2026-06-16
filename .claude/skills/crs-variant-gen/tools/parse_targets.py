#!/usr/bin/env python3
"""parse_targets.py — project a Stage-1 verdict.json to the crs-variant-gen whitelist.

Usage:
    python .claude/skills/crs-variant-gen/tools/parse_targets.py \
        <verdict.json> <variant-context.json> [--aggressive]   (from repo root)

crs-variant-gen runs BEFORE the New-rule Generator, so it owns its own projection
(it does NOT depend on crs-rule-author's parse_verdict.py / author-context.json).
It keeps ONLY the fields needed to craft same-class request variants that fall
OUTSIDE the regex of the rules currently in play, plus carries probe.paranoia
straight through for Lane-4 Verify.

The "regex target rule" set is MODE-GATED (proposal §4) — candidate_rules is
deliberately NOT used here:
  - focused (default)  : targets = root_cause_rules ⨝ recommendation.rule_analysis
    (by id). The root-cause regex is ALREADY in the verdict as pattern_excerpt, so
    the skill reads no .conf. Empty when not-covered (no root_cause_rules) → the
    skill emits a PoC-only passthrough; run --aggressive to get variants there.
  - aggressive (--aggressive) : targets = probe.matched_rules (all fired rules,
    incl. off-class SQLi/XSS/protocol). probe output carries no file/line/operator,
    so targets hold id+tags only; the skill resolves id→file/line via the Stage-1
    index tsv and Reads the .conf block for the @rx pattern.

Output schema (everything the skill reads, nothing else):
    {
      "template_id", "template_path",
      "classification": { families, injection_point, protocol },
      "payload_samples": [ {label, value} ],
      "paranoia": 2,                       # from probe.paranoia → Lane-4 Verify PL
      "mode": "focused" | "aggressive",
      "targets": [
        # focused  : {id, msg, operator, transforms, pattern_excerpt, matched_at, trigger_explanation}
        # aggressive: {id, msg, tags, paranoia_level, matched_var}
      ]
    }
"""
import json
import sys

CLASS_KEYS = ("families", "injection_point", "protocol")
RC_ANALYSIS_KEYS = ("operator", "transforms", "pattern_excerpt", "matched_at", "trigger_explanation")
MATCHED_KEYS = ("id", "msg", "tags", "paranoia_level", "matched_var")


def build_focused_targets(root_causes):
    """root_cause_rules ⨝ recommendation.rule_analysis by id — pattern is inline."""
    if not root_causes:
        return []
    rc = root_causes.get("root_cause_rules") or []
    analysis = {a.get("id"): a for a in ((root_causes.get("recommendation") or {}).get("rule_analysis") or [])}
    targets = []
    for r in rc:
        a = analysis.get(r.get("id"), {})
        t = {"id": r.get("id"), "msg": r.get("msg")}
        t.update({k: a.get(k) for k in RC_ANALYSIS_KEYS})
        targets.append(t)
    return targets


def build_aggressive_targets(probe):
    """All fired rules — id+tags only; skill resolves pattern via index + .conf."""
    out = []
    for r in (probe or {}).get("matched_rules") or []:
        out.append({k: r.get(k) for k in MATCHED_KEYS})
    return out


def main():
    argv = sys.argv[1:]
    aggressive = "--aggressive" in argv
    pos = [a for a in argv if not a.startswith("--")]
    if len(pos) != 2:
        sys.exit("usage: parse_targets.py <verdict.json> <variant-context.json> [--aggressive]")

    with open(pos[0], encoding="utf-8") as f:
        v = json.load(f)

    classification = v.get("classification") or {}
    probe = v.get("probe") or {}
    mode = "aggressive" if aggressive else "focused"
    targets = build_aggressive_targets(probe) if aggressive else build_focused_targets(v.get("root_causes"))

    out = {
        "template_id": v.get("template_id"),
        "template_path": v.get("template_path"),
        "classification": {k: classification.get(k) for k in CLASS_KEYS},
        "payload_samples": v.get("payload_samples") or [],
        "paranoia": probe.get("paranoia"),
        "mode": mode,
        "targets": targets,
    }

    with open(pos[1], "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    note = "" if targets else " (empty → PoC-only passthrough unless --aggressive)"
    print(f"{pos[1]} — mode={mode}, targets={len(targets)}, paranoia={out['paranoia']}{note}")


if __name__ == "__main__":
    main()
