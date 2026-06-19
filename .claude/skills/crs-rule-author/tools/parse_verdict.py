#!/usr/bin/env python3
"""parse_verdict.py — project a Stage-1 verdict.json to the crs-rule-author whitelist.

Usage:
    python .claude/skills/crs-rule-author/tools/parse_verdict.py <verdict.json> <author-context.json>   (from repo root)

Reads the full verdict.json (Stage 1 output) and keeps ONLY the fields that help
DESIGN a new rule, so the model never loads the whole verdict (raw probe
matched_rules with full tag arrays, protocol-enforcement noise, off-class FP
rules already summarized in candidate_rules, etc.).

It also DERIVES the probe-only signals that no other field carries:
  - engine_confirmed_var : the variable locations the engine actually matched on,
    ranked by how many fired rules hit each (ground-truth scope, more reliable
    than the prose injection_point). Empty when no rule fired.
  - off_class_on_var     : count of off-root-cause rules that fired on the top
    confirmed var → "payload is heuristically noisy, design precise".
  - pl_gap               : anomaly_score + pl1_blocks/pl2_blocks booleans →
    tells the author which PL the gap sits at (a new PL1 rule has value when
    pl1_blocks is false).

`already_covered_by` is populated ONLY when the verdict is covered (force-candidates
mode); it merges root_cause_rules (id/msg/reason/matched_var) with the matching
recommendation.rule_analysis entry (operator/transforms/pattern_excerpt/
trigger_explanation) by id — the richest few-shot mechanism available. Null on a
plain not-covered verdict.

The model still Reads the Nuclei .yaml itself for full request fidelity; this
script only distills the verdict.

Output schema (everything the skill reads, nothing else):
    {
      "template_id", "template_path",
      "coverage": "covered" | "not-covered",
      "classification": { families, injection_point, severity, protocol, cwe_hint, confidence },
      "payload_samples": [ {label, value} ],
      "scope_signal": {
        "injection_point", "engine_confirmed_var": [ {var, hits} ], "off_class_on_var", "note"
      },
      "pl_gap": { inbound, threshold, score_pl1, score_pl2, blocked, pl1_blocks, pl2_blocks } | null,
      "target_file_hint": "<top candidate file>" | null,
      "candidate_rules": [ {id, file, line, operator, pl, why}, ... ],
      "already_covered_by": [ {id, msg, reason, operator, transforms, pattern_excerpt, matched_at, trigger_explanation} ] | null,
      "recommendation_pl_coverage": "PL2" | null,
      "scope_gate": { "decision": "in-scope"|"virtual-patch-only"|"out-of-scope-structural", "rationale": "..." } | null
    }

scope_gate is carried verbatim from the Stage-1 verdict (SCOPE-GATE trace, not-covered
only). The skill's input-guard branches on `decision`: out-of-scope-structural and
virtual-patch-only both HALT (rule-author only synthesizes generic CRS rules);
in-scope (or null) proceeds. null on covered verdicts (gate not entered).
"""
import json
import sys
from collections import Counter

CLASS_KEYS = ("families", "injection_point", "severity", "protocol", "cwe_hint", "confidence")
CAND_KEYS = ("id", "file", "line", "operator", "pl", "why")


def rank_matched_vars(matched_rules):
    """Rank real injection locations by how many fired rules hit each.

    Drops MATCHED_VARS:* (Coraza-internal self-reference, not a distinct location).
    Keeps locations with >=2 hits (engine consensus); if none reach 2, falls back
    to the single most-hit location so a lone off-class fire still surfaces a scope.
    """
    counter = Counter()
    for r in matched_rules:
        for loc in dict.fromkeys(r.get("matched_var") or []):  # dedupe within a rule
            if loc.startswith("MATCHED_VARS"):
                continue
            counter[loc] += 1
    ordered = counter.most_common()
    consensus = [{"var": v, "hits": n} for v, n in ordered if n >= 2]
    if consensus:
        return consensus
    return [{"var": v, "hits": n} for v, n in ordered[:1]]


def build_scope_signal(classification, probe):
    matched_rules = (probe or {}).get("matched_rules") or []
    ranked = rank_matched_vars(matched_rules)
    top_var = ranked[0]["var"] if ranked else None

    off_class = 0
    if top_var:
        for r in matched_rules:
            if not r.get("root_cause") and top_var in (r.get("matched_var") or []):
                off_class += 1

    if not ranked:
        note = "no rule fired on the probe — engine gives no scope confirmation; rely on injection_point prose."
    elif off_class:
        note = (f"{off_class} off-root-cause rule(s) also fired on {top_var} — "
                "payload is heuristically noisy; design the new rule to be precise, "
                "do not mimic these broad heuristics.")
    else:
        note = f"engine matched on {top_var}; no off-class collateral on that location."

    return {
        "injection_point": (classification or {}).get("injection_point"),
        "engine_confirmed_var": ranked,
        "off_class_on_var": off_class,
        "note": note,
    }


def build_pl_gap(probe):
    if not probe:
        return None
    score = probe.get("anomaly_score") or {}
    inbound = score.get("inbound")
    threshold = score.get("threshold")
    pl1 = score.get("score_pl1")

    def ge(a, b):
        return a is not None and b is not None and a >= b

    return {
        "inbound": inbound,
        "threshold": threshold,
        "score_pl1": pl1,
        "score_pl2": score.get("score_pl2"),
        "blocked": probe.get("blocked"),
        "pl1_blocks": ge(pl1, threshold),
        "pl2_blocks": ge(inbound, threshold),
    }


def build_already_covered_by(root_causes):
    """Merge root_cause_rules with recommendation.rule_analysis by id (covered only)."""
    if not root_causes:
        return None
    rc = root_causes.get("root_cause_rules") or []
    analysis = {a.get("id"): a for a in ((root_causes.get("recommendation") or {}).get("rule_analysis") or [])}
    merged = []
    for r in rc:
        a = analysis.get(r.get("id"), {})
        merged.append({
            "id": r.get("id"),
            "msg": r.get("msg"),
            "reason": r.get("reason"),
            "operator": a.get("operator"),
            "transforms": a.get("transforms"),
            "pattern_excerpt": a.get("pattern_excerpt"),
            "matched_at": a.get("matched_at"),
            "trigger_explanation": a.get("trigger_explanation"),
        })
    return merged or None


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: parse_verdict.py <verdict.json> <author-context.json>")

    with open(sys.argv[1], encoding="utf-8") as f:
        v = json.load(f)

    classification = v.get("classification") or {}
    probe = v.get("probe") or {}
    root_causes = v.get("root_causes")
    candidates = [{k: c.get(k) for k in CAND_KEYS} for c in (v.get("candidate_rules") or [])]
    covered = root_causes is not None

    out = {
        "template_id": v.get("template_id"),
        "template_path": v.get("template_path"),
        "coverage": "covered" if covered else "not-covered",
        "classification": {k: classification.get(k) for k in CLASS_KEYS},
        "payload_samples": v.get("payload_samples") or [],
        "scope_signal": build_scope_signal(classification, probe),
        "pl_gap": build_pl_gap(probe),
        "target_file_hint": candidates[0]["file"] if candidates else None,
        "candidate_rules": candidates,
        "already_covered_by": build_already_covered_by(root_causes),
        "recommendation_pl_coverage": ((root_causes or {}).get("recommendation") or {}).get("pl_coverage"),
        "scope_gate": v.get("scope_gate"),
    }

    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    n_cand = len(candidates)
    top = out["scope_signal"]["engine_confirmed_var"]
    top_var = top[0]["var"] if top else "none"
    gate = (out["scope_gate"] or {}).get("decision", "—")
    print(f"{sys.argv[2]} — {out['coverage']}, candidates={n_cand}, scope={top_var}, "
          f"target_file_hint={out['target_file_hint']}, scope_gate={gate}")


if __name__ == "__main__":
    main()
