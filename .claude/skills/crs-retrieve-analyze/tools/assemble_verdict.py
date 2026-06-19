#!/usr/bin/env python3
"""assemble_verdict.py — merge the model's judgment with the probe transcript.

Usage:
    python .claude/skills/crs-retrieve-analyze/tools/assemble_verdict.py \
        <probe.json> <analysis.json> <verdict.json> [--keep-analysis]   (from repo root)

analysis.json is pure staging: this script is its ONLY reader, and verdict.json
is a strict superset of it (model judgment + the injected probe transcript). So
after verdict.json is SAFELY written, assemble_verdict deletes analysis.json. The
delete is gated on the successful write (a guardrail abort leaves analysis.json in
place to fix) and `--keep-analysis` retains it to inspect the pre-injection view.

The skill writes only its JUDGMENT to analysis.json (classification, payload
samples, which fired rules are root-cause + why, recommendation OR candidate
rules). This script injects the probe transcript from probe.json (the parsed
probe-engine output) so the model never re-types it, then:

  * annotates each fired rule with root_cause (= its id is in the model's
    root_cause_rules),
  * fills root_causes[].matched_var / msg straight from the probe transcript,
  * derives covered/not-covered from the root-cause count (no verdict field),
  * writes the final verdict.json,
  * prints the one confirmation line the skill emits.

Guardrail: every id the model lists as root-cause MUST appear in the probed
exploit request's matched_rules — you cannot call a rule a root cause if the
engine never fired it. A violation aborts with a non-zero exit so the skill
fixes its adjudication instead of emitting a bogus verdict.

analysis.json (what the model writes) — judgment only:
    {
      "template_id": "...",
      "template_path": "...",
      "exploit_index": 0,                     # which probed request is the exploit (default 0)
      "classification": { "families", "injection_point", "injection_slot", "severity",
                          "protocol", "confidence", "cwe_hint" },
      "payload_samples": [ {"label","value"}, ... ],
      "root_cause_rules": [ {"id": 942100, "reason": "..."} ],  # [] => not-covered
      "recommendation": {                     # used when covered — STRUCTURED object, not a string
          "summary": "...", "pl_coverage": "PL2",
          "rule_analysis": [ {"id": 942100, "msg": "...", "operator": "...",
                              "transforms": [...], "pattern_excerpt": "...",
                              "matched_at": "...", "trigger_explanation": "..."} ]
      },
      "candidate_rules": [ ... ],             # used when not-covered (or always, if force_candidates); each entry needs pl (1-4)
      "force_candidates": false,              # optional; true => keep candidate_rules even when covered
      "scope_gate": {                         # required on not-covered: SCOPE-GATE reasoning trace
          "entered": true,
          "g0_root_cause_fired": 0, "g1_content_signature": false,
          "g2_app_state_required": true, "g3_mutatable_payload": false,
          "g4_deterministic_cve_signature": true,
          "decision": "virtual-patch-only",   # in-scope | virtual-patch-only | out-of-scope-structural
          "rationale": "..."
      },
      "note": null                            # optional (e.g. probe-error fallback)
    }

force_candidates mode: when true, candidate_rules are preserved in BOTH the
covered and not-covered branches (covered verdict then carries recommendation
AND candidate_rules side by side). covered/not-covered is still derived from
the root-cause count; candidates are supplementary handoff material only and
must not repeat the root-cause rule ids.
"""
import json
import os
import sys

PROBE_RULE_KEEP = ("id", "paranoia_level", "tags", "matched_var", "msg")


def die(msg):
    sys.exit(f"assemble_verdict: {msg}")


def main():
    argv = sys.argv[1:]
    keep_analysis = "--keep-analysis" in argv
    pos = [a for a in argv if not a.startswith("--")]
    if len(pos) != 3:
        die("usage: assemble_verdict.py <probe.json> <analysis.json> <verdict.json> [--keep-analysis]")
    probe_path, analysis_path, verdict_path = pos
    sys.stdout.reconfigure(encoding="utf-8")

    with open(probe_path, encoding="utf-8") as f:
        probe = json.load(f)
    with open(analysis_path, encoding="utf-8") as f:
        analysis = json.load(f)

    rc_in = analysis.get("root_cause_rules") or []
    rc_ids = [int(r["id"]) for r in rc_in]
    rc_reason = {int(r["id"]): r.get("reason", "") for r in rc_in}
    covered = len(rc_ids) > 0

    # --- locate the probed exploit result -------------------------------
    results = probe.get("results") or []
    idx = analysis.get("exploit_index", 0)
    status = probe.get("status")
    result = results[idx] if status == "ok" and 0 <= idx < len(results) else None

    # --- probe block (injected from probe.json) -------------------------
    if result is not None:
        fired = result.get("matched_rules") or []
        fired_ids = {int(r["id"]) for r in fired}
        missing = [i for i in rc_ids if i not in fired_ids]
        if missing:
            die(f"root_cause_rules {missing} did not fire on exploit_index {idx} "
                f"(fired: {sorted(fired_ids)}) - a root cause must be an engine-fired rule")
        probe_block = {
            "paranoia": result.get("paranoia"),
            "blocked": result.get("blocked"),
            "anomaly_score": result.get("anomaly_score"),
            "matched_rules": [
                {**{k: r.get(k) for k in PROBE_RULE_KEEP}, "root_cause": int(r["id"]) in rc_ids}
                for r in fired
            ],
        }
        rule_by_id = {int(r["id"]): r for r in fired}
    else:
        if covered:
            die(f"probe has no usable result (status={status!r}) but analysis lists "
                "root_cause_rules — cannot be covered")
        probe_block = {"status": status, "error": probe.get("error"), "matched_rules": []}
        rule_by_id = {}

    # --- root_causes block ----------------------------------------------
    if covered:
        root_causes = {
            "root_cause_rules": [
                {
                    "id": i,
                    "matched_var": rule_by_id[i].get("matched_var"),
                    "msg": rule_by_id[i].get("msg"),
                    "reason": rc_reason[i],
                }
                for i in rc_ids
            ],
            "recommendation": analysis.get("recommendation"),
        }
    else:
        root_causes = None

    # --- candidate_rules ------------------------------------------------
    # Default: covered => no candidates (recommendation carries the verdict).
    # force_candidates mode (QA / always-handoff): keep candidate_rules in
    # BOTH branches so they coexist with root_causes. covered/not-covered is
    # still derived from root_cause count — candidates are supplementary only.
    force = bool(analysis.get("force_candidates"))
    if covered and not force:
        candidate_rules = []
    else:
        candidate_rules = analysis.get("candidate_rules") or []
    if len(candidate_rules) > 5:
        die(f"candidate_rules has {len(candidate_rules)} entries — cap is 5 (gate `cap`)")
    for i, c in enumerate(candidate_rules):
        if "id" not in c:
            die(f"candidate_rules[{i}] missing 'id'")
        if "pl" not in c:
            die(f"candidate_rules[{i}] missing 'pl' (paranoia level — lấy từ index cột pl)")
        pl = c["pl"]
        if not isinstance(pl, int) or pl not in (1, 2, 3, 4):
            die(f"candidate_rules[{i}] pl={pl!r} invalid — must be int 1–4")
    # In force mode, candidates must not duplicate the root-cause rules.
    if covered and force:
        dup = [c["id"] for c in candidate_rules if int(c["id"]) in rc_ids]
        if dup:
            die(f"force_candidates: candidate_rules {dup} are already root-cause rules — "
                "candidates must be supplementary (off-root-cause / class-relevant non-fired)")

    # --- scope_gate (SCOPE-GATE trace; only meaningful on not-covered) ---
    # The gate runs in the not-covered path to decide whether the gap is in
    # WAF content-inspection scope. covered => G0 routes out, no gate. We only
    # persist the trace + validate its decision enum; the spawn-suppression it
    # drives happens upstream (GEN-VARIANTS), before this script runs.
    _SCOPE_DECISIONS = ("in-scope", "virtual-patch-only", "out-of-scope-structural")
    scope_gate = analysis.get("scope_gate")
    if scope_gate is not None:
        if covered:
            die("scope_gate present but verdict is covered — the gate's G0 "
                "precondition routes covered probes out; drop scope_gate when covered")
        dec = scope_gate.get("decision")
        if dec not in _SCOPE_DECISIONS:
            die(f"scope_gate.decision={dec!r} invalid — must be one of {_SCOPE_DECISIONS}")

    # --- assemble (canonical field order) -------------------------------
    verdict = {
        "template_id": analysis.get("template_id"),
        "template_path": analysis.get("template_path"),
        "classification": analysis.get("classification"),
        "payload_samples": analysis.get("payload_samples") or [],
        "probe": probe_block,
        "root_causes": root_causes,
        "candidate_rules": candidate_rules,
    }
    if scope_gate is not None:
        verdict["scope_gate"] = scope_gate
    if analysis.get("note"):
        verdict["note"] = analysis["note"]

    with open(verdict_path, "w", encoding="utf-8") as f:
        json.dump(verdict, f, indent=2, ensure_ascii=False)

    # staging cleanup: verdict.json (superset) is written, so analysis.json is now
    # dead. delete it (gated on the successful write + all guardrails passing
    # above). never clobber the output; never crash the pipeline on a failed unlink.
    cleaned = ""
    if not keep_analysis and os.path.abspath(analysis_path) != os.path.abspath(verdict_path):
        try:
            os.remove(analysis_path)
            cleaned = f" (removed {analysis_path})"
        except OSError as e:
            cleaned = f" (kept {analysis_path}: {e})"

    print(f"{verdict_path} — {'covered' if covered else 'not-covered'}{cleaned}")


if __name__ == "__main__":
    main()
