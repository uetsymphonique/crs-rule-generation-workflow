#!/usr/bin/env python3
"""verify_rule.py — engine-verify a candidate SecRule against PoC + variant requests.

Usage (from repo root):
    python .claude/skills/crs-rule-author/tools/verify_rule.py \
        out/<id>/new.json out/<id>/extended-requests.json out/<id>/verify-report.json

Wraps probe-engine to answer: does the candidate rule actually TRIGGER on the
full request set the New-rule Generator designed it to cover?

Steps:
  1. Read new.json → rule.secrule_text + rule.id (placeholder e.g. "934XXX").
  2. Swap placeholder id → THROWAWAY_ID (numeric; SecLang id: must be numeric).
     new.json is not modified; only the temp .conf probe uses the swapped id.
  3. Write swapped rule to out/<id>/verify-candidate.conf (alongside artifacts;
     kept for debugging; overwritten on each verify run).
  4. Read extended-requests.json → paranoia + labeled request batch.
  5. Probe: probe-engine --crs coreruleset --candidate-rule-file <conf>
     Batch mode: one compile, all requests in one pass.
  6. For each result: triggered = THROWAWAY_ID in matched_rules.
     When triggered: matched_value = first variables[].value (post-transform
     payload the engine matched on — engine's-eye view for rationale tracing).
  7. Project minimal report (model only reads this):
       {"parse_ok", "paranoia", "rule_id_placeholder",
        "requests": [{label, triggered[, matched_value]}]}
  8. Write verify-report.json; print one-line summary.

Engine constraint (probe-engine README §Notes):
  --candidate-rule-file loads the rule AFTER rule 949, so any anomaly score it
  sets is NOT counted by 949 in the same run. This script confirms TRIGGER/FIRE
  only; scoring/block claims remain "engine-not-verified" in design_rationale
  (Tier-B deferred per proposal §6).

Side-effects:
  Writes out/<id>/verify-candidate.conf (swapped rule, temp; safe to delete).
"""
import glob
import json
import os
import subprocess
import sys

THROWAWAY_ID = 999901


def find_probe_engine():
    for path in ["tools/probe-engine/probe-engine.exe",
                 "tools/probe-engine/probe-engine"]:
        if os.path.isfile(path):
            return os.path.abspath(path)
    candidates = glob.glob("tools/probe-engine/probe-engine*")
    skip_exts = {".go", ".mod", ".sum", ".gitignore", ".md", ".conf", ".txt"}
    for c in candidates:
        if os.path.isfile(c) and os.path.splitext(c)[1] not in skip_exts:
            return os.path.abspath(c)
    return None


def swap_id(secrule_text, placeholder_id):
    old = f"id:{placeholder_id}"
    new = f"id:{THROWAWAY_ID}"
    if old not in secrule_text:
        sys.exit(
            f"placeholder 'id:{placeholder_id}' not found in secrule_text — "
            "cannot swap to numeric id; check rule.id and secrule_text are consistent"
        )
    text = secrule_text.replace(old, new)

    # probe-engine isDetectionRule() requires paranoia-level/N or attack-* tag.
    # CRS authoring convention omits paranoia-level/1 tag for PL1 rules, so
    # candidate rules typically have neither. Inject the tag into the verify-only
    # conf (new.json is NOT modified). The secrule_text action string always ends
    # with a closing " — we insert the tag just before it.
    has_pl_tag = "tag:'paranoia-level/" in text or 'tag:"paranoia-level/' in text
    has_attack_tag = "tag:'attack-" in text or 'tag:"attack-' in text
    if not has_pl_tag and not has_attack_tag:
        text = text.rstrip()
        if text.endswith('"'):
            text = text[:-1] + ",\\\n    tag:'paranoia-level/1'\""

    return text


def run_probe(engine_path, conf_path, requests, paranoia):
    payload = json.dumps({"requests": requests, "paranoia": paranoia})
    cmd = [engine_path, "--crs", "coreruleset", "--candidate-rule-file", conf_path]
    result = subprocess.run(cmd, input=payload, capture_output=True, text=True)
    if result.returncode != 0 and not result.stdout.strip():
        sys.exit(f"probe-engine failed (exit {result.returncode}): {result.stderr[:400]}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        sys.exit(f"probe-engine output is not valid JSON: {e}\nstdout[:200]: {result.stdout[:200]}")


def build_report(raw, labels, paranoia, placeholder_id):
    parse_ok = bool(raw.get("parse_ok"))
    req_reports = []

    if parse_ok:
        for res in raw.get("results") or []:
            idx = res.get("index", 0)
            label = labels[idx] if idx < len(labels) else f"req:{idx}"
            triggered = False
            matched_value = None
            for rule in res.get("matched_rules") or []:
                if rule.get("id") == THROWAWAY_ID:
                    triggered = True
                    vars_ = rule.get("variables") or []
                    if vars_:
                        matched_value = vars_[0].get("value")
                    break
            entry = {"label": label, "triggered": triggered}
            if triggered and matched_value is not None:
                entry["matched_value"] = matched_value
            req_reports.append(entry)

    return {
        "parse_ok": parse_ok,
        "paranoia": paranoia,
        "rule_id_placeholder": placeholder_id,
        "requests": req_reports,
    }


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: verify_rule.py <new.json> <extended-requests.json> <verify-report.json>")

    new_path, ext_path, report_path = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(new_path, encoding="utf-8") as f:
        new_data = json.load(f)

    if not os.path.isfile(ext_path):
        sys.exit(
            f"{ext_path} not found — run crs-variant-gen first "
            "(passthrough mode still produces this file with the PoC)"
        )
    with open(ext_path, encoding="utf-8") as f:
        ext = json.load(f)

    rule = new_data.get("rule") or {}
    placeholder_id = rule.get("id")
    secrule_text = rule.get("secrule_text")
    if not placeholder_id or not secrule_text:
        sys.exit("new.json missing rule.id or rule.secrule_text")

    requests = ext.get("requests") or []
    labels = ext.get("labels") or [f"req:{i}" for i in range(len(requests))]
    paranoia = ext.get("paranoia") or 2

    if not requests:
        sys.exit("extended-requests.json has no requests[]")

    engine = find_probe_engine()
    if not engine:
        sys.exit("probe-engine binary not found under tools/probe-engine/")

    swapped = swap_id(secrule_text, placeholder_id)
    out_dir = os.path.dirname(os.path.abspath(report_path))
    conf_path = os.path.join(out_dir, "verify-candidate.conf")
    with open(conf_path, "w", encoding="utf-8") as f:
        f.write(swapped + "\n")

    raw = run_probe(engine, conf_path, requests, paranoia)
    report = build_report(raw, labels, paranoia, placeholder_id)

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    n_triggered = sum(1 for r in report["requests"] if r["triggered"])
    n_total = len(report["requests"])
    if not report["parse_ok"]:
        status = "PARSE FAIL — rule has bad syntax"
    elif n_triggered == n_total:
        status = f"ALL PASS ({n_total}/{n_total} triggered)"
    else:
        status = f"PARTIAL — {n_triggered}/{n_total} triggered"
    print(f"{report_path} — parse_ok={report['parse_ok']}, {status}")


if __name__ == "__main__":
    main()
