#!/usr/bin/env python3
"""parse_probe.py — project probe-engine output to the Stage-1 whitelist.

Usage:
    python .claude/skills/crs-retrieve-analyze/tools/parse_probe.py <raw-probe-output.json> <parsed-out.json> [--keep-raw]   (from repo root)

The raw probe-engine output is pure staging: this script is its ONLY reader, and
once the projected probe.json is written the raw transcript is dead weight (it is
the largest, noisiest artifact in out/<id>/). So after probe.json is SAFELY
written, parse_probe deletes the raw file. The delete is gated on a successful
write — if anything fails earlier the raw bytes are still on disk to inspect — and
`--keep-raw` retains it for debugging.

Reads the raw probe-engine stdout JSON and keeps ONLY the match-time fields the
crs-retrieve-analyze skill consumes (the field-consumption contract documented
in reference.md), dropping everything else so the model never has to load the
noise fields (raw regex, severity, phase, maturity, accuracy, detection score,
pl3/pl4, interruption, …).

It deliberately DROPS the rule's file/line/operator: Coraza's rule.Line() is
not the .conf physical line (it counts across the merged ruleset), so source
location is unreliable here. The authoritative file/line/operator for any rule
— fired or not — is the index tsv (keyed by id), looked up in RETRIEVE.

Handles both probe-engine output shapes and normalizes to one structure:
    flat single-request  -> wrapped as results:[<one>]
    batch / sweep        -> results:[...] passed through (projected)

For each matched rule it also DERIVES `matched_var` — the list of
"VARIABLE:KEY" locations the rule matched (built from variables[]) — so the
skill can compare a fired rule against the plain injection_point without
recomputing it from variables[].

Output schema (everything the skill reads, nothing else):
    {
      "status": "ok" | "error",
      "error":  null | "<message>",
      "results": [
        {
          "index": 0,
          "paranoia": 2,
          "blocked": true,
          "anomaly_score": { "inbound", "threshold", "to_block", "score_pl1", "score_pl2" },
          "matched_rules": [
            {
              "id", "tags", "paranoia_level", "msg",
              "matched_var": ["ARGS:uid", ...],     # DERIVED from variables[]
              "variables": [ {"variable","key","value"}, ... ]
            }
          ]
        }
      ]
    }
"""
import json
import os
import sys

SCORE_KEYS = ("inbound", "threshold", "to_block", "score_pl1", "score_pl2")
RULE_KEYS = ("id", "tags", "paranoia_level", "msg")
VAR_KEYS = ("variable", "key", "value")


def project_var(v):
    return {k: v.get(k) for k in VAR_KEYS}


def derive_matched_var(rule):
    """Build ["VARIABLE:KEY", ...] (deduped, order-preserving) from variables[]."""
    out = []
    for v in rule.get("variables") or []:
        loc = v.get("variable", "")
        if v.get("key"):
            loc = f"{loc}:{v['key']}"
        if loc and loc not in out:
            out.append(loc)
    return out


def project_rule(r):
    out = {k: r[k] for k in RULE_KEYS if k in r}
    out["matched_var"] = derive_matched_var(r)
    out["variables"] = [project_var(v) for v in (r.get("variables") or [])]
    return out


def project_result(res):
    score = res.get("anomaly_score") or {}
    return {
        "index": res.get("index", 0),
        "paranoia": res.get("paranoia"),
        "blocked": res.get("blocked"),
        "anomaly_score": {k: score.get(k) for k in SCORE_KEYS},
        "matched_rules": [project_rule(r) for r in (res.get("matched_rules") or [])],
    }


def main():
    argv = sys.argv[1:]
    keep_raw = "--keep-raw" in argv
    pos = [a for a in argv if not a.startswith("--")]
    if len(pos) != 2:
        sys.exit("usage: parse_probe.py <raw-probe-output.json> <parsed-out.json> [--keep-raw]")
    raw_path, out_path = pos

    with open(raw_path, encoding="utf-8") as f:
        raw = json.load(f)

    results = raw["results"] if raw.get("results") is not None else [raw]
    out = {
        "status": raw.get("status"),
        "error": raw.get("error"),
        "results": [project_result(r) for r in results],
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    # staging cleanup: probe.json is written, so the raw transcript is now dead.
    # delete it (gated on the successful write above). Never delete if it would
    # clobber the output, and never crash the pipeline if removal fails.
    cleaned = ""
    if not keep_raw and os.path.abspath(raw_path) != os.path.abspath(out_path):
        try:
            os.remove(raw_path)
            cleaned = f" (removed {raw_path})"
        except OSError as e:
            cleaned = f" (kept {raw_path}: {e})"

    n = len(out["results"])
    blocked = sum(1 for r in out["results"] if r.get("blocked"))
    print(f"{out_path} - status={out['status']} results={n} blocked={blocked}{cleaned}")


if __name__ == "__main__":
    main()
