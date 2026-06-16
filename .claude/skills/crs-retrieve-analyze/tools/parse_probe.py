#!/usr/bin/env python3
"""parse_probe.py — project probe-engine output to the Stage-1 whitelist.

Usage:
    python .claude/skills/crs-retrieve-analyze/tools/parse_probe.py <raw-probe-output.json> <parsed-out.json>   (from repo root)

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
    if len(sys.argv) != 3:
        sys.exit("usage: parse_probe.py <raw-probe-output.json> <parsed-out.json>")

    with open(sys.argv[1], encoding="utf-8") as f:
        raw = json.load(f)

    results = raw["results"] if raw.get("results") is not None else [raw]
    out = {
        "status": raw.get("status"),
        "error": raw.get("error"),
        "results": [project_result(r) for r in results],
    }

    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    n = len(out["results"])
    blocked = sum(1 for r in out["results"] if r.get("blocked"))
    print(f"{sys.argv[2]} - status={out['status']} results={n} blocked={blocked}")


if __name__ == "__main__":
    main()
