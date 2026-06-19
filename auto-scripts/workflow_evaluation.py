#!/usr/bin/env python3
# workflow_evaluation.py - per-CVE / per-step run metrics -> CSV
#
# Reads the raw run dumps the pipeline saves at out/<id>/claude-stepN.raw.json
# (written by run-pipeline.py) and emits one CSV row per (cve, step) with
# token usage, timing, cost, and status. A TOTAL row per CVE is appended.
#
# Usage (from repo root):
#   python auto-scripts/workflow_evaluation.py
#   python auto-scripts/workflow_evaluation.py --out-dir out --csv workflow-evaluation.csv
#   python auto-scripts/workflow_evaluation.py --csv -        # write to stdout
#
# Step -> expected artifact (presence reported in the `artifact_ok` column):
#   1 crs-retrieve-analyze -> verdict.json
#   2 crs-variant-gen      -> extended-requests.json
#   3 crs-rule-author      -> new.json

import argparse
import csv
import json
import re
import sys
from pathlib import Path

STEP_ARTIFACT = {1: "verdict.json", 2: "extended-requests.json", 3: "new.json"}
STEP_SKILL = {1: "crs-retrieve-analyze", 2: "crs-variant-gen", 3: "crs-rule-author"}

# scope_gate decisions that skip Steps 2 & 3 (must match run-pipeline.py).
HALT_GATES = {"virtual-patch-only", "out-of-scope-structural"}

FIELDS = [
    "cve", "final_status", "step", "skill", "status", "stop_reason", "terminal_reason",
    "num_turns", "duration_min", "duration_api_min",
    "input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens",
    "total_tokens", "cost_usd",
]


def final_status(cve_dir: Path) -> str:
    """Per-CVE outcome from verdict.json (same logic as stats-verdicts.py)."""
    vp = cve_dir / "verdict.json"
    if not vp.exists():
        return "no-verdict"
    try:
        v = json.loads(vp.read_text(encoding="utf-8"))
    except Exception:
        return "parse-error"
    if v.get("root_causes") is not None:
        return "covered"
    decision = (v.get("scope_gate") or {}).get("decision")
    if decision in HALT_GATES:
        return "gated"
    if decision == "in-scope":
        return "in-scope"
    return decision or "no-gate"

parser = argparse.ArgumentParser(description="Per-CVE/per-step run metrics to CSV")
parser.add_argument("--out-dir", default="out", help="Directory holding <id>/claude-stepN.raw.json (default: out)")
parser.add_argument("--csv", default="workflow-evaluation.csv", help="Output CSV path, or '-' for stdout")
args = parser.parse_args()

out_dir = Path(args.out_dir)


def num(x):
    return x if isinstance(x, (int, float)) else 0


def row_from_raw(cve: str, step: int, raw_path: Path) -> dict:
    artifact = STEP_ARTIFACT.get(step, "")
    artifact_ok = (raw_path.parent / artifact).exists() if artifact else False
    base = {"cve": cve, "step": step, "skill": STEP_SKILL.get(step, "")}
    try:
        d = json.loads(raw_path.read_text(encoding="utf-8"))
    except Exception as e:
        base["status"] = f"parse-error: {e}"
        return base

    u = d.get("usage") or {}
    in_tok = num(u.get("input_tokens"))
    out_tok = num(u.get("output_tokens"))
    cr = num(u.get("cache_read_input_tokens"))
    cw = num(u.get("cache_creation_input_tokens"))

    if d.get("is_error"):
        status = f"error:{d.get('api_error_status') or d.get('subtype') or 'unknown'}"
    else:
        status = "ok" if artifact_ok else "no-artifact"

    base.update({
        "status": status,
        "stop_reason": d.get("stop_reason", ""),
        "terminal_reason": d.get("terminal_reason", ""),
        "num_turns": num(d.get("num_turns")),
        "duration_min": round(num(d.get("duration_ms")) / 60000, 2),
        "duration_api_min": round(num(d.get("duration_api_ms")) / 60000, 2),
        "input_tokens": in_tok,
        "output_tokens": out_tok,
        "cache_read_tokens": cr,
        "cache_write_tokens": cw,
        "total_tokens": in_tok + out_tok + cr + cw,
        "cost_usd": round(num(d.get("total_cost_usd")), 4),
    })
    return base


# Collect CVEs that have at least one raw step dump.
raw_glob = sorted(out_dir.glob("*/claude-step*.raw.json"))
cves = sorted({p.parent.name for p in raw_glob})

rows = []
grand = {k: 0 for k in ("num_turns", "input_tokens", "output_tokens",
                        "cache_read_tokens", "cache_write_tokens", "total_tokens")}
grand_cost = 0.0
grand_dur = 0.0

for cve in cves:
    cdir = out_dir / cve
    fstatus = final_status(cdir)
    step_rows = []
    for step in sorted(STEP_ARTIFACT):
        rp = cdir / f"claude-step{step}.raw.json"
        if not rp.exists():
            continue
        # Drop gated Steps 2-3: pre mechanical-gate these were sent to the model
        # which self-HALTed — degenerate runs, not real variant/rule generation.
        if step in (2, 3) and fstatus == "gated":
            continue
        r = row_from_raw(cve, step, rp)
        r["final_status"] = fstatus
        step_rows.append(r)

    rows.extend(step_rows)

    # per-CVE TOTAL row
    tot = {"cve": cve, "final_status": fstatus, "step": "TOTAL", "skill": "",
           "status": "", "stop_reason": "", "terminal_reason": ""}
    for k in ("num_turns", "input_tokens", "output_tokens", "cache_read_tokens",
              "cache_write_tokens", "total_tokens"):
        tot[k] = sum(num(r.get(k)) for r in step_rows)
        grand[k] += tot[k]
    tot["duration_min"] = round(sum(num(r.get("duration_min")) for r in step_rows), 2)
    tot["duration_api_min"] = round(sum(num(r.get("duration_api_min")) for r in step_rows), 2)
    tot["cost_usd"] = round(sum(num(r.get("cost_usd")) for r in step_rows), 4)
    grand_cost += tot["cost_usd"]
    grand_dur += tot["duration_min"]
    rows.append(tot)

# Write CSV.
if args.csv == "-":
    w = csv.DictWriter(sys.stdout, fieldnames=FIELDS, extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)
else:
    with open(args.csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

# Console summary (not written to CSV).
if args.csv != "-":
    print(f"wrote {len(rows)} rows ({len(cves)} CVEs) -> {args.csv}")
    print(f"grand total: turns={grand['num_turns']} "
          f"in={grand['input_tokens']} out={grand['output_tokens']} "
          f"cache_read={grand['cache_read_tokens']} cache_write={grand['cache_write_tokens']} "
          f"total_tokens={grand['total_tokens']} "
          f"cost=${grand_cost:.4f} wall={grand_dur:.1f}min")

    # Per-step averages over actual runs.
    # Steps 2 & 3 exclude gated CVEs: historically (pre mechanical gate) they
    # were still sent to the model, which then self-HALTed — those degenerate
    # runs would skew the real cost/time of producing variants and rules.
    step_rows_only = [r for r in rows if isinstance(r.get("step"), int)]
    print("\nper-step stats (real runs; steps 2-3 exclude gated):")
    metrics = [
        ("turns",        "num_turns",        "{:.1f}"),
        ("dur_min",      "duration_min",     "{:.2f}"),
        ("dur_api_min",  "duration_api_min", "{:.2f}"),
        ("total_tokens", "total_tokens",     "{:.0f}"),
        ("cost_usd",     "cost_usd",         "{:.4f}"),
    ]
    for step in sorted(STEP_ARTIFACT):
        recs = [r for r in step_rows_only if r["step"] == step]
        if step in (2, 3):
            recs = [r for r in recs if r.get("final_status") != "gated"]
        if not recs:
            continue
        n = len(recs)
        print(f"  step {step} {STEP_SKILL[step]} (n={n}):")
        for label, key, fmt in metrics:
            vals = [num(r.get(key)) for r in recs]
            avg = sum(vals) / n
            print(f"    {label:<13} avg={fmt.format(avg):>10}  "
                  f"min={fmt.format(min(vals)):>10}  max={fmt.format(max(vals)):>10}")

    # Per-CVE averages (from TOTAL rows = full pipeline cost per CVE),
    # overall and split by final_status.
    total_rows = [r for r in rows if r.get("step") == "TOTAL"]

    def cve_block(title, recs):
        if not recs:
            return
        n = len(recs)
        print(f"  {title} (n={n}):")
        for label, key, fmt in metrics:
            vals = [num(r.get(key)) for r in recs]
            avg = sum(vals) / n
            print(f"    {label:<13} avg={fmt.format(avg):>10}  "
                  f"min={fmt.format(min(vals)):>10}  max={fmt.format(max(vals)):>10}")

    print("\nper-CVE stats (full pipeline per CVE):")
    cve_block("all", total_rows)
    for label in ("covered", "in-scope", "gated"):
        cve_block(label, [r for r in total_rows if r.get("final_status") == label])
