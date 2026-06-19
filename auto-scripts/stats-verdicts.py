#!/usr/bin/env python3
# stats-verdicts.py - tally outcomes across out/<id>/verdict.json
#
# Usage (from repo root):
#   python auto-scripts/stats-verdicts.py
#   python auto-scripts/stats-verdicts.py --out-dir out
#   python auto-scripts/stats-verdicts.py --json        # machine-readable dump
#
# Classifies each verdict the same way run-pipeline.py does:
#   covered                 -> root_causes is not null
#   gated                   -> scope_gate.decision in HALT_GATES
#   in-scope                -> proceeds to Step 2/3 (variant-gen + rule-author)
#   <other>                 -> any unexpected scope_gate.decision value
# Also reports families, block stats, and Step-3 outcome (new.json present).

import argparse
import json
from collections import Counter
from pathlib import Path

# Must match run-pipeline.py.
HALT_GATES = {"virtual-patch-only", "out-of-scope-structural"}

parser = argparse.ArgumentParser(description="Tally CRS verdict.json outcomes")
parser.add_argument("--out-dir", default="out", help="Directory holding <id>/verdict.json (default: out)")
parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of a table")
args = parser.parse_args()

out_dir = Path(args.out_dir)
verdicts = sorted(out_dir.glob("*/verdict.json"))

rows = []          # per-template summary
status_count = Counter()
gate_count = Counter()
family_count = Counter()
blocked = Counter()
authored = Counter()   # did Step 3 emit new.json for in-scope items

for vp in verdicts:
    tid = vp.parent.name
    try:
        v = json.loads(vp.read_text(encoding="utf-8"))
    except Exception as e:
        rows.append({"id": tid, "status": "parse-error", "detail": str(e)})
        status_count["parse-error"] += 1
        continue

    decision = (v.get("scope_gate") or {}).get("decision")

    if v.get("root_causes") is not None:
        status = "covered"
    elif decision in HALT_GATES:
        status = "gated"
        gate_count[decision] += 1
    elif decision == "in-scope":
        status = "in-scope"
    elif decision is None:
        status = "no-gate"
    else:
        status = decision  # unexpected value, surface it as-is

    status_count[status] += 1

    for fam in (v.get("classification") or {}).get("families", []) or []:
        family_count[fam] += 1

    probe = v.get("probe") or {}
    if "blocked" in probe:
        blocked["blocked" if probe.get("blocked") else "not-blocked"] += 1

    has_new = (vp.parent / "new.json").exists()
    if status == "in-scope":
        authored["authored" if has_new else "pending"] += 1

    rows.append({
        "id": tid,
        "status": status,
        "decision": decision,
        "families": (v.get("classification") or {}).get("families", []),
        "blocked": probe.get("blocked"),
        "new_json": has_new,
    })

total = len(rows)

if args.json:
    print(json.dumps({
        "total": total,
        "status": dict(status_count),
        "gate_breakdown": dict(gate_count),
        "families": dict(family_count),
        "blocked": dict(blocked),
        "in_scope_outcome": dict(authored),
        "rows": rows,
    }, indent=2))
    raise SystemExit(0)


def section(title):
    print(f"\n{title}")
    print("-" * len(title))


def tally(counter, total_ref=None):
    if not counter:
        print("  (none)")
        return
    width = max(len(str(k)) for k in counter)
    for k, n in counter.most_common():
        pct = f"  ({n / total_ref * 100:5.1f}%)" if total_ref else ""
        print(f"  {str(k):<{width}}  {n:3}{pct}")


print(f"verdicts scanned: {total}  (from {out_dir}/)")

section("status")
tally(status_count, total)

section("gated breakdown (skipped Steps 2 & 3, no API call)")
tally(gate_count)

section("in-scope outcome (Step 3 new.json)")
tally(authored)

section("probe blocked at PL2")
tally(blocked)

section("attack families (templates may count in multiple)")
tally(family_count)

# Per-template table.
section("per-template")
id_w = max((len(r["id"]) for r in rows), default=2)
st_w = max((len(str(r["status"])) for r in rows), default=6)
for r in rows:
    fams = ",".join(r.get("families", []) or [])
    new = "new.json" if r.get("new_json") else ""
    print(f"  {r['id']:<{id_w}}  {str(r['status']):<{st_w}}  {fams:<28} {new}")
