#!/usr/bin/env python3
# run-pipeline.py - batch CRS rule-generation pipeline
#
# Usage (from repo root):
#   python run-pipeline.py --list cve-list.txt
#   python run-pipeline.py --list cve-list.txt --gen-variants root-cause-only
#   python run-pipeline.py --list cve-list.txt --resume
#   python run-pipeline.py --list cve-list.txt --max-budget-usd 2.00 --max-turns 20
#
# cve-list.txt: one template path per line (relative to repo root); # = comment.
#
# Steps per template:
#   1. crs-retrieve-analyze  --gen-variants=off  -> out/<id>/verdict.json
#   2. crs-variant-gen       --gen-variants=<mode> (self-gates on scope_gate)
#   3. crs-rule-author       (self-gates on scope_gate + coverage)
#
# Skills self-gate: scope_gate in {virtual-patch-only, out-of-scope-structural}
# causes Step 2 and Step 3 to HALT early without error.
#
# Per-step debug logs: out/<id>/claude-step<N>.log
# Token/cost summary printed at end of each step and pipeline end.

import argparse
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path

# ── arg parse ─────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Batch CRS rule-generation pipeline")
parser.add_argument("--list",            required=True,  help="Path to template list file")
parser.add_argument("--gen-variants",    default="class-only",
                    choices=["class-only", "root-cause-only", "all-triggered-rules"])
parser.add_argument("--model",           default="claude-sonnet-4-6")
parser.add_argument("--log-file",        default="pipeline-run.log")
parser.add_argument("--max-budget-usd",  default="5.50")
parser.add_argument("--max-turns",       default="50")
parser.add_argument("--resume",          action="store_true")
args = parser.parse_args()

# ── cumulative counters ───────────────────────────────────────────────────────
totals = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "cost": 0.0}

# ── helpers ───────────────────────────────────────────────────────────────────
def log(msg: str):
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line)
    with open(args.log_file, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def run_claude(prompt: str, id: str, step: int) -> int:
    debug_log = f"out/{id}/claude-step{step}.log"
    raw_log   = f"out/{id}/claude-step{step}.raw.json"

    result = subprocess.run(
        [
            "claude", "-p", prompt,
            "--dangerously-skip-permissions",
            "--model",           args.model,
            "--output-format",   "json",
            "--no-session-persistence",
            "--exclude-dynamic-system-prompt-sections",
            "--max-turns",       args.max_turns,
            "--max-budget-usd",  args.max_budget_usd,
            "--debug-file",      debug_log,
            "--name",            f"crs-{id}-s{step}",
        ],
        capture_output=True,
        text=True,
    )

    raw = result.stdout
    Path(raw_log).write_text(raw, encoding="utf-8")

    try:
        obj = json.loads(raw)
        u = obj.get("usage", {})
        if u:
            in_tok  = u.get("input_tokens", 0)
            out_tok = u.get("output_tokens", 0)
            cr      = u.get("cache_read_input_tokens", 0)
            cw      = u.get("cache_creation_input_tokens", 0)
            cost    = obj.get("total_cost_usd", 0.0)

            totals["input"]       += in_tok
            totals["output"]      += out_tok
            totals["cache_read"]  += cr
            totals["cache_write"] += cw
            totals["cost"]        += cost

            turns   = obj.get("num_turns", 0)
            dur_sec = obj.get("duration_ms", 0) / 1000
            stop_r  = obj.get("stop_reason", "?")
            term_r  = obj.get("terminal_reason", "?")
            is_err  = obj.get("is_error", False)
            api_err = obj.get("api_error_status", "")
            result_text  = obj.get("result", "")
            perm_denials = len(obj.get("permission_denials") or [])

            log(f"    [tokens] in={in_tok} out={out_tok} cache_read={cr} cache_write={cw} "
                f"cost=${cost:.4f} | turns={turns} dur={dur_sec:.1f}s stop={stop_r} term={term_r}")
            if result_text:
                log(f"    [result] {result_text}")
            if is_err:
                log(f"    [ERROR] is_error=true api_error_status={api_err}")
            if perm_denials > 0:
                log(f"    [WARN] permission_denials={perm_denials}")
    except Exception:
        pass

    return result.returncode


# ── load list ─────────────────────────────────────────────────────────────────
list_path = Path(args.list)
if not list_path.exists():
    print(f"Error: {args.list} not found")
    raise SystemExit(1)

templates = [
    line.strip()
    for line in list_path.read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.strip().startswith("#")
]

log(f"=== pipeline start: {len(templates)} template(s), model={args.model}, "
    f"gen-variants={args.gen_variants}, max-budget=${args.max_budget_usd}/step, "
    f"max-turns={args.max_turns} ===")

stats = {"ok": 0, "covered": 0, "warn": 0}

for tpl in templates:
    id  = Path(tpl).stem
    out = Path(f"out/{id}")
    out.mkdir(parents=True, exist_ok=True)

    log(f"--- [{id}] {tpl}")

    # ── Step 1: analyze ───────────────────────────────────────────────────────
    verdict_path = out / "verdict.json"
    if args.resume and verdict_path.exists():
        log("  Step 1: skip (resume - verdict.json exists)")
    else:
        log("  Step 1: crs-retrieve-analyze --gen-variants=off")
        rc = run_claude(f"Invoke Skill(crs-retrieve-analyze) - args: --gen-variants=off {tpl}", id, 1)
        if rc != 0:
            log(f"  WARN: claude exited {rc} at Step 1")

    if not verdict_path.exists():
        log(f"  WARN: verdict.json missing - skipping {id}")
        stats["warn"] += 1
        continue

    verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    if verdict.get("root_causes") is not None:
        log("  covered - no new rule needed")
        stats["covered"] += 1
        continue

    # ── Step 2: variant-gen ───────────────────────────────────────────────────
    ext_path = out / "extended-requests.json"
    if args.resume and ext_path.exists():
        log("  Step 2: skip (resume - extended-requests.json exists)")
    else:
        log(f"  Step 2: crs-variant-gen --gen-variants={args.gen_variants}")
        rc = run_claude(
            f"Invoke Skill(crs-variant-gen) - args: --gen-variants={args.gen_variants} "
            f"out/{id}/variant-handoff.json out/{id}/probe.json template: {tpl}",
            id, 2,
        )
        if rc != 0:
            log(f"  WARN: claude exited {rc} at Step 2")

    # ── Step 3: rule-author ───────────────────────────────────────────────────
    new_path = out / "new.json"
    if args.resume and new_path.exists():
        log("  Step 3: skip (resume - new.json exists)")
        stats["ok"] += 1
        continue

    log("  Step 3: crs-rule-author")
    rc = run_claude(f"Invoke Skill(crs-rule-author) - out/{id}/verdict.json  template: {tpl}", id, 3)
    if rc != 0:
        log(f"  WARN: claude exited {rc} at Step 3")

    if new_path.exists():
        log(f"  done -> {new_path}")
        stats["ok"] += 1
    else:
        log("  WARN: new.json missing after Step 3")
        stats["warn"] += 1

log(f"=== pipeline end: ok={stats['ok']} covered={stats['covered']} warn={stats['warn']} | "
    f"tokens in={totals['input']} out={totals['output']} "
    f"cache_read={totals['cache_read']} cache_write={totals['cache_write']} "
    f"total_cost=${totals['cost']:.4f} ===")
