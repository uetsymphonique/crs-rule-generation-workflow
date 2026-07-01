# auto-scripts

Batch driver + reporting scripts for the CRS rule-generation pipeline. All commands assume you run from the repo root using the project venv:

```
venv/Scripts/python.exe auto-scripts/<script>.py [options]
```

(On Windows PowerShell this is the same path; on Git Bash use `./venv/Scripts/python.exe`.)

Everything downstream reads `out/<CVE-ID>/verdict.json` and, where relevant, `new.json` — both produced by `run-pipeline.py`. Run `run-pipeline.py` first.

---

## run-pipeline.py

Runs the 3-step skill pipeline (`crs-retrieve-analyze` → `crs-variant-gen` → `crs-rule-author`) over a list of Nuclei templates, one `out/<id>/` folder per template.

```
venv/Scripts/python.exe auto-scripts/run-pipeline.py --list cve-list.txt
venv/Scripts/python.exe auto-scripts/run-pipeline.py --list cve-list.txt --gen-variants root-cause-only
venv/Scripts/python.exe auto-scripts/run-pipeline.py --list cve-list.txt --resume
venv/Scripts/python.exe auto-scripts/run-pipeline.py --list cve-list.txt --max-budget-usd 2.00 --max-turns 20
```

- `--list` (required) — path to a template list file: one Nuclei template path per line, `#` = comment.
- `--gen-variants` — `class-only` (default) | `root-cause-only` | `all-triggered-rules`.
- `--model` — Claude model to invoke (default `claude-sonnet-4-6`).
- `--log-file` — pipeline-level run log (default `pipeline-run.log`).
- `--max-budget-usd`, `--max-turns` — per-step caps passed to `claude -p`.
- `--resume` — skip a step if its output artifact already exists (`verdict.json` / `extended-requests.json` / `new.json`), so you can re-run the same list after a partial/failed run without redoing completed work.

Self-gating: if Step 1's `scope_gate.decision` is `virtual-patch-only` or `out-of-scope-structural`, Steps 2 and 3 are skipped locally (no API call). Per-step debug logs and raw JSON dumps land in `out/<id>/claude-stepN.log` / `.raw.json`.

---

## stats-verdicts.py

Console tally of outcomes across all `out/<id>/verdict.json` — the quick "where do we stand" check.

```
venv/Scripts/python.exe auto-scripts/stats-verdicts.py
venv/Scripts/python.exe auto-scripts/stats-verdicts.py --out-dir out
venv/Scripts/python.exe auto-scripts/stats-verdicts.py --json
```

- `--out-dir` — directory holding `<id>/verdict.json` (default `out`).
- `--json` — emit a machine-readable JSON dump instead of the console table.

Prints: status breakdown (`covered` / `gated` / `in-scope` / `no-gate`), gate breakdown, in-scope Step-3 outcome (`new.json` present or `pending`), probe-blocked stats, attack-family counts, and a per-template table.

---

## reviewer.py

Purple-team review workbook (`.xlsx`) built from the same `verdict.json`/`new.json` classification as `stats-verdicts.py`, plus a derived recommendation and rule-logic summary per CVE.

```
venv/Scripts/python.exe auto-scripts/reviewer.py
venv/Scripts/python.exe auto-scripts/reviewer.py --out-dir out --xlsx cve-review.xlsx
```

- `--out-dir` — directory holding `<id>/verdict.json` (default `out`).
- `--xlsx` — output workbook path (default `cve-review.xlsx`).

Output has two sheets:
- **Summary** — status/gate/authored/blocked/attack-family tallies.
- **CVE Review** — one row per CVE: classification, template metadata, probe/anomaly scores, root-cause or new-rule IDs, a two-column rule-logic summary (structural summary + prose explanation — never the raw `SecRule` pattern itself, since some are very long), and a purple-team recommendation (accept baseline / ship new rule / virtual-patch outside CRS core / push back to app-vendor), grounded in the skill's own rationale/note text.

For handoff to the content/purple team, use `resources-compress.py` (below) instead of sharing the full `out/` tree.

---

## resources-compress.py

Stages and zips just the small review-relevant artifacts per CVE — split out of `reviewer.py` so that script stays focused on the xlsx report. Use this when you need to send case files to the content/purple team without the heavyweight debug transcripts (`claude-step*.log`/`.raw.json`, tens-hundreds of KB each per step).

```
venv/Scripts/python.exe auto-scripts/resources-compress.py
venv/Scripts/python.exe auto-scripts/resources-compress.py --out-dir out --resources-zip handoff.zip
```

- `--out-dir` — directory holding `<id>/verdict.json` (default `out`).
- `--resources-dir` — staging folder for copied artifacts (default `cve-resources`).
- `--resources-zip` — output `.zip` path (default `<resources-dir>.zip`).
- `--resources-files` — comma-separated file names to copy per CVE, overriding the default set (`verdict.json, probe.json, probe-input.json, new.json, extended-requests.json, variant-handoff.json, verify-candidate.conf, verify-report.json` — whichever exist).
- `--keep-staging` — keep the staging folder after zipping (default: delete it, zip only).

Note: some PoC payloads embedded in `verdict.json`/`new.json` (e.g. webshell snippets) can get silently quarantined by antivirus during copy. The script wraps each file copy/zip in its own try/except and reports skipped files as a warning instead of aborting the batch — re-run if you see warnings and check whether AV quarantined something.

---

## workflow_evaluation.py

Per-CVE / per-step run metrics (tokens, timing, cost, status) to CSV, read from `out/<id>/claude-stepN.raw.json`.

```
venv/Scripts/python.exe auto-scripts/workflow_evaluation.py
venv/Scripts/python.exe auto-scripts/workflow_evaluation.py --out-dir out --csv workflow-evaluation.csv
venv/Scripts/python.exe auto-scripts/workflow_evaluation.py --csv -
venv/Scripts/python.exe auto-scripts/workflow_evaluation.py --pricing pricing.csv
```

- `--out-dir` — directory holding `<id>/claude-stepN.raw.json` (default `out`).
- `--csv` — output CSV path, or `-` for stdout (default `workflow-evaluation.csv`).
- `--pricing` — custom pricing CSV to override `cost_usd` (columns: `1M_input_tokens`, `1M_output_tokens`, `1M_cache_read_tokens`[, `1M_cache_write_tokens`] — see `pricing.csv` for an example).

One CSV row per `(cve, step)` plus a per-CVE `TOTAL` row. Console output (when `--csv` isn't `-`) also prints grand totals, per-step averages, and per-CVE averages split by final status (`covered` / `in-scope` / `gated`). Steps 2–3 exclude gated CVEs from the averages, since those were self-HALTed degenerate runs pre-mechanical-gate.
