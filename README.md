# CRS Rule Generator

Automated pipeline: **Nuclei vulnerability template → CRS `SecRule` recommendation** via engine-as-oracle + LLM synthesis.

Coverage is determined by probing crafted HTTP requests through a real Coraza/CRS instance at PL2 — not keyword matching. When a gap exists, LLM synthesis produces a SecRule candidate backed by RAG from `comibined-docs/` and verified by the same engine.

See [`CLAUDE.md`](CLAUDE.md) for authoring conventions and [`workflow.md`](workflow.md) for full stage state machines.

---

## Prerequisites

- **Python 3.9+** — pipeline helper scripts
- **Go ≥ 1.25** — only needed to rebuild `probe-engine`; pre-built binary at `tools/probe-engine/probe-engine.exe`
- **Claude Code** — pipeline runs as three slash-command skills

## Setup

```bash
# initialise submodules (coreruleset, nuclei-templates, doc_modules)
git submodule update --init --recursive

# rebuild probe-engine only if the binary is missing or Go source changed
cd tools/probe-engine && go build -o probe-engine.exe . && cd ../..

# build rule metadata index (required for Stage 1 RETRIEVE + Stage 3 DESIGN)
python .claude/skills/crs-retrieve-analyze/tools/build_rule_index.py
```

---

## Running the pipeline

All stages run as Claude Code skills inside this repo root. Outputs land in `out/<template_id>/`.

### Stage 1 — Coverage analysis (`/crs-retrieve-analyze`)

```
/crs-retrieve-analyze <path/to/template.yaml>
```

Probes the template's exploit request at PL2, adjudicates root-cause, and writes `verdict.json`. Also spawns Stage 2 as a background agent (default `--gen-variants=class-only`).

Optional flags passed as part of the prompt:
- `--gen-variants=off|class-only|root-cause-only|all-triggered-rules` (default: `class-only`)
- `force-candidates` — populate `candidate_rules` even on covered templates

### Stage 2 — Variant generation (`/crs-variant-gen`)

Spawned automatically by Stage 1. To run standalone:

```
/crs-variant-gen out/<id>/variant-handoff.json out/<id>/probe.json \
  [--gen-variants=class-only|root-cause-only|all-triggered-rules]
```

Reads `variant-handoff.json` + `probe.json`, crafts attack-class variants, writes `extended-requests.json`.

### Stage 3 — Rule synthesis (`/crs-rule-author`)

```
/crs-rule-author out/<id>/
```

Reads `verdict.json` + `extended-requests.json`, synthesizes a SecRule via RAG, verifies with engine (max 5 iterations), writes `new.json`.

Halts automatically when `scope_gate` is `out-of-scope-structural` or `virtual-patch-only` — these cases are documented in `verdict.json`.

---

## Outputs

| File | Stage | Keep? | Description |
|------|-------|-------|-------------|
| `out/<id>/verdict.json` | S1 | yes | Coverage decision + probe transcript + candidate rules |
| `out/<id>/extended-requests.json` | S2 | yes | PoC + attack-class variants (input for S3 verify) |
| `out/<id>/new.json` | S3 | yes | SecRule recommendation — review before adding to `coreruleset/rules/` |
| `out/<id>/variant-handoff.json` | S1 | yes | S1→S2 handoff context (trace/re-run) |
| `out/<id>/probe.json` | S1 | yes | Parsed probe results (trace/re-run) |
| `out/<id>/probe-raw.json` | S1 | auto-deleted | Raw engine output — removed after `probe.json` is written |
| `out/<id>/analysis.json` | S1 | auto-deleted | Staging judgment — removed after `verdict.json` is assembled |

`new.json` is a recommendation only — it is not committed to `coreruleset/` automatically.

---

## Reference

| Need | Location |
|------|----------|
| Rule authoring conventions, metadata tiers | [`CLAUDE.md`](CLAUDE.md) |
| Full stage state machines, HARD GATES, SCOPE-GATE logic | [`workflow.md`](workflow.md) |
| probe-engine flags and JSON schema | [`tools/probe-engine/README.md`](tools/probe-engine/README.md) |
| RAG corpus (operators, variables, transforms, CRS patterns) | [`comibined-docs/`](comibined-docs/) |
| Existing CRS rules (few-shot reference) | [`coreruleset/rules/`](coreruleset/rules/) |
| Nuclei templates (pipeline input) | [`nuclei-templates/`](nuclei-templates/) |
