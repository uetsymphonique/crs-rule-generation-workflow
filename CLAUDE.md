# CLAUDE.md — CRS Rule Generation Workflow

## Project Purpose

Automated pipeline: **Nuclei vulnerability template → LLM (RAG) → ModSecurity/CRS `SecRule`**.

Nuclei templates describe exploit/vulnerability patterns. CRS rules are WAF rules that block those patterns. This repo provides the documentation corpus (RAG context) and the workflow to generate correct, CRS-compliant `SecRule` definitions via LLM.

---

## Repository Layout

```
crs-rule-generation-workflow/
├── comibined-docs/          # PRIMARY RAG CORPUS — curated, LLM-optimized docs
│   ├── modsec-docs/         # ModSecurity engine reference (actions, operators, variables, transforms, directives, phases)
│   ├── CRS-contents/        # CRS-specific patterns (anomaly scoring, rule syntax, chaining, regex, authoring standards, testing)
│   └── nuclei-docs/         # Nuclei template format reference
│
├── doc_modules/             # Raw upstream docs (git submodules, read-only)
│   ├── ModSecurity.wiki/    # ModSecurity v3 official wiki
│   ├── crs-documentation/   # OWASP CRS docs site source
│   └── nuclei-docs/         # Nuclei scanner official docs
│
├── coreruleset/             # Git submodule — fork of OWASP CRS
│   ├── rules/               # Actual .conf rule files (reference for rule patterns)
│   └── regex-assembly/      # .ra regex assembly files
│
├── nuclei-templates/        # Git submodule — Nuclei vuln templates (INPUT source)
├── skill-lesson-learn.md    # 10 lessons for writing effective AI agent skills
└── README.md
```

---

## Key Conventions

### Where to look for reference
- **ModSec engine** (actions, operators, variables, transforms, directives): `comibined-docs/modsec-docs/`
- **CRS rule authoring** (anomaly scoring, chaining, regex, metadata): `comibined-docs/CRS-contents/`
- **Nuclei template format**: `comibined-docs/nuclei-docs/nuclei-template-format.md`
- **Existing CRS rules** (patterns to follow): `coreruleset/rules/*.conf`

### SecRule generation rules
- CRS detection rules use `block` + `setvar:tx.anomaly_score_pl%{TX:DETECTION_PARANOIA_LEVEL}=+%{tx.critical_anomaly_score}` — **never `deny`** in detection rules
- Required metadata per rule: `id`, `phase`, `msg`, `tag`, `ver`, `severity`, `maturity`, `accuracy`
- Rule IDs: check `coreruleset/rules/` to avoid conflicts; CRS uses ranges (9xxxxx)
- Transformations are mandatory for string matching to prevent bypass (e.g., `t:lowercase,t:urlDecodeUni`)
- See `comibined-docs/modsec-docs/metadata/required-metadata.md` for the full required fields spec

### Submodule policy
- `doc_modules/` and `nuclei-templates/` are upstream read-only submodules — **do not edit files inside them**
- `coreruleset/` is a fork — edits are allowed but should follow CRS contribution conventions

---

## Workflow

Full detail: `workflow.md`

```
Nuclei template
      ↓
  Probe Engine (Coraza + CRS, PL2) — engine-as-oracle
      ↓
  Adjudicate root-cause
  "root-cause rule fired?"
      ↓ yes                        ↓ no
  covered (terminal)          SCOPE-GATE → RETRIEVE
  recommendation in           candidate_rules for
  verdict.json                Rule Designer
                                   ↓ (scope_gate=in-scope)
                              crs-variant-gen (Lane 2)
                              extended-requests.json
                                   ↓
                              crs-rule-author (Lane 3)
                              new rule recommendation
                                   ↓
                              verify_rule.py (Lane 4)
                                   ↓
                              out/<id>/new.json
```

**Two stages, distinct roles:**
- **Stage 1 (crs-retrieve-analyze)** — engine-as-oracle: probe PL2, adjudicate root-cause, classify scope, build candidate_rules handoff
- **Stage 2 (crs-variant-gen + crs-rule-author)** — generation: craft variants, synthesize new SecRule with RAG from `comibined-docs/`, verify with engine

**One output type:**
- `new` — new SecRule recommendation; greenfield (not-covered) or complementary (covered + force-candidates)

---

## Skill Development

`skill-lesson-learn.md` documents 10 principles for writing effective AI agent skills (hard gates, state machines, Red Flags tables, terminal states, etc.). Apply these when building or reviewing skills in this project.
