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
- Required metadata per rule (Tier 1): `id`, `phase`, `block`, `severity`, anomaly `setvar`, `tag:'paranoia-level/N'` (PL>1); (Tier 2): `msg`, `logdata` — `ver`/`maturity`/`accuracy` are Tier 3, skip unless release-ready
- Rule IDs: check `coreruleset/rules/` to avoid conflicts; CRS uses ranges (9xxxxx)
- Transformations are mandatory for string matching to prevent bypass (e.g., `t:lowercase,t:urlDecodeUni`)
- See `comibined-docs/modsec-docs/metadata/required-metadata.md` for the full required fields spec

### Submodule policy
- `doc_modules/` and `nuclei-templates/` are upstream read-only submodules — **do not edit files inside them**
- `coreruleset/` is a fork — edits are allowed but should follow CRS contribution conventions

---

## Workflow

Full detail: `workflow.md`

| Stage | Step | Condition | Output |
|-------|------|-----------|--------|
| **S1** crs-retrieve-analyze | CRAFT | — | `probe-input.json` |
| **S1** | PROBE (PL2, engine-as-oracle) | — | `probe.json` |
| **S1** | Adjudicate root-cause | ≥1 root-cause rule → **covered** | → INSPECT-ROOT-CAUSE |
| **S1** | Adjudicate root-cause | 0 root-cause rule → **not-covered** | → SCOPE-GATE |
| **S1** | INSPECT-ROOT-CAUSE | covered only | `rule_analysis[]` → recommendation |
| **S1** | SCOPE-GATE (G0–G4) | not-covered only | `scope_gate.decision` |
| **S1** | VARIANT-HANDOFF | always (both branches) | `variant-handoff.json` |
| **S1** | GEN-VARIANTS | `gen-variants≠off` **and** `scope_gate=in-scope` | spawn S2 bg agent |
| **S1** | RETRIEVE | not-covered **or** covered+force-candidates | `candidate_rules[]` |
| **S1** | EMIT | — | `verdict.json` |
| **S2** crs-variant-gen | craft attack-class variants | bg agent; runs parallel with S1 RETRIEVE→EMIT | `extended-requests.json` |
| **S3** crs-rule-author | DESIGN → SYNTHESIZE | not-covered or covered+force-candidates | SecRule candidate |
| **S3** | VERIFY (engine gate, max 5 iter) | all triggered → EMIT · any miss + iter<5 → DESIGN · iter=5 → EMIT residual | `new.json` |

**One output type:** `new` — greenfield (not-covered) or complementary (covered + force-candidates)

---

## Skill Development

`skill-lesson-learn.md` documents 10 principles for writing effective AI agent skills (hard gates, state machines, Red Flags tables, terminal states, etc.). Apply these when building or reviewing skills in this project.
