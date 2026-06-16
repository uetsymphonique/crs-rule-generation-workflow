# Rule Metadata — A Detection-First Policy

This project's output is a **rule recommendation for testing / review**, not a release-ready
file dropped straight into a production CRS deployment. The priority is that the rule's
**detection logic faithfully matches the attack pattern in the input**. Metadata is therefore
tiered by whether it affects detection/behavior/scoring or is pure deployment bookkeeping that
the integrator adds when slotting the rule into a CRS release.

> **Rule of thumb:** emit what changes *what the rule does*; skip what only changes *how the
> ruleset is catalogued*.

---

## Tier 1 — Detection / behavior / scoring (always emit)

These either make the rule functional or encode the core detection decision. A rule missing
any of these is wrong or non-functional.

| Field | Why it is essential |
|---|---|
| `id` | The engine requires a unique numeric id. Use the correct CRS range (900,000–949,999 inbound; 950,000–999,999 outbound). Exact neighbor allocation is bookkeeping — a valid in-range id is enough for a recommendation. |
| `phase` | Selects which data the rule sees. **Always numeric** (`phase:2`, never `phase:request`). A wrong phase means the target data is not yet available — a pure detection error. |
| disruptive action | Use `block` (delegates to `SecDefaultAction`). Determines what happens on match. |
| `severity` | Maps directly to the anomaly score (see ##2). It is a scoring input, not a label. |
| scoring `setvar` | `setvar:'tx.inbound_anomaly_score_plN=+%{tx.<sev>_anomaly_score}'` (optionally a category score too). This is the CRS detection model — without it the match contributes nothing. |
| `tag:'paranoia-level/N'` | Declares the strictness / false-positive tier the rule belongs to. This is a detection-engineering decision (how aggressive the match is), not bookkeeping. |
| `capture` | Required whenever the logic or `logdata` references a captured group (`%{TX.0}`, `%{TX.1}`…). |

> The matching core itself — **variables, operator, transformations, `chain`** — is not
> "metadata"; it is the rule. See `core_kb.md` and the `*_category.md` references.

---

## Tier 2 — Recommendation legibility (emit, but not blocking)

These make the recommendation reviewable and show evidence of the match. Keep them because the
deliverable is a *recommendation a human evaluates*, but their absence does not break detection.

| Field | Role |
|---|---|
| `msg` | Human-readable statement of what the rule detects. Anchors the "why" trace. |
| `logdata` | Surfaces the matched evidence, e.g. `logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}'`. Lets a reviewer confirm the rule fires on the intended payload. |

---

## Tier 3 — Deployment bookkeeping (skip unless asked)

These do **not** affect matching, blocking, or scoring. They classify and version the rule for
catalogue/exclusion/management purposes and are properly the integrator's responsibility when
the rule is placed into a specific CRS release. Omitting them keeps the recommendation focused
on detection.

- `ver` (e.g. `ver:'OWASP_CRS/4.x'`), `rev`
- Classification tags: `tag:'OWASP_CRS'`, `tag:'OWASP_CRS/ATTACK-*'`, `tag:'capec/...'`
- Context tags: `tag:'application-*'`, `tag:'language-*'`, `tag:'platform-*'`
- Attack-class tags: `tag:'attack-*'` (broad) and `tag:'attack-*/*'` (specific technique)

> The attack family and target platform are still worth stating **in the prose trace** that
> accompanies the rule (they explain the design); they just need not be encoded as tags in a
> recommendation. Note also that real CRS rules frequently carry only the broad `attack-*` tag
> and no `attack-*/*` — the specific-technique tag is optional, not mandatory.

---

## 2. Severity → anomaly score

`severity` is a scoring input. It selects which CRS anomaly-score variable a Tier-1 `setvar`
increments:

| Declared severity | Score variable | Default score | When to use |
| :--- | :--- | :--- | :--- |
| `severity:'CRITICAL'` | `%{tx.critical_anomaly_score}` | 5 | Confirmed, unambiguous attack payload. |
| `severity:'ERROR'` | `%{tx.error_anomaly_score}` | 4 | Highly likely attack, some false-positive risk. |
| `severity:'WARNING'` | `%{tx.warning_anomaly_score}` | 3 | Suspicious pattern, moderate FP risk. |
| `severity:'NOTICE'` | `%{tx.notice_anomaly_score}` | 2 | Policy violation or minor anomaly. |

### Worked example (Tier 1 + Tier 2 only)

A focused, detection-first recommendation — no Tier-3 bookkeeping tags:

```apache
SecRule ARGS "@detectSQLi" \
    "id:942100,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,\
    msg:'SQL Injection detected via libinjection',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}',\
    tag:'paranoia-level/1',\
    severity:'CRITICAL',\
    multiMatch,\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

> If a release-ready rule is explicitly requested, add the Tier-3 fields to match a target CRS
> version's idiom — ground them against a sibling rule in `coreruleset/rules/`.
