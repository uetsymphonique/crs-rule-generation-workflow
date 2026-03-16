# CRS Rule ID Numbering Scheme

This document explains how CRS assigns rule IDs, including reserved blocks, step conventions, and the stricter sibling pattern.

---

## 1. Top-Level ID Ranges

| Range | Purpose |
|---|---|
| **900,000 – 949,999** | Inbound request rules (REQUEST-9xx files) |
| **950,000 – 999,999** | Outbound response rules (RESPONSE-9xx files) |
| **9,000,000 – 9,999,999** | Default exclusion packages and plugins |

---

## 2. Grouping by Vulnerability Class

Rules are grouped into **blocks of 1,000** by the attack category (or functionality) they address. The first three digits of the rule ID correspond to the file name prefix:

| File prefix | Rule ID block | Attack category |
|---|---|---|
| `REQUEST-901` | 901,000 – 901,999 | Initialization (TX setup) |
| `REQUEST-911` | 911,000 – 911,999 | Method enforcement |
| `REQUEST-913` | 913,000 – 913,999 | Scanner detection |
| `REQUEST-920` | 920,000 – 920,999 | Protocol enforcement |
| `REQUEST-921` | 921,000 – 921,999 | HTTP protocol attacks |
| `REQUEST-922` | 922,000 – 922,999 | Multipart body attacks |
| `REQUEST-930` | 930,000 – 930,999 | LFI |
| `REQUEST-931` | 931,000 – 931,999 | RFI |
| `REQUEST-932` | 932,000 – 932,999 | RCE |
| `REQUEST-933` | 933,000 – 933,999 | PHP injection |
| `REQUEST-934` | 934,000 – 934,999 | Generic injection |
| `REQUEST-941` | 941,000 – 941,999 | XSS |
| `REQUEST-942` | 942,000 – 942,999 | SQLi |
| `REQUEST-943` | 943,000 – 943,999 | Session fixation |
| `REQUEST-944` | 944,000 – 944,999 | Java injection |
| `RESPONSE-950` | 950,000 – 950,999 | Generic data leakage |
| `RESPONSE-951` | 951,000 – 951,999 | SQL error leakage |
| `RESPONSE-952` | 952,000 – 952,999 | Java stack trace leakage |
| `RESPONSE-953` | 953,000 – 953,999 | PHP error leakage |
| `RESPONSE-954` | 954,000 – 954,999 | IIS/ASP error leakage |
| `RESPONSE-955` | 955,000 – 955,999 | Web shell detection |

---

## 3. Within-File ID Layout

Within each file (e.g., `REQUEST-942-APPLICATION-ATTACK-SQLI.conf`, block = `942xxx`):

```
9xx000 – 9xx099   Reserved: CRS helper / control-flow rules only
                  No blocking or detection rules in this range.

    Reserved skip-gate IDs (always these exact IDs):
        9xx011, 9xx012  → Phase 1 & 2 skip-gate for PL1 (or global file skip)
        9xx013, 9xx014  → Phase 1 & 2 skip-gate for PL2
        9xx015, 9xx016  → Phase 1 & 2 skip-gate for PL3
        9xx017, 9xx018  → Phase 1 & 2 skip-gate for PL4

9xx100            First detection rule (PL1)
9xx110            Second detection rule (step of 10)
9xx120, 9xx130 …  More rules, always incrementing by 10

9xx101            Stricter sibling of 9xx100 (if needed at a higher PL)
9xx161            Stricter sibling of 9xx160
```

> **Important:** Rules are always **added at the end of their PL group**. Never insert a new rule between two existing IDs.

---

## 4. Stricter Sibling Pattern

A **stricter sibling** is a rule that is closely related to a base rule but applies tighter detection logic — typically the same attack vector inspected with:
- A stricter regex (less permissive, lower FP risk at higher PL)
- A different variable target (e.g., base rule covers `ARGS`, sibling also covers `REQUEST_HEADERS`)

### ID convention

```
Base rule:       9xx160   (PL1 or PL2)
Stricter sibling: 9xx161  (PL2 or PL3 — same first 5 digits, last digit = 1, 2, …)
```

### File placement

Stricter siblings are **not** placed next to their base rule. They are ordered by paranoia level, so a PL2 sibling of a PL1 rule appears in the PL2 block:

```
# PL1 detection rules
SecRule ...    "id:942160, ..."    ← base rule
SecRule ...    "id:942170, ..."

# PL2+ skip gate
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" "id:942013, ..., skipAfter:END-REQUEST-942-..."

# PL2 rules (including the stricter sibling of 942160)
SecRule ...    "id:942161, ..."    ← stricter sibling of 942160
```

### Documentation convention

- In the **base rule** comment, mention all its stricter siblings:
  ```apache
  # This rule has stricter siblings: 942161 (PL2) and 942162 (PL3).
  ```
- In the **stricter sibling** comment, refer back:
  ```apache
  # This is a stricter sibling of rule 942160.
  ```

---

## 5. Quick Reference: Adding a New Rule

1. Identify the correct **file** for the attack category.
2. Determine the **paranoia level** of the new rule.
3. Find the **highest existing ID** in that PL block within the file.
4. Use `highest_id + 10` as the new rule's ID.
5. If you are writing a stricter sibling: use `base_id + N` (N = 1, 2, … for each sibling).
6. If you are adding a new skip-gate: use the reserved IDs `9xx011–9xx018`.

### Example — Adding a new PL2 SQLi rule

```
Existing last PL2 rule in REQUEST-942: id 942370
New rule ID: 942380

File: REQUEST-942-APPLICATION-ATTACK-SQLI.conf
Position: after id 942370, before the PL3 skip-gate
```

### Example — Adding a stricter sibling

```
Base rule PL1: id 942300
Stricter sibling PL2: id 942301
(Another sibling PL3 if needed: id 942302)
```

---

## 6. Exclusion Packages and Plugin IDs (9,000,000+)

Plugins and default CRS exclusion packages use the range `9,000,000 – 9,999,999`. These are not part of the core CRS rule files and follow their own internal numbering within that range.
