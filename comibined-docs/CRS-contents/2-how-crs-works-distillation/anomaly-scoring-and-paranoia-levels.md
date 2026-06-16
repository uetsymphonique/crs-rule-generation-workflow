# Anomaly Scoring & Paranoia Levels — Rule Authoring Reference

## Architecture: Detection vs. Blocking (Critical Concept)

CRS decouples **detection** from **blocking**. Detection rules never block directly — they accumulate an anomaly score. A separate blocking evaluation rule (`REQUEST-949` / `RESPONSE-959`) reads the total score and decides whether to block.

**Implication for rule writing:** Every detection rule MUST use `block` (not `deny`) and MUST increment the anomaly score via `setvar`. A rule without `setvar` is silent — it matches but has no effect on the blocking decision.

---

## Mandatory Template for Every Detection Rule

```apache
SecRule VARIABLES "OPERATOR" \
    "id:XXXXXX,\
    phase:N,\
    block,\
    t:none,\
    msg:'Description of attack',\
    logdata:'%{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-TYPE',\
    tag:'paranoia-level/N',\
    tag:'OWASP_CRS',\
    tag:'capec/...',\
    ver:'OWASP_CRS/4.x.x-dev',\
    severity:'SEVERITY_LEVEL',\
    setvar:'tx.inbound_anomaly_score_plN=+%{tx.SEVERITY_anomaly_score}'"
```

Key constraints:
- Use `block`, never `deny` or `pass` for detection rules
- `setvar` line is **required** — omitting it makes the rule have no blocking effect
- `severity` and `setvar` must be consistent (see tables below)

---

## Severity → Anomaly Score

> **Note:** `severity` uses syslog numeric codes internally (CRITICAL=2, ERROR=3, WARNING=4, NOTICE=5), but always write the **text form** — numeric form is deprecated per the Reference Manual. The "Default score" column below refers to the *anomaly score value* (what `tx.critical_anomaly_score` etc. default to in REQUEST-901), which is a separate concept from the syslog code.

| `severity` value | `setvar` score variable          | Default anomaly score |
|-----------------|----------------------------------|-----------------------|
| `CRITICAL`      | `%{tx.critical_anomaly_score}`   | 5                     |
| `ERROR`         | `%{tx.error_anomaly_score}`      | 4                     |
| `WARNING`       | `%{tx.warning_anomaly_score}`    | 3                     |
| `NOTICE`        | `%{tx.notice_anomaly_score}`     | 2                     |

Most attack detection rules use `CRITICAL` (score 5). Protocol/policy violations typically use `WARNING` or `NOTICE`.

---

## Paranoia Level → setvar Variable

> **Note:** The Reference Manual (v3.x) shows the old CRS v2-era variable `tx.anomaly_score`. CRS v3+ uses per-PL variables. For **request rules** use `tx.inbound_anomaly_score_plN`; for **response rules** use `tx.outbound_anomaly_score_plN`.

| Paranoia Level | Request rules (`inbound`)                                              | Response rules (`outbound`)                                             |
|----------------|------------------------------------------------------------------------|-------------------------------------------------------------------------|
| PL 1           | `setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'` | `setvar:'tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'` |
| PL 2           | `setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'` | `setvar:'tx.outbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'` |
| PL 3           | `setvar:'tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}'` | `setvar:'tx.outbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}'` |
| PL 4           | `setvar:'tx.inbound_anomaly_score_pl4=+%{tx.critical_anomaly_score}'` | `setvar:'tx.outbound_anomaly_score_pl4=+%{tx.critical_anomaly_score}'` |

Tag must match: `tag:'paranoia-level/N'` where N matches the variable suffix.

---

## Choosing a Paranoia Level for a New Rule

| PL | Intent | False positive risk |
|----|--------|-------------------|
| 1  | Baseline — clear, unambiguous attack patterns only | Minimal |
| 2  | Broader patterns, some legitimate edge cases may match | Low–Medium |
| 3  | Specialized/uncommon attack vectors | Medium–High |
| 4  | Maximum coverage, aggressive patterns | High |

**Default for new rules targeting known CVEs/exploits:** PL 1 if the pattern is specific and unambiguous. Use PL 2 if the detection pattern is necessarily broad.

---

## Complete Example (CRS-style)

```apache
SecRule REQUEST_HEADERS:Content-Length "!@rx ^\d+$" \
    "id:920160,\
    phase:1,\
    block,\
    t:none,\
    msg:'Content-Length HTTP header is not numeric',\
    logdata:'%{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-protocol',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'capec/1000/210/272',\
    ver:'OWASP_CRS/4.x.x-dev',\
    severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```
