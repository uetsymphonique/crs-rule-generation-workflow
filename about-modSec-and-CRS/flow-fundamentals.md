# ModSecurity & CRS — Request Processing Flow Fundamentals

## 1. Overview

ModSecurity is a **Web Application Firewall (WAF) engine** that integrates as a module within the web server (Apache, Nginx, IIS). It intercepts HTTP transactions at multiple processing points called **phases**, applies configured rules to inspect request and response data, and takes disruptive or non-disruptive actions accordingly.

The **OWASP Core Rule Set (CRS)** is a ruleset loaded on top of ModSecurity. It provides a set of generic attack-detection rules for the most common web vulnerabilities (OWASP Top 10), organized by attack category and controlled by **paranoia levels** and an **anomaly scoring** mechanism.

Together, they form a layered inspection pipeline:

```
Client Request
      │
      ▼
[ Web Server (Apache/Nginx) ]
      │
      ▼ ModSecurity intercepts
[ Phase 1: Request Headers ]
[ Phase 2: Request Body    ]
      │
      ▼
[ Backend Application ]
      │
      ▼ Response generated
[ Phase 3: Response Headers ]
[ Phase 4: Response Body    ]
      │
      ▼
[ Phase 5: Logging          ]
      │
      ▼
Client Response
```

---

## 2. ModSecurity Processing Phases

ModSecurity processes each HTTP transaction across **five phases** in sequence. Rules are assigned to a phase via the `phase:N` action. A rule only runs in its designated phase.

### Phase 1 — Request Headers
- Fires **before the request body is read**.
- Available variables: `REQUEST_URI`, `REQUEST_METHOD`, `REQUEST_HEADERS`, `ARGS_GET`, `REQUEST_COOKIES`.
- Typical use: enforce HTTP method allowlist, check `Content-Type`, detect scanner User-Agents, validate URI structure.
- CRS rules that run here: `REQUEST-911` (method), `REQUEST-913` (scanner detection), parts of `REQUEST-920` (protocol enforcement).

### Phase 2 — Request Body
- Fires **after the complete request body has been buffered**.
- Available variables: all Phase 1 variables plus `ARGS_POST`, `FILES`, `REQUEST_BODY`, `XML:/*`.
- ModSecurity parses the body according to `Content-Type`:
  - `application/x-www-form-urlencoded` → populates `ARGS_POST`
  - `multipart/form-data` → populates `FILES` and `ARGS_POST`
  - `application/json` → accessible via `REQUEST_BODY`
  - `application/xml` → accessible via `XML:/*` XPath
- Typical use: detect attack payloads in parameters (SQLi, XSS, LFI, RCE, etc.).
- CRS rules that run here: `REQUEST-930` through `REQUEST-944` (all attack detection files).

> **Note:** `SecRequestBodyAccess On` must be enabled for Phase 2 to inspect body data.

### Phase 3 — Response Headers
- Fires **after the backend sends response headers**, before the body is streamed.
- Available variables: `RESPONSE_HEADERS`, `RESPONSE_STATUS`.
- Typical use: detect error status codes (5xx), inspect `Content-Type` / `Content-Encoding`.
- CRS rules here: `RESPONSE-959` early blocking check (if early blocking is enabled), status code leakage at PL2 in `RESPONSE-950`.

### Phase 4 — Response Body
- Fires **after the entire response body has been buffered**.
- Available variables: `RESPONSE_BODY`, `RESPONSE_HEADERS`.
- **Limitation:** If `Content-Encoding` is `gzip`, `deflate`, `br`, or `zstd`, ModSecurity cannot decompress the body → CRS skips all body inspection rules to avoid false positives.
- Typical use: detect data leakage (SQL errors, stack traces, source code, web shells).
- CRS rules here: `RESPONSE-950` through `RESPONSE-955`, `RESPONSE-959` final blocking evaluation.

> **Note:** `SecResponseBodyAccess On` must be enabled for Phase 4 to buffer and inspect the body.

### Phase 5 — Logging
- Fires **after the response has already been sent to the client**.
- No blocking is possible in this phase.
- Used for post-processing: correlating inbound and outbound anomaly scores, emitting structured log entries.
- CRS rules here: `RESPONSE-980` correlation and reporting.

---

## 3. CRS Initialization (REQUEST-901)

Before any transaction processing, CRS runs an initialization block that sets all global `TX` variables:

```apache
# Paranoia and blocking levels
setvar:'tx.paranoia_level=1'
setvar:'tx.blocking_paranoia_level=1'

# Anomaly score thresholds
setvar:'tx.inbound_anomaly_score_threshold=5'
setvar:'tx.outbound_anomaly_score_threshold=4'

# Anomaly score weights per severity
setvar:'tx.critical_anomaly_score=5'
setvar:'tx.error_anomaly_score=4'
setvar:'tx.warning_anomaly_score=3'
setvar:'tx.notice_anomaly_score=2'

# Per-category score accumulators (start at 0)
setvar:'tx.sqli_score=0'
setvar:'tx.xss_score=0'
setvar:'tx.lfi_score=0'
setvar:'tx.rce_score=0'
...

# Per-PL inbound/outbound accumulators
setvar:'tx.inbound_anomaly_score_pl1=0'
setvar:'tx.inbound_anomaly_score_pl2=0'
setvar:'tx.inbound_anomaly_score_pl3=0'
setvar:'tx.inbound_anomaly_score_pl4=0'
setvar:'tx.outbound_anomaly_score_pl1=0'
...
```

---

## 4. Anomaly Scoring Mechanism

CRS does **not block directly**. Instead, each detection rule adds points to a shared score. A separate evaluation rule checks if the total score exceeds the configured threshold and triggers the block.

### Inbound (Request) Scoring Flow

```
Detection rule fires
        │
        ▼ Action: setvar
tx.CATEGORY_score      += tx.critical_anomaly_score   (category accumulator)
tx.inbound_anomaly_score_plN += tx.[severity]_anomaly_score  (PL accumulator)
        │
        │  (more rules may fire and add more points)
        │
        ▼ REQUEST-949 (end of request processing)
tx.blocking_inbound_anomaly_score = sum of all plN scores
        │
        ▼ Compare against threshold
IF tx.blocking_inbound_anomaly_score >= tx.inbound_anomaly_score_threshold
        → DENY request (HTTP 403)
```

### Outbound (Response) Scoring Flow

```
Detection rule fires (Phase 3 or 4)
        │
        ▼ Action: setvar
tx.outbound_anomaly_score_plN += tx.[severity]_anomaly_score
        │
        ▼ RESPONSE-959 (end of response processing)
tx.blocking_outbound_anomaly_score = sum of all plN scores
        │
        ▼ Compare against threshold
IF tx.blocking_outbound_anomaly_score >= tx.outbound_anomaly_score_threshold
        → DENY (block response body from reaching client)
```

### Score Accumulation by Paranoia Level

`REQUEST-949` and `RESPONSE-959` sum per-PL scores selectively based on the configured `blocking_paranoia_level`:

```apache
# If blocking_paranoia_level >= 1, include PL1 scores
SecRule TX:BLOCKING_PARANOIA_LEVEL "@ge 1" "setvar:'tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl1}'"

# If blocking_paranoia_level >= 2, also include PL2 scores
SecRule TX:BLOCKING_PARANOIA_LEVEL "@ge 2" "setvar:'tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl2}'"
...
```

This design decouples **detection** (`detection_paranoia_level`) from **blocking** (`blocking_paranoia_level`), enabling a safe ramp-up strategy: detect at PL3, block at PL1 until tuning is done.

---

## 5. Paranoia Level (PL) Skip Gates

Within each attack detection file, rules are organized by PL. Each PL block is guarded by skip gates:

```apache
# Skip PL1 and above if detection_paranoia_level < 1
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:9xx011,phase:1,pass,nolog,skipAfter:END-..."
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:9xx012,phase:2,pass,nolog,skipAfter:END-..."

# PL1 rules run here ...

# Skip PL2 and above if detection_paranoia_level < 2
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" "id:9xx013,phase:1,pass,nolog,skipAfter:END-..."
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" "id:9xx014,phase:2,pass,nolog,skipAfter:END-..."

# PL2 rules run here ...
# (and so on for PL3, PL4)
```

This ensures rules above the configured PL are **never evaluated**, saving CPU cycles.

---

## 6. Detection Rule Anatomy

A typical CRS detection rule follows this structure:

```apache
SecRule VARIABLES "@rx PATTERN" \
    "id:NNNNNN,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:lowercase,\
    msg:'Attack Description',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-TYPE',\
    tag:'paranoia-level/N',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-TYPE',\
    tag:'capec/...',\
    ver:'OWASP_CRS/4.x.x',\
    severity:'CRITICAL',\
    setvar:'tx.TYPE_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_plN=+%{tx.critical_anomaly_score}'"
```

Key components:

| Component | Role |
|---|---|
| `VARIABLES` | WHERE to look (`ARGS`, `REQUEST_HEADERS`, `RESPONSE_BODY`, etc.) |
| `@rx PATTERN` | WHEN to trigger (regex / pmFromFile / detectSQLi / detectXSS) |
| `t:none,t:...` | Transformation chain applied BEFORE matching (anti-evasion normalization) |
| `block` | Use the default disruptive action (configured via `SecDefaultAction`) |
| `capture` | Store the matched value in `TX:0` for use in `logdata` |
| `setvar` | Increment the anomaly score accumulators |

---

## 7. Transformation Pipeline (Anti-Evasion)

ModSecurity applies transformations to the variable value **before** running the operator. This neutralizes encoding-based evasion attacks.

Transformations are applied **in order**. `t:none` resets any inherited transformations from `SecDefaultAction`.

Common transformation stacks per attack type:

| Attack | Transformation Stack | Purpose |
|---|---|---|
| LFI / Path traversal | `t:none,t:utf8toUnicode,t:urlDecodeUni,t:normalizePathWin` | Decode %2e, unicode slashes, resolve ../ |
| RCE / Shell injection | `t:none` (or + `t:cmdLine`) | cmdLine removes quotes, lowercases, strips separators |
| SQLi | `t:none` | libinjection handles normalization internally |
| XSS | `t:none,t:lowercase,t:removeWhitespace,t:htmlEntityDecode` | Normalize HTML, case, space |
| Generic | `t:none,t:urlDecodeUni,t:removeNulls` | URL-decode, strip null bytes |

> **Important:** `t:cmdLine` removes semicolons, so avoid it for rules that need to detect semicolons.

---

## 8. Variable Inspection Scope

Rules use target collections that define the HTTP data surface:

```apache
# Most attack detection rules inspect all user-controllable inputs:
REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*

# Header-targeting rules (often PL2 stricter siblings):
REQUEST_HEADERS:Referer|REQUEST_HEADERS:User-Agent

# LFI-specific (includes raw URI):
REQUEST_URI_RAW|ARGS|REQUEST_HEADERS|!REQUEST_HEADERS:Referer|FILES|XML:/*

# Response body inspection:
RESPONSE_BODY
```

Collection modifiers:
- `|` — inspect multiple targets in one rule
- `!ARGS:password` — exclude a specific key from a collection
- `&ARGS` — count of arguments (used for numeric comparisons)
- `ARGS:fieldname` — target a specific argument by name

---

## 9. Early Blocking

By default, blocking decisions are made at Phase 2 (inbound) and Phase 4 (outbound). CRS supports **early blocking** to block earlier:

```
TX:EARLY_BLOCKING = 1   →  blocking check at Phase 1 (inbound) and Phase 3 (outbound)
```

Early blocking reduces backend load for high-confidence detections (e.g., scanning attempts caught at the header level), but means the body is never read for blocked requests.

---

## 10. Response Rule Special Behaviors

Response rules have two unique guards not present in request rules:

### Compressed Body Guard
```apache
# At PL0 in every response file
SecRule RESPONSE_HEADERS:Content-Encoding "@pm gzip compress deflate br zstd" \
    "id:9xx010,phase:4,pass,nolog,...,skipAfter:END-RESPONSE-9xx-..."
```
ModSecurity cannot decompress response bodies, so if the body is compressed, all body-inspection rules are skipped entirely.

### Global Skip Guard
```apache
# In RESPONSE-950, applied globally across all response analysis
SecRule TX:crs_skip_response_analysis "@eq 1" \
    "id:950021,phase:3,...,skipAfter:END-RESPONSE-959-BLOCKING-EVALUATION"
```
Setting `tx.crs_skip_response_analysis=1` disables all outbound analysis for the current transaction (useful for exception handling).

---

## 11. Phase 5 Correlation and Reporting

After the transaction completes, `RESPONSE-980` combines inbound and outbound scores into unified metrics and logs them:

```
tx.blocking_anomaly_score  = blocking_inbound + blocking_outbound
tx.detection_anomaly_score = detection_inbound + detection_outbound
tx.anomaly_score           = blocking_inbound + blocking_outbound  (legacy compat)
```

The log entry emitted by rule `980170` contains the full score breakdown:
```
Anomaly Scores:
  (Inbound: blocking=10, detection=10, per_pl=5-5-0-0, threshold=5)
  (Outbound: blocking=4, detection=4, per_pl=4-0-0-0, threshold=4)
  (SQLI=5, XSS=0, RFI=0, LFI=0, RCE=5, PHPI=0, HTTP=0, SESS=0, COMBINED_SCORE=14)
```

**Reporting levels** control when this log is emitted:

| Level | When logged |
|---|---|
| 0 | Never |
| 1 | Only when blocking score exceeds threshold |
| 2 | When detection score exceeds threshold |
| 3 | When total blocking score > 0 |
| 4 | When total detection score > 0 (any match at all) |
| 5 | Always (every request) |

---

## 12. Rule File Processing Order

ModSecurity loads rule files in alphabetical order. CRS filenames are numbered to enforce the correct sequence:

```
REQUEST-901-INITIALIZATION.conf         ← 1. Init TX variables
REQUEST-905-COMMON-EXCEPTIONS.conf      ← 2. Global allowlist exceptions
REQUEST-911-METHOD-ENFORCEMENT.conf     ← 3. HTTP method control
REQUEST-913-SCANNER-DETECTION.conf      ← 4. Scanner/bot detection
REQUEST-920-PROTOCOL-ENFORCEMENT.conf   ← 5. Protocol checks
REQUEST-921-PROTOCOL-ATTACK.conf        ← 6. HTTP smuggling, etc.
REQUEST-922-MULTIPART-ATTACK.conf       ← 7. Multipart parsing attacks
REQUEST-930-APPLICATION-ATTACK-LFI.conf ← 8. LFI detection
REQUEST-931-APPLICATION-ATTACK-RFI.conf ← 9. RFI detection
REQUEST-932-APPLICATION-ATTACK-RCE.conf ← 10. RCE detection
REQUEST-933-APPLICATION-ATTACK-PHP.conf
REQUEST-934-APPLICATION-ATTACK-GENERIC.conf
REQUEST-941-APPLICATION-ATTACK-XSS.conf
REQUEST-942-APPLICATION-ATTACK-SQLI.conf
REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
REQUEST-944-APPLICATION-ATTACK-JAVA.conf
REQUEST-949-BLOCKING-EVALUATION.conf    ← 11. Sum scores & block decision
RESPONSE-950-DATA-LEAKAGES.conf         ← 12. Generic leakage
RESPONSE-951-DATA-LEAKAGES-SQL.conf     ← 13. SQL error leakage
RESPONSE-952-DATA-LEAKAGES-JAVA.conf    ← 14. Java stack trace leakage
RESPONSE-953-DATA-LEAKAGES-PHP.conf     ← 15. PHP error leakage
RESPONSE-954-DATA-LEAKAGES-IIS.conf     ← 16. IIS/ASP error leakage
RESPONSE-955-WEB-SHELLS.conf            ← 17. Web shell detection
RESPONSE-956-DATA-LEAKAGES-RUBY.conf    ← 18. Ruby error leakage
RESPONSE-959-BLOCKING-EVALUATION.conf   ← 19. Outbound block decision
RESPONSE-980-CORRELATION.conf           ← 20. Phase 5 logging + correlation
```

---

## 13. Chain Rules

A chain rule allows ANDing multiple conditions into a single logical rule. Only the first rule in the chain carries the `id`, `phase`, and disruptive action. Secondary rules just add further conditions:

```apache
# Fire only if BOTH conditions match
SecRule ARGS "@rx pattern1" \
    "id:942200,phase:2,block,capture,t:none,chain,\
    msg:'...',setvar:'tx.sqli_score=+%{tx.critical_anomaly_score}',..."
    SecRule MATCHED_VAR "@rx pattern2" \
        "t:none"
```

Chain rules are commonly used at PL2+ for higher-confidence, multi-signal detection. They carry a lower false positive risk than single-condition rules.

---

## 14. SecMarker and skipAfter

`SecMarker` defines a named label in the rule processing stream. Rules can use `skipAfter:MARKER_NAME` to jump forward to that position, skipping all intermediate rules.

```apache
# Jump over PL2 rules when PL < 2
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" \
    "id:942013,phase:2,pass,nolog,skipAfter:END-REQUEST-942-SQLI"

# ... PL2 rules ...

SecMarker "END-REQUEST-942-SQLI"
```

`skipAfter` is the core mechanism powering PL gating.
