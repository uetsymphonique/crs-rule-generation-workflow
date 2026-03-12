# ModSecurity Rule Processing and Writing Logic

This document focuses on **how ModSecurity processes rules** and **how to reason through writing rule logic**. For full reference, see the category files in `workflow-plan/docs/`.

---

## 1. Rule Processing Flow

ModSecurity processes rules **phase by phase**, in order. Within a phase, rules execute in the order they appear in the configuration file.

```
HTTP Request arrives
        │
        ▼
┌─────────────────────────┐
│  Phase 1: Request       │  ← Headers only. No body yet.
│  Headers                │    Variables: REQUEST_HEADERS, REQUEST_URI,
│                         │    REQUEST_METHOD, REMOTE_ADDR, ARGS_GET
└────────────┬────────────┘
             │  (if body access enabled)
             ▼
┌─────────────────────────┐
│  Phase 2: Request Body  │  ← Full request available.
│                         │    Variables: ARGS, ARGS_POST, REQUEST_BODY,
│                         │    REQUEST_COOKIES, FILES, XML
└────────────┬────────────┘
             │  (request forwarded to backend)
             ▼
┌─────────────────────────┐
│  Phase 3: Response      │  ← Response headers available.
│  Headers                │    Variables: RESPONSE_HEADERS, RESPONSE_STATUS,
│                         │    RESPONSE_CONTENT_TYPE
└────────────┬────────────┘
             │  (if response body access enabled)
             ▼
┌─────────────────────────┐
│  Phase 4: Response Body │  ← Full response. Can detect data leakage.
│                         │    Variables: RESPONSE_BODY
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Phase 5: Logging       │  ← Cannot block. For logging only.
└─────────────────────────┘
```

**Key constraint:** A variable must exist in the current phase. If you reference `ARGS` in phase 1, it will be empty — a silent false negative.

---

## 2. Rule Evaluation Logic

For each rule, ModSecurity executes the following steps:

```
For each variable in the target list:
    Apply transformations (in order)
    Run operator against transformed value
    If match:
        Execute non-disruptive actions (setvar, log, capture, ctl...)
        If NOT in a chain → execute disruptive action
        If last rule in chain → execute disruptive action
```

### Collections expand at evaluation time

When a rule targets `ARGS` (a collection), ModSecurity **iterates over every member**:

```apache
SecRule ARGS "@rx attack" "id:1,..."
# → Evaluated against: ARGS:q, ARGS:name, ARGS:id, ARGS:token, ...
# → Triggers on the FIRST member that matches
```

To count members instead of inspecting values, prefix with `&`:

```apache
# Triggers if there are more than 20 parameters
SecRule &ARGS "@gt 20" "id:2,..."
```

---

## 3. Decision Process: Choosing a Variable

```
What data do I need to inspect?
├── Client parameter input (form fields, query string)?
│   ├── All input → ARGS
│   ├── Query string only → ARGS_GET
│   ├── POST body only → ARGS_POST
│   └── Parameter names only → ARGS_NAMES
│
├── Request headers?
│   ├── All headers → REQUEST_HEADERS
│   └── Specific header → REQUEST_HEADERS:User-Agent
│
├── Cookies?
│   ├── Values → REQUEST_COOKIES
│   └── Names → REQUEST_COOKIES_NAMES
│
├── URL / path?
│   ├── Full URL with query string → REQUEST_URI
│   ├── Path only → REQUEST_FILENAME
│   └── File name only → REQUEST_BASENAME
│
├── Request body (raw)?
│   └── REQUEST_BODY  (only when Content-Type: application/x-www-form-urlencoded)
│
├── Uploaded files?
│   ├── File names → FILES
│   └── Temporary disk paths → FILES_TMPNAMES
│
├── Is this about the response?
│   ├── Status code → RESPONSE_STATUS
│   ├── Headers → RESPONSE_HEADERS
│   └── Body → RESPONSE_BODY  (phase 4 only)
│
└── Transaction state?
    ├── Score accumulation → TX:anomaly_score
    └── Flags and custom state → TX:my_flag
```

---

## 4. Decision Process: Choosing an Operator

```
What kind of match do I need?

├── Match a specific, fixed value?
│   ├── Exact equality → @streq "value"
│   ├── Starts with → @beginsWith "prefix"
│   ├── Ends with → @endsWith ".php"
│   └── Contains → @contains "substring"
│
├── Match one of many words/phrases?
│   ├── Small list (2-5 items) → @rx (?:word1|word2|word3)
│   ├── Large list → @pm word1 word2 word3 ...
│   └── From file → @pmf /path/to/words.data
│
├── Match a complex pattern?
│   └── @rx PCRE_PATTERN
│       ├── Use (?i) for case-insensitive
│       └── Use capture for TX:0 (matched value)
│
├── Detect attack fingerprints?
│   ├── SQL Injection → @detectSQLi  (libinjection — no regex needed)
│   └── XSS → @detectXSS            (libinjection — no regex needed)
│
├── Compare numbers?
│   └── @eq / @ne / @gt / @ge / @lt / @le
│
├── Check client IP?
│   ├── Static → @ipMatch 192.168.1.0/24
│   └── From file → @ipMatchFromFile blocked_ips.txt
│
├── Validate encoding/format?
│   ├── URL encoding → @validateUrlEncoding
│   ├── UTF-8 → @validateUtf8Encoding
│   └── Byte range → @validateByteRange 1-255
│
└── Always match / never match?
    ├── @unconditionalMatch  (match always, still sets MATCHED_VAR)
    └── @noMatch             (never match — disable a rule conditionally)
```

**Negation:** Prefix any operator with `!` to invert:

```apache
# Block if method is NOT GET or POST
SecRule REQUEST_METHOD "!@within GET,POST" "id:10,..."
```

---

## 5. Decision Process: Choosing Transformations

**Always start with `t:none`** to clear inherited transforms.

Then ask: *What encoding layers might an attacker use to hide the payload?*

```
Standard URL parameter (ARGS, ARGS_GET, ARGS_POST):
→ Already URL-decoded by ModSecurity
→ t:none, t:lowercase

User Agent, Referer, custom headers:
→ t:none, t:lowercase

URI path (REQUEST_URI, REQUEST_FILENAME):
→ Not auto-decoded
→ t:none, t:urlDecodeUni, t:normalizePath, t:lowercase

Raw request body (REQUEST_BODY):
→ t:none, t:urlDecodeUni, t:lowercase

Any field that may contain HTML encoding:
→ t:none, t:htmlEntityDecode, t:lowercase

Maximum evasion coverage (XSS, SQLi):
→ t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:removeNulls

Shell command detection (RCE):
→ t:none, t:cmdLine
```

**Important ordering rules:**
- Decode before case normalization: `t:urlDecodeUni` before `t:lowercase`
- Always `t:removeNulls` last if used (null bytes break matching)
- Never `t:urlDecode` — always use `t:urlDecodeUni`

---

## 6. Writing the Action Block

### Minimum required
```apache
id:NNNNN,       # Unique ID
phase:2,        # Phase (always numeric)
block,          # Or pass, deny, allow
```

### Standard CRS detection rule pattern
```apache
id:NNNNN,
phase:2,
block,
capture,                    # Optional: store match into TX:0
t:none,t:urlDecodeUni,      # Transform pipeline
msg:'Short description',
logdata:'Matched: %{TX.0} in %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',
tag:'attack-sqli',
tag:'paranoia-level/1',
tag:'OWASP_CRS',
ver:'OWASP_CRS/4.x.x',
severity:'CRITICAL',
setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',
setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'
```

### Choosing severity and score
| What is being detected | Severity | Score variable |
|---|---|---|
| Confirmed attack payload | `CRITICAL` | `tx.critical_anomaly_score` (5) |
| Likely attack, some FP risk | `ERROR` | `tx.error_anomaly_score` (4) |
| Suspicious pattern, moderate FP risk | `WARNING` | `tx.warning_anomaly_score` (3) |
| Anomaly or policy violation | `NOTICE` | `tx.notice_anomaly_score` (2) |

---

## 7. Chain Rule Logic (AND Conditions)

Use `chain` when a single rule would produce too many false positives, but the **combination** of two conditions uniquely identifies an attack.

**Pattern**: Rule A captures a value → Rule B validates the capture

```apache
# Only block if two sides of a comparison are identical (tautology SQLi: 1=1)
SecRule ARGS "@rx (\w+)\s*=\s*(\w+)" \
    "id:942130,phase:2,block,capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Tautology detected',\
    chain"
    SecRule TX:1 "@streq %{TX.2}" \   ← AND: only if group 1 == group 2
        "t:none,\
        setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}'"
```

**Chain rules:**
- Disruptive action, `id`, `phase`, `msg`, `tag`, `skip`, `skipAfter` → **first rule only**
- `setvar`, `capture`, `ctl` → can appear in **any** rule in the chain
- `chain` → on every rule **except the last**

**Multi-level chain** (A AND B AND C):

```apache
SecRule VAR_A "@rx pattern_a" "id:100,phase:2,block,chain"
    SecRule VAR_B "@rx pattern_b" "chain"
        SecRule VAR_C "@rx pattern_c" "setvar:tx.score=+5"
```

---

## 8. Flow Control: skip and skipAfter

### skip — skip a fixed number of rules

```apache
# If client is trusted IP, skip the next rule
SecRule REMOTE_ADDR "@ipMatch 192.168.1.0/24" \
    "id:200,phase:1,pass,nolog,skip:1"

# This rule is skipped for trusted IPs
SecRule ARGS "@rx attack" "id:201,phase:2,block,..."
```

### skipAfter — jump to a named marker

Used extensively in CRS for **paranoia level gating**:

```apache
# Skip entire file content if PL < 2
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" \
    "id:942013,phase:1,pass,nolog,\
    skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"

# ... all PL2 rules ...

SecMarker END-REQUEST-942-APPLICATION-ATTACK-SQLI
```

### Whitelist pattern (allow early, skip detection)

```apache
# Allow known-good path — skip all further checks in this phase
SecRule REQUEST_URI "@beginsWith /health" \
    "id:9000,phase:1,pass,nolog,\
    ctl:ruleEngine=Off,\
    skipAfter:END-CUSTOM-RULES"

# ... attack detection rules ...

SecMarker END-CUSTOM-RULES
```

---

## 9. Per-Transaction Configuration with `ctl`

`ctl` modifies engine behavior **only for the current transaction**, without affecting other requests.

### Disable a rule for a specific path

```apache
# On /api/json, disable rule 942100 to allow JSON payloads
SecRule REQUEST_URI "@beginsWith /api/json" \
    "id:9001,phase:1,pass,nolog,\
    ctl:ruleRemoveById=942100"
```

### Remove a specific variable from a rule's target list

```apache
# Do not scan ARGS:search_query for XSS (too many FP)
SecRule REQUEST_URI "@beginsWith /search" \
    "id:9002,phase:1,pass,nolog,\
    ctl:ruleRemoveTargetById=941100;ARGS:search_query"
```

### Set body parser based on Content-Type

```apache
# Use XML parser for text/xml requests
SecRule REQUEST_HEADERS:Content-Type "@beginsWith text/xml" \
    "id:9003,phase:1,pass,nolog,\
    ctl:requestBodyProcessor=XML"
```

---

## 10. Accumulating State Across Rules

### Using TX for anomaly scoring

```apache
# Rule 1: Detect query param with SQL keyword
SecRule ARGS "@pm select union insert update delete" \
    "id:100,phase:2,pass,nolog,\
    setvar:'tx.sql_keyword_score=+1'"

# Rule 2: Detect SQL comment
SecRule ARGS "@rx /\*.*\*/" \
    "id:101,phase:2,pass,nolog,\
    setvar:'tx.sql_keyword_score=+1'"

# Rule 3: Block if combined score is suspicious
SecRule TX:SQL_KEYWORD_SCORE "@ge 2" \
    "id:102,phase:2,block,\
    msg:'Multiple SQL keywords detected'"
```

### Using IP for rate limiting

```apache
# Initialize IP collection
SecAction "id:200,phase:1,nolog,pass,initcol:ip=%{REMOTE_ADDR}"

# Increment error counter per IP
SecRule RESPONSE_STATUS "^[45]" \
    "id:201,phase:3,pass,nolog,\
    setvar:'ip.error_count=+1',\
    expirevar:'ip.error_count=300'"

# Block if too many errors
SecRule IP:ERROR_COUNT "@ge 10" \
    "id:202,phase:1,deny,\
    msg:'Too many errors from IP %{REMOTE_ADDR}'"
```

---

## 11. Common Rule Patterns

### Pattern 1 — Simple content check
```apache
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)nikto|sqlmap|nessus" \
    "id:1000,phase:1,block,\
    t:none,\
    msg:'Known scanner detected'"
```

### Pattern 2 — Detect and score (anomaly scoring)
```apache
SecRule ARGS "@detectSQLi" \
    "id:1001,phase:2,block,capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQLi via libinjection',\
    logdata:'Matched: %{TX.0}',\
    severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

### Pattern 3 — Whitelist (exception rule)
```apache
# Allow SQL keyword in specific trusted param
SecRule REQUEST_URI "@beginsWith /admin/query" \
    "id:1002,phase:1,pass,nolog,\
    ctl:ruleRemoveTargetById=942100;ARGS:sql_input"
```

### Pattern 4 — Collect and check later
```apache
# Phase 1: flag suspicious UA
SecRule REQUEST_HEADERS:User-Agent "@rx curl|python-requests|libwww" \
    "id:1003,phase:1,pass,nolog,\
    setvar:'tx.suspicious_ua=1'"

# Phase 2: if suspicious UA AND attack pattern → block
SecRule TX:SUSPICIOUS_UA "@eq 1" \
    "id:1004,phase:2,block,\
    msg:'Suspicious UA with attack payload',\
    chain"
    SecRule ARGS "@rx (?i)(union|select|exec)" "t:none,t:lowercase"
```

### Pattern 5 — Validate mandatory headers
```apache
# Block if Host header is absent
SecRule &REQUEST_HEADERS:Host "@eq 0" \
    "id:1005,phase:1,block,\
    msg:'Missing Host header'"

# Block if User-Agent is empty or missing
SecRule &REQUEST_HEADERS:User-Agent "@eq 0" \
    "id:1006,phase:1,block,\
    msg:'Missing User-Agent header'"
```

---

## 12. Logic Decision Summary

| Goal | Approach |
|---|---|
| Detect one attack type with low FP | Single `SecRule` with `@rx` or `@detectSQLi` |
| Reduce FP by requiring two conditions | `chain` (AND logic) |
| Check many keywords efficiently | `@pm` (Aho-Corasick) |
| Decode complex encoding before matching | Transform pipeline (`t:urlDecodeUni,t:htmlEntityDecode,...`) |
| Allow traffic for specific paths or params | `ctl:ruleRemoveById` or `ctl:ruleRemoveTargetById` |
| Apply cumulative detection (CRS style) | `setvar` scores + final evaluation rule |
| Track attacker state across requests | `initcol:ip=...` + IP collection variables |
| Skip rules for trusted sources | `skip:N` or `skipAfter:MARKER` |
| Execute rule only at certain paranoia level | `skipAfter` gating with `TX:DETECTION_PARANOIA_LEVEL` |
