# ModSecurity / CRS Rule Development Guide

This document describes how to write and contribute rules for ModSecurity v3 and the OWASP Core Rule Set (CRS). It combines the CRS official documentation with the extracted ModSecurity reference manuals located in `workflow-plan/docs/`.

---

## 1. Rule Structure

Every `SecRule` is made up of four parts:

```apache
SecRule VARIABLES "OPERATOR" "TRANSFORMATIONS,ACTIONS"
```

| Part | Question answered | Reference |
|---|---|---|
| **Variables** | *Where* to look for data | `docs/variables/reference-variables.md` |
| **Operator** | *When* to trigger a match | `docs/operators/reference-operators.md` |
| **Transformations** | *How* to normalize data before matching | `docs/transforms/reference-transforms.md` |
| **Actions** | *What* to do when the rule matches | `docs/actions/reference-actions.md` |

### Minimum required actions

Every `SecRule` must have:
1. `id` — unique rule identifier
2. `phase` — always use numbers (`phase:2`), never aliases like `phase:request`
3. A disruptive action — `block`, `deny`, `pass`, `allow`, or `drop`. If omitted, the default from `SecDefaultAction` applies.

---

## 2. Processing Phases

ModSecurity processes rules in five phases. Choose the correct phase based on **what data is available**:

| Phase | Number | Available data | Typical use |
|---|---|---|---|
| Request Headers | `1` | Headers only, no body | IP blocking, early header checks |
| Request Body | `2` | Full request including ARGS, body | SQLi, XSS, RCE — most detection rules go here |
| Response Headers | `3` | Response headers | Header policy enforcement |
| Response Body | `4` | Response body (requires `SecResponseBodyAccess On`) | Data leakage detection |
| Logging | `5` | Everything, but cannot block | Post-processing, logging only |

> **Note:** Using the wrong phase means the target variable may not yet be populated, causing false negatives.

See `docs/reference-process.md` for full details.

---

## 3. Variables (Targets)

Variables define *where* ModSecurity looks. Key categories:

**Request input** (phase 2):
- `ARGS` — all GET + POST parameters (collection)
- `ARGS_NAMES` — parameter names only
- `ARGS_GET` / `ARGS_POST` — GET or POST separately
- `REQUEST_BODY` — raw request body
- `REQUEST_COOKIES` / `REQUEST_COOKIES_NAMES`

**Headers** (phase 1):
- `REQUEST_HEADERS` — all request headers (collection)
- `REQUEST_HEADERS:User-Agent` — specific header

**URI** (phase 1+):
- `REQUEST_URI` — full URI including query string
- `REQUEST_FILENAME` — path portion only
- `REQUEST_LINE` — complete first line of request

**Response** (phase 3–4):
- `RESPONSE_HEADERS` — response headers
- `RESPONSE_BODY` — response body

**Transaction state** (all phases):
- `TX` — per-transaction variables (read/write with `setvar`)
- `IP` — per-IP persistent storage
- `SESSION` — per-session persistent storage

**Collection modifiers:**
```apache
# Pipe: check multiple targets in one rule
REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*

# Colon: address a specific key in a collection
REQUEST_HEADERS:Content-Type

# Exclamation: exclude a key from a collection
ARGS|!ARGS:password

# Ampersand: count elements instead of inspecting values
&ARGS  # number of arguments
```

See `docs/variables/reference-variables.md` for the full list.

---

## 4. Operators

Operators define *when* a rule triggers.

### String / Pattern operators

| Operator | Description |
|---|---|
| `@rx PATTERN` | PCRE regex (always specify explicitly, never implicit) |
| `@pm word1 word2 ...` | Aho-Corasick multi-string match (very fast) |
| `@pmf FILE` | Multi-string match from a `.data` file |
| `@beginsWith STR` | String starts with |
| `@contains STR` | String contains |
| `@endsWith STR` | String ends with |
| `@streq STR` | Exact string equality |

### Numeric operators

| Operator | Description |
|---|---|
| `@eq N` | Equal to N |
| `@gt N` | Greater than N |
| `@ge N` | Greater than or equal |
| `@lt N` | Less than |
| `@le N` | Less than or equal |

### Detection operators (libinjection)

| Operator | Description |
|---|---|
| `@detectSQLi` | SQLi detection using libinjection — no regex needed |
| `@detectXSS` | XSS detection using libinjection |

### Validation operators

| Operator | Description |
|---|---|
| `@validateByteRange RANGE` | Check bytes are in allowed ranges |
| `@validateUrlEncoding` | Validate URL encoding |
| `@validateUtf8Encoding` | Validate UTF-8 encoding |

**Negation:** prefix any operator with `!` to negate:
```apache
SecRule REQUEST_FILENAME "!@beginsWith /api/" ...
```

See `docs/operators/reference-operators.md` for the full list.

---

## 5. Transformations

Transformations **normalize** data before matching to counter evasion. The input variable is never modified; ModSecurity operates on a copy.

### Core rule: always start with `t:none`

```apache
t:none,t:urlDecodeUni,t:lowercase
```

`t:none` clears any inherited transforms from `SecDefaultAction`.

### Standard decode pipeline (in order)

```apache
t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls
```

> **Never** use `t:urlDecode` — always use `t:urlDecodeUni` to handle Unicode correctly.

### Common transformations

| Transform | Purpose |
|---|---|
| `lowercase` | Normalize case |
| `urlDecodeUni` | Decode URL encoding (handles Unicode) |
| `htmlEntityDecode` | Decode `&lt;`, `&#60;`, etc. |
| `jsDecode` | Decode JS escape sequences `\uXXXX` |
| `removeNulls` | Remove null bytes |
| `removeWhitespace` | Collapse whitespace (detect `<scr ipt>`) |
| `compressWhitespace` | Normalize multiple spaces to one |
| `replaceComments` | Replace `/* ... */` with a space |
| `normalizePath` | Resolve `../` |
| `base64Decode` | Decode base64 |
| `cmdLine` | Unix/Windows shell command normalization |

See `docs/transforms/reference-transforms.md` for the full list.

---

## 6. Actions

Actions define *what* to do when a rule matches.

### Required action order (CRS convention)

```
id
phase
allow | block | deny | drop | pass | redirect
status
capture
t:xxx
log / nolog
auditlog / noauditlog
msg
logdata
tag
ctl
ver
severity
multiMatch
initcol
setenv
setvar
expirevar
chain
skip / skipAfter
```

### Key actions

**Disruptive:**
- `block` — use the action from `SecDefaultAction` (preferred in CRS)
- `deny` — immediately reject with HTTP error
- `pass` — continue processing (no block; used in detection-only rules)
- `allow` — short-circuit all further rules

**Non-disruptive:**
- `capture` — store regex captures into `TX:0` through `TX:9`
- `setvar:tx.score=+5` — set or modify a TX variable
- `expirevar:ip.blocked=300` — expire an IP variable after 300 seconds
- `initcol:ip=%{REMOTE_ADDR}` — initialize a persistent IP collection
- `ctl:ruleEngine=Off` — modify engine settings per-transaction
- `ctl:ruleRemoveById=942100` — disable a rule for this transaction
- `ctl:ruleRemoveTargetByTag=xss-perf-disable;REQUEST_FILENAME` — remove a target from tagged rules

**Metadata:**
- `id:942100` — unique rule ID
- `phase:2` — execution phase
- `msg:'Description'` — logged alert message
- `logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}'` — detail in log
- `tag:'attack-sqli'` — classification tag
- `ver:'OWASP_CRS/4.0.0'` — rule set version
- `severity:'CRITICAL'` — severity level (CRITICAL / ERROR / WARNING / NOTICE)
- `rev:'1'` — rule revision

**Flow:**
- `chain` — AND the next rule; only triggers if this rule matches
- `skip:2` — skip the next 2 rules
- `skipAfter:MARKER_NAME` — jump to a `SecMarker`
- `multiMatch` — run the operator against each value in a collection independently

### Macro expansion in actions

```apache
msg:'Attack from %{REMOTE_ADDR}'             # server variable
logdata:'Found: %{TX.0} in %{MATCHED_VAR_NAME}'  # TX captures
setvar:'tx.msg=%{rule.msg}'                  # rule metadata
```

See `docs/actions/reference-actions.md` for the full list.  
Not supported in v3: see `docs/actions/not-supported-actions.md`.

---

## 7. Naming and Variable Conventions

```apache
# Variable definition — lowercase collection, dot separator
setvar:tx.foo_bar_variable=1

# Variable use — UPPERCASE collection, colon separator
SecRule TX:FOO_BAR_VARIABLE "@eq 1" ...
```

Variable names: lowercase letters `a-z`, digits `0-9`, underscores only.

---

## 8. Anomaly Scoring Pattern (CRS)

CRS rules **do not block directly**. Each detection rule **accumulates a score**:

```apache
# Each detection rule: add to score, do not block
setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}'
setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'
```

A final evaluation rule in `REQUEST-949-BLOCKING-EVALUATION.conf` (phase 2) blocks if the total score exceeds the threshold:

```apache
SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}" \
    "id:949110,phase:2,deny,\
    msg:'Inbound Anomaly Score Exceeded (Total: %{TX.BLOCKING_INBOUND_ANOMALY_SCORE})'"
```

**Severity → score mapping** (from `REQUEST-901-INITIALIZATION.conf`):

| Severity | TX variable | Typical value |
|---|---|---|
| `CRITICAL` | `tx.critical_anomaly_score` | 5 |
| `ERROR` | `tx.error_anomaly_score` | 4 |
| `WARNING` | `tx.warning_anomaly_score` | 3 |
| `NOTICE` | `tx.notice_anomaly_score` | 2 |

---

## 9. Paranoia Levels

Rules are organized into levels 1–4. Higher levels detect more attacks but produce more false positives.

| PL | Characteristics |
|---|---|
| **1** (default) | Low FP rate; confirmed matches only; atomic single rules |
| **2** | Chain rules allowed; low FP rate; critical or scoring rules |
| **3** | More complex chain rules; moderate FP rate |
| **4** | Maximum coverage; higher FP rate; checks everything |

**Within each file**, paranoia-level gating uses `skipAfter`:

```apache
# Skip all rules if PL < 1 (at top of file)
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" \
    "id:942011,phase:1,pass,nolog,skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"

# Skip PL2+ rules if PL < 2
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" \
    "id:942013,phase:1,pass,nolog,skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"
```

Each rule must carry `tag:'paranoia-level/N'` (unless using `nolog`).

---

## 10. Rule ID Assignment

CRS occupies ID ranges:
- **900,000 – 949,999**: inbound request rules
- **950,000 – 999,999**: outbound response rules
- **9,000,000 – 9,999,999**: exclusion packages and plugins

Within each vulnerability group (e.g., 942xxx for SQLi):
- `9xx000 – 9xx099`: control flow rules (skip/paranoia gating, IDs 9xx011–9xx018 reserved)
- `9xx100, 9xx110, 9xx120, ...`: detection rules, **step of 10**
- `9xx101, 9xx161`: stricter siblings of base rules

**Rules are always added at the end of their group.** Never insert between existing IDs.

---

## 11. Metadata and Tags

CRS rules carry standardized metadata tags:

```apache
tag:'application-multi'        # or: application-php, application-nodejs
tag:'language-multi'           # or: language-java, language-php
tag:'platform-multi'           # or: platform-windows, platform-mysql
tag:'attack-sqli'              # attack category
tag:'paranoia-level/1'         # PL (required if logging)
tag:'OWASP_CRS'                # always required
tag:'OWASP_CRS/ATTACK-SQLI'   # legacy CRS v2 tag
tag:'capec/1000/152/248/66'    # CAPEC attack classification
ver:'OWASP_CRS/4.25.0-dev'    # rule set version string
```

---

## 12. Chain Rules

Chain rules implement **logical AND**: all chained rules must match for the disruptive action to fire.

```apache
SecRule ARGS "@rx (?i)\b(\w+)\b.*?=.*?\b(\w+)\b" \
    "id:942130,phase:2,block,capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Boolean-based attack detected',\
    tag:'paranoia-level/2',\
    setvar:'tx.match=%{matched_var_name}',\
    chain"
    SecRule TX:1 "@streq %{TX.2}" \      ← AND: only block if TX:1 equals TX:2
        "t:none,\
        setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}'"
```

**Rules for chains:**
- Disruptive actions, `phase`, `id`, `msg`, `tag`, `skip`, `skipAfter` → **chain starter only**
- Non-disruptive actions (`setvar`, `ctl`, `capture`) → **allowed in any rule in the chain**
- `chain` action → never in the last rule of the chain

---

## 13. Regex Best Practices

### Forbidden patterns (non-RE2 compatible — not allowed in CRS)

```
(?=...)     positive lookahead
(?!...)     negative lookahead
(?<=...)    positive lookbehind
(?<!...)    negative lookbehind
(?P<name>)  named capture groups
\1          backreferences
(?:x)++     possessive quantifiers
(?>x)       atomic groups
```

### Required conventions

| Rule | Detail |
|---|---|
| Always use `@rx` explicitly | Never omit the operator (no implicit `@rx`) |
| Backslash → `\x5c` | Never use `[\\\\]` (not portable) |
| Forward slash → `/` | Do not escape forward slashes |
| Vertical tab → `\x0b` | Do not use `\v` |
| Non-capturing groups | Use `(?:...)` instead of `(...)` unless capture is needed |
| Anchors `^` and `$` | Use only when the entire input must be matched |
| Lazy `.*?` | Use carefully — can be slower than greedy versions |
| `(?i)` flag | Use for case-insensitive rules instead of `t:lowercase` in regex |
| Character class for alphanumeric | `[a-zA-Z0-9_-]` (in this order) |

---

## 14. Complex Regex: Using `.ra` Files and crs-toolchain

For rules using `@rx` with complex patterns, the regex is maintained in a separate `.ra` (regex-assembly) file:

```
regex-assembly/942170.ra   →   crs-toolchain regex update 942170   →   rules/REQUEST-942*.conf
```

### `.ra` file format

```
##! comment (ignored)

##!+ i                          # add (?i) flag
##!^ \b                         # global prefix
##!$ \W*\(                      # global suffix

##!> define WS [\s\x0b]+        # define a reusable expression
##!> define SEL_OR_END (?:select|;){{WS}}

##!> assemble                   # assemble alternations
  {{SEL_OR_END}}benchmark
  {{SEL_OR_END}}sleep
  ##!=>                         # concat with next block
  \s*?\(\s*?\w+
##!<
```

### Processor types

| Directive | Purpose |
|---|---|
| `##!> assemble` | Merge multiple lines into one alternation (`\|`) |
| `##!> define NAME value` | Define a reusable substitution `{{NAME}}` |
| `##!> cmdline unix\|windows` | Evasion-aware command word processing |
| `##!> include FILE` | Include another `.ra` file |
| `##!> include-except BASE EXCLUDE` | Include with lines from EXCLUDE removed |
| `##!=< id` | Store current block result under `id` |
| `##!=> id` | Insert previously stored block `id` |
| `'literal` | (in cmdline) treat as literal pattern, no escaping |
| `word@` | (in cmdline) allow shell separators after word |
| `word~` | (in cmdline) forbid whitespace immediately after word |

### Toolchain workflow

```bash
# 1. Edit the .ra file
vim regex-assembly/942170.ra

# 2. Check formatting rules
crs-toolchain regex format 942170

# 3. Preview the assembled regex
crs-toolchain regex generate 942170

# 4. Compare with current rule file
crs-toolchain regex compare 942170

# 5. Update the rule file
crs-toolchain regex update 942170

# 6. Batch update all
crs-toolchain regex update --all
```

Comment in the `.conf` file must be added to indicate the `.ra` source:

```apache
# Regular expression generated from regex-assembly/942170.ra.
# To update the regular expression run the following shell script:
#   crs-toolchain regex update 942170
```

---

## 15. Writing Tests

Every rule must have at least one regression test. Tests are YAML files under `tests/regression/tests/<FILE-GROUP>/<RULE-ID>.yaml`.

### Positive test (rule should match)

```yaml
- test_id: 1
  desc: "SQL injection via UNION SELECT"
  stages:
    - input:
        dest_addr: "127.0.0.1"
        port: 80
        method: POST
        uri: "/"
        headers:
          Host: localhost
          User-Agent: "OWASP CRS test agent"
          Accept: "text/html"
        data: "id=1 UNION SELECT username,password FROM users"
        version: HTTP/1.1
      output:
        log:
          expect_ids: [942270]   # rule 942270 must fire
```

### Negative test (rule must NOT match legitimate traffic)

```yaml
- test_id: 4
  desc: "Normal POST data should not trigger"
  stages:
    - input:
        dest_addr: "127.0.0.1"
        port: 80
        method: POST
        headers:
          User-Agent: "OWASP CRS test agent"
          Host: "localhost"
          Accept: "text/html"
        data: "name=ping pong table&color=red"
        uri: "/"
      output:
        log:
          no_expect_ids: [942270]  # rule 942270 must NOT fire
```

### Running tests with go-ftw

```bash
# Start Docker test environment
docker compose -f tests/docker-compose.yml up -d modsec2-apache

# Run full test suite
./go-ftw run --config .ftw.apache.yaml -d tests/regression/tests/

# Run single rule test
./go-ftw run --config .ftw.apache.yaml -d tests/regression/tests/ -i "942270"

# Debug output
./go-ftw run --config .ftw.apache.yaml -d tests/regression/tests/ -i "942270-1$" --trace
```

Renumber tests after adding or removing cases:

```bash
crs-toolchain util renumber-tests
```

---

## 16. Complete Rule Template

The following is a template for a typical CRS detection rule:

```apache
# -----------------------------------------------------------------------
# -=[ Attack Description ]=-
#
# Brief description of what attack this rule detects.
#
# References:
# - https://example.com/reference
#
# If rule uses a .ra file:
# Regular expression generated from regex-assembly/9XXXXX.ra.
# To update the regular expression run the following shell script
#   crs-toolchain regex update 9XXXXX
#
SecRule VARIABLES "@rx PATTERN" \     # or @detectSQLi / @pm / @pmf
    "id:9XXXXX,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Short description of attack',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-TYPE',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-TYPE',\
    tag:'capec/...',\
    ver:'OWASP_CRS/4.25.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.TYPE_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

---

## 17. What NOT to Do

| Prohibited | Reason |
|---|---|
| `ctl:auditLogParts=+E` | CRS must not change audit log format |
| Implicit `@rx` (no operator) | Always write operator explicitly |
| Lookahead/lookbehind in regex | Not RE2 compatible |
| Possessive quantifiers `++` | Not RE2 compatible |
| Backreferences `\1` | Not RE2 compatible |
| `t:urlDecode` | Use `t:urlDecodeUni` instead |
| `[\\\\]` for backslash | Use `\x5c` instead |
| Inserting rule ID between existing IDs | Always add at end of group |
| `phase:request` (name alias) | Always use numeric: `phase:2` |
| Tabs for indentation | Use 4 spaces |
| Trailing whitespace | Remove before commit |
| Actions not in double quotes | Always quote action list |

Not-supported actions in v3: see `docs/actions/not-supported-actions.md`.  
Not-supported directives in v3: see `docs/directives/not-supported-directives.md`.

---

## Reference Files

| Topic | File |
|---|---|
| Processing phases | `docs/reference-process.md` |
| Variables / Targets | `docs/variables/reference-variables.md` |
| Operators | `docs/operators/reference-operators.md` |
| Transformations | `docs/transforms/reference-transforms.md` |
| Transformation categories | `docs/transforms/transforms_category.md` |
| Actions | `docs/actions/reference-actions.md` |
| Actions not supported in v3 | `docs/actions/not-supported-actions.md` |
| Configuration directives | `docs/directives/reference-config-directives.md` |
| Non-rule directives (logging, debug) | `docs/directives/non-rule-directives.md` |
| Directives not supported in v3 | `docs/directives/not-supported-directives.md` |
