# Core Knowledge Base for Generic Rule Design

This document consolidates the core rule-design knowledge needed by the generic `RuleDesigner` node.

It is derived from:

- `../../plan/about-modSec-and-CRS/rule-writing-logic.md`
- `../../plan/about-modSec-and-CRS/flow-fundamentals.md`
- `../../plan/docs/reference-process.md`
- `../../plan/docs/metadata/required-metadata.md`

The goal is to preserve the essential reasoning and reference points while removing overlap between the source documents.

## 1. What a Rule Is

A `SecRule` is built from four parts:

```apache
SecRule VARIABLES "OPERATOR" "TRANSFORMATIONS,ACTIONS"
```

These parts answer four questions:

| Part | Question |
|---|---|
| Variables | Where to look |
| Operator | When to match |
| Transformations | How to normalize the input |
| Actions | What to do on match |

Core rule-writing constraints:

1. Every rule must target data through a variable.
2. Every rule must have an operator. If omitted, ModSecurity implies `@rx`.
3. Every rule must have an action list, whether explicit or inherited.
4. Every rule must run in a phase.
5. If no disruptive action is specified, the default disruptive action applies.

For CRS-style rules, write operators explicitly and use numeric phase values.

## 2. Request Processing and Phases

ModSecurity inspects traffic in five phases:

| Phase | Number | Typical use |
|---|---|---|
| Request headers | `1` | Method, URI, header checks, request-body parser selection |
| Request body | `2` | Request parameters and body inspection |
| Response headers | `3` | Response status and response header inspection |
| Response body | `4` | Response content inspection |
| Logging | `5` | Logging-only logic; too late to block |

Important execution rules:

- Rules execute phase by phase.
- Rule order matters only within the same phase.
- Later phases have cumulative access to transaction data.
- `skip` and `skipAfter` only affect rules in the current phase.
- The logging phase still runs even if the transaction was previously intercepted.

Operational notes:

- To inspect request bodies, enable `SecRequestBodyAccess On`.
- To inspect response bodies, enable `SecResponseBodyAccess On`.

## 3. Start With Phase, Then Choose Data

Choose the phase first, then choose the variable that matches the data available there.

### Request-side variables

| Need | Variable |
|---|---|
| All request parameters | `ARGS` |
| Query string parameters only | `ARGS_GET` |
| Request body parameters only | `ARGS_POST` |
| Parameter names | `ARGS_NAMES`, `ARGS_GET_NAMES`, `ARGS_POST_NAMES` |
| All request headers | `REQUEST_HEADERS` |
| One request header | `REQUEST_HEADERS:Header-Name` |
| Cookie values | `REQUEST_COOKIES` |
| Cookie names | `REQUEST_COOKIES_NAMES` |
| Full URI including query string | `REQUEST_URI` |
| Path only | `REQUEST_FILENAME` |
| Request line | `REQUEST_LINE` |
| Raw request body | `REQUEST_BODY` |
| Uploaded file names | `FILES` |
| Uploaded temporary file paths | `FILES_TMPNAMES` |

### Response-side variables

| Need | Variable |
|---|---|
| Response status | `RESPONSE_STATUS` |
| Response headers | `RESPONSE_HEADERS` |
| Response body | `RESPONSE_BODY` |

### State and context variables

| Need | Variable |
|---|---|
| Per-transaction state | `TX` |
| Per-IP state | `IP` |
| Per-session state | `SESSION` |
| Per-user state | `USER` |
| Current rule metadata | `RULE` |
| Current match data | `MATCHED_VAR`, `MATCHED_VAR_NAME`, `MATCHED_VARS` |

## 4. Collections and Target Selection

Collections change how a rule executes because ModSecurity iterates over members.

Common collection targeting patterns:

| Operation | Syntax | Meaning |
|---|---|---|
| Entire collection | `ARGS` | Inspect all members |
| Specific key | `ARGS:name` | Inspect one member |
| Regex-selected keys | `ARGS:/^id_/` | Inspect members whose key matches the regex |
| Exclusion | `ARGS|!ARGS:password` | Inspect the collection except one member |

To count collection members instead of inspecting values, use `&`:

```apache
SecRule &ARGS "@gt 20" "id:5,phase:2,deny"
```

## 5. Choose an Operator by Match Semantics

Choose the operator based on the comparison you actually need:

### Simple string matching

- `@streq`
- `@beginsWith`
- `@endsWith`
- `@contains`
- `@containsWord`
- `@within`

### Pattern and keyword matching

- `@rx`
- `@rxGlobal`
- `@pm`
- `@pmFromFile` / `@pmf`

When matching many keywords, `@pm` is usually preferable to a large regex.

### Numeric comparison

- `@eq`
- `@gt`
- `@ge`
- `@lt`
- `@le`

### Specialized detection and validation

- `@detectSQLi`
- `@detectXSS`
- `@validateUrlEncoding`
- `@validateUtf8Encoding`
- `@validateByteRange`
- `@ipMatch` / `@ipMatchFromFile`
- `@geoLookup`
- `@validateSchema`
- `@validateDTD`

Any operator may be negated with `!`.

## 6. Transformations: Use Only What the Rule Needs

Transformations are applied to a copy of the input before the operator runs. Order matters.

Core conventions:

1. Start rule-local transform lists with `t:none`.
2. Prefer explicit rule-local transforms over inherited transforms.
3. Prefer `t:urlDecodeUni` over `t:urlDecode`.
4. Add only the transforms that the detection logic actually needs.

Example:

```apache
SecRule ARGS "@rx attack" \
    "id:20,phase:2,t:none,t:urlDecodeUni,t:lowercase,deny"
```

Interpretation:

- `t:none` clears inherited transforms
- later transforms are applied in the order written
- unnecessary transforms increase ambiguity and false positive risk

## 7. Actions and Rule Flow

For rule logic, actions matter in several different ways:

- disruptive actions decide what happens to the transaction
- non-disruptive actions record state or cause side effects
- flow actions control which rules execute next
- metadata actions describe and classify the rule

### Common disruptive actions

- `block`
- `deny`
- `pass`
- `allow`
- `drop`
- `redirect`

For CRS-style rules, `block` is preferred because it delegates behavior to `SecDefaultAction`.

### Common metadata actions

- `id`
- `phase`
- `msg`
- `logdata`
- `tag`
- `severity`
- `ver`
- `rev`

### Common non-disruptive actions used in rule logic

- `capture`
- `setvar`
- `expirevar`
- `initcol`
- `setenv`
- `ctl`
- `multiMatch`

## 8. Chain Means Logical AND

`chain` is the core way to represent logical AND across adjacent rules.

```apache
SecRule REQUEST_METHOD "^POST$" "phase:1,chain,t:none,id:30"
    SecRule &REQUEST_HEADERS:Content-Length "@eq 0" "t:none"
```

Important chain rules:

- the disruptive action fires only if the whole chain matches
- disruptive actions and metadata actions belong in the chain starter
- non-disruptive actions may appear in any chain step
- `setvar` in an early chain step executes when that step matches, not only when the full chain matches

CRS conventions:

- use 4-space indentation for chained rules
- do not place comments between chained rules

## 9. Flow Control Beyond Chain

Two major flow-control actions are:

- `skip`
- `skipAfter`

`skip` skips a fixed number of rules.

`skipAfter` jumps to the next rule after a named `SecMarker`.

Both operate only inside the current phase, so phase choice must be correct before relying on them.

## 10. Transaction-Specific Behavior and State

### `ctl`

`ctl` changes configuration for the current transaction only.

Typical uses:

- switch request-body parsing
- disable another rule for one transaction
- remove one target from another rule
- change rule-engine or audit behavior for the current transaction

Because some `ctl` sub-options are unsupported in v3, the action and unsupported-action references should be checked before use.

### `setvar`

`setvar` creates, updates, or deletes variables and is the basis of both rule-to-rule state and anomaly scoring.

It supports:

- setting flags
- initializing counters
- incrementing or decrementing scores
- removing variables
- carrying state through `TX`
- carrying state across requests with persistent collections such as `IP`, `SESSION`, and `USER`

## 11. CRS Detection Model: Anomaly Scoring and Paranoia Levels

CRS is built around anomaly scoring rather than immediate blocking.

High-level flow:

1. Execute request rules.
2. Compare inbound anomaly score to the inbound threshold.
3. Execute response rules.
4. Compare outbound anomaly score to the outbound threshold.

Key CRS files:

- `REQUEST-949-BLOCKING-EVALUATION.conf`
- `RESPONSE-959-BLOCKING-EVALUATION.conf`

Default thresholds emphasized in the source documents:

- inbound threshold: `5`
- outbound threshold: `4`

Paranoia level and anomaly threshold are different concepts:

- paranoia level controls how many rules run
- anomaly threshold controls how many matches are needed before blocking

Higher executing paranoia levels may be used for observation and tuning even when blocking behavior is governed by a different active level.

## 12. Required CRS Metadata

Every CRS rule, or the first rule in a chain, should include these core metadata fields:

- `id`
- `phase`
- `msg`
- `logdata`
- `severity`

### Required tag groups

#### Context tags

- `tag:'application-*'`
- `tag:'language-*'`
- `tag:'platform-*'`

#### Attack tags

- broad category: `tag:'attack-*'`
- specific technique: `tag:'attack-*/*'`

#### Structural tags

- `tag:'paranoia-level/x'`
- `tag:'OWASP_CRS'`

## 13. Severity and Scoring

`severity` is not only a display label. It maps directly to anomaly-scoring variables used by `setvar`.

| Severity | Score variable | Default score |
|---|---|---|
| `CRITICAL` | `%{tx.critical_anomaly_score}` | `5` |
| `ERROR` | `%{tx.error_anomaly_score}` | `4` |
| `WARNING` | `%{tx.warning_anomaly_score}` | `3` |
| `NOTICE` | `%{tx.notice_anomaly_score}` | `2` |

Typical CRS scoring pattern:

```apache
SecRule ARGS "@detectSQLi" \
    "id:942100,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Injection detected',\
    logdata:'Matched Data: %{TX.0}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'attack-sqli/boolean-based',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    severity:'CRITICAL',\
    setvar:'tx.sqli_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## 14. Source-Grounded Rule-Writing Sequence

Use this sequence when designing a rule:

1. Decide which phase contains the data you need.
2. Choose the variable that corresponds to that data.
3. Decide whether the target is a single value or a collection.
4. Choose the operator that matches the comparison semantics.
5. Add only the needed transformations, usually starting with `t:none`.
6. Choose actions:
   - metadata
   - disruptive action
   - non-disruptive actions
7. If one condition is insufficient, use `chain`.
8. If execution flow must jump over rules, use `skip` or `skipAfter`.
9. If behavior must change only for this transaction, use `ctl`.
10. If state must persist across rules or requests, use `setvar` with the proper collection.

