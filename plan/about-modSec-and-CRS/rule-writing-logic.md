# ModSecurity Rule Processing and Writing Logic

This document focuses on **rule logic** using only concepts and behaviors that are documented in the extracted CRS documentation and the ModSecurity v3 reference manual. For full reference details, use the files under `workflow-plan/docs/`.

---

## 1. What a Rule Is

The CRS documentation describes a `SecRule` as having four parts:

```apache
SecRule VARIABLES "OPERATOR" "TRANSFORMATIONS,ACTIONS"
```

These four parts answer four questions:

| Part | Question |
|---|---|
| Variables | Where to look |
| Operator | When to match |
| Transformations | How to normalize the input |
| Actions | What to do on match |

The same source also states these basic points:

1. Every `SecRule` must have a variable target.
2. Every `SecRule` must have an operator. If omitted, ModSecurity implies `@rx`.
3. Every `SecRule` must have an action list, whether explicit or inherited via `SecDefaultAction`.
4. Every `SecRule` must run in a phase, whether explicit or inherited.
5. If no disruptive action is specified, the default disruptive action applies.

In CRS contributions, operators should always be written explicitly, and phase numbers should be written as numbers rather than aliases.

---

## 2. Processing Logic: Start With Phase

The ModSecurity v3 manual defines five phases:

| Phase | Number | What is available |
|---|---|---|
| Request headers | `1` | Request line, URI, headers; request body not yet read |
| Request body | `2` | Request arguments and body content after buffering/parsing |
| Response headers | `3` | Response headers |
| Response body | `4` | Response body, if buffered |
| Logging | `5` | Logging stage only; too late to block |

The manual emphasizes two logic constraints:

- Rules are executed **phase by phase**.
- The order of rules in the configuration file matters **only within the same phase**.

It also states that choosing the wrong phase can silently miss data because the target variable may not yet be populated.

Practical reading:

- If you need to inspect request headers or decide how to parse the body, start from **phase 1**.
- If you need request arguments or request body content, start from **phase 2**.
- If you need response status or response headers, start from **phase 3**.
- If you need response body text, start from **phase 4** and `SecResponseBodyAccess On`.

---

## 3. After Phase, Choose the Data Source

The CRS "Making Rules" page and the ModSecurity manual both describe variables as the place where ModSecurity looks for data.

### Request-side logic

| Need | Variable |
|---|---|
| All request parameters | `ARGS` |
| Query string parameters only | `ARGS_GET` |
| Request body parameters only | `ARGS_POST` |
| Parameter names only | `ARGS_NAMES` / `ARGS_GET_NAMES` / `ARGS_POST_NAMES` |
| All request headers | `REQUEST_HEADERS` |
| One request header | `REQUEST_HEADERS:Header-Name` |
| All cookie values | `REQUEST_COOKIES` |
| All cookie names | `REQUEST_COOKIES_NAMES` |
| Full URI including query string | `REQUEST_URI` |
| Path only | `REQUEST_FILENAME` |
| Request line | `REQUEST_LINE` |
| Raw request body | `REQUEST_BODY` |
| Uploaded file names | `FILES` |
| Uploaded temporary file paths | `FILES_TMPNAMES` |

### Response-side logic

| Need | Variable |
|---|---|
| Response status | `RESPONSE_STATUS` |
| Response headers | `RESPONSE_HEADERS` |
| Response body | `RESPONSE_BODY` |

### Transaction and persistent state

| Need | Variable |
|---|---|
| Per-transaction state | `TX` |
| Per-IP state | `IP` |
| Per-session state | `SESSION` |
| Per-user state | `USER` |
| Current rule metadata | `RULE` |
| Current match result | `MATCHED_VAR`, `MATCHED_VAR_NAME`, `MATCHED_VARS` |

---

## 4. Collections Change How Rules Execute

The CRS "Making Rules" page explains that some variables are **collections**. When a collection is targeted, ModSecurity iterates over its members until it finds a match.

Examples from the manual:

```apache
SecRule ARGS "@rx attack" "id:1,phase:2,deny"
SecRule ARGS:username "@contains admin" "id:2,phase:2,deny"
SecRule ARGS|!ARGS:password "@rx admin" "id:3,phase:2,deny"
SecRule ARGS:/^id_/ "@rx attack" "id:4,phase:2,deny"
```

This yields four important logic tools:

| Operation | Syntax | Meaning |
|---|---|---|
| Entire collection | `ARGS` | Inspect all members |
| Specific key | `ARGS:name` | Inspect one member |
| Regex-selected keys | `ARGS:/^id_/` | Inspect members whose key matches the regex |
| Exclusion | `ARGS|!ARGS:password` | Inspect the collection except one member |

To count collection members instead of inspecting their values, the manual defines the `&` prefix:

```apache
SecRule &ARGS "@gt 20" "id:5,phase:2,deny"
```

---

## 5. Choose an Operator by Match Semantics

The operator should follow the kind of comparison you need to make.

### Exact or simple string matching

| Need | Operator |
|---|---|
| Exact equality | `@streq` |
| Starts with | `@beginsWith` |
| Ends with | `@endsWith` |
| Contains substring | `@contains` |
| Contains whole word | `@containsWord` |
| Check whether input is within a provided set/string | `@within` |

### Pattern and phrase matching

| Need | Operator |
|---|---|
| Regular expression | `@rx` |
| Global regular expression matching | `@rxGlobal` |
| Phrase list in rule | `@pm` |
| Phrase list from file | `@pmFromFile` / `@pmf` |

The manual explicitly notes that `@pm` performs much better than a regular expression when matching a large number of keywords.

### Numeric comparison

| Need | Operator |
|---|---|
| Equal | `@eq` |
| Greater than | `@gt` |
| Greater than or equal | `@ge` |
| Less than | `@lt` |
| Less than or equal | `@le` |

### Specialized detection and validation

| Need | Operator |
|---|---|
| SQLi fingerprint detection | `@detectSQLi` |
| XSS fingerprint detection | `@detectXSS` |
| URL encoding validation | `@validateUrlEncoding` |
| UTF-8 validation | `@validateUtf8Encoding` |
| Byte range validation | `@validateByteRange` |
| IP/network matching | `@ipMatch` / `@ipMatchFromFile` |
| Geolocation lookup | `@geoLookup` |
| XML schema/DTD validation | `@validateSchema`, `@validateDTD` |

Any operator may be negated with `!`:

```apache
SecRule REQUEST_METHOD "!@within GET,POST,HEAD" "id:10,phase:1,deny"
```

---

## 6. Transformations: Use Only What the Rule Needs

The manual defines transformations as operations applied to a **copy** of the input before the operator runs. It also states that the order of transformations matters.

The CRS contribution guidance and rule development guidance add three important conventions:

1. Start rule-local transform lists with `t:none`.
2. Write transformations explicitly in the rule rather than relying on inherited transforms.
3. Prefer `t:urlDecodeUni` over `t:urlDecode`.

Example:

```apache
SecRule ARGS "@rx attack" \
    "id:20,phase:2,t:none,t:urlDecodeUni,t:lowercase,deny"
```

The logic here is:

- use `t:none` to clear inherited transforms;
- add only the transforms needed for the target data and the attack pattern;
- keep their order intentional, because ModSecurity applies them in the order written.

---

## 7. Actions Control Rule Flow

The manual groups actions into disruptive, non-disruptive, flow, metadata, and data actions. For rule logic, the most important distinction is:

- **disruptive actions** decide what happens to the transaction;
- **non-disruptive actions** record state or side effects;
- **flow actions** affect which rules execute next.

### Disruptive actions

Common disruptive actions:

- `block`
- `deny`
- `pass`
- `allow`
- `drop`
- `redirect`

In CRS, `block` is preferred because it uses the policy defined by `SecDefaultAction`.

### Metadata actions

Key metadata actions:

- `id`
- `phase`
- `msg`
- `logdata`
- `tag`
- `severity`
- `ver`
- `rev`

### Non-disruptive actions often used in rule logic

- `capture`
- `setvar`
- `expirevar`
- `initcol`
- `setenv`
- `ctl`
- `multiMatch`

---

## 8. Chain Means Logical AND

The manual explicitly states that `chain` allows rules to simulate logical AND.

```apache
SecRule REQUEST_METHOD "^POST$" "phase:1,chain,t:none,id:30"
    SecRule &REQUEST_HEADERS:Content-Length "@eq 0" "t:none"
```

Documented chain logic:

- the disruptive action fires only if the **entire chain** matches;
- disruptive actions, `phase`, `id`, `msg`, `tag`, `severity`, `logdata`, `skip`, and `skipAfter` may appear only in the **chain starter**;
- non-disruptive actions may appear in any rule in the chain.

The manual also gives one important consequence for stateful logic:

- `setvar` inside an early chain step executes when **that individual step** matches, not only when the full chain matches.
- If the variable should change only when the full chain matches, place `setvar` in the **last** chained rule.

CRS contribution guidelines also require:

- 4-space indentation for chained rules;
- no comments between chained rules.

---

## 9. skip and skipAfter Change Which Rules Run Next

The manual defines two main flow-control actions:

### `skip`

Skips a fixed number of rules:

```apache
SecRule REMOTE_ADDR "^127\.0\.0\.1$" "phase:1,skip:1,id:40"
SecRule &REQUEST_HEADERS:Accept "@eq 0" "phase:1,id:41,deny"
```

### `skipAfter`

Jumps forward to the next rule after a marker:

```apache
SecRule REMOTE_ADDR "^127\.0\.0\.1$" "phase:1,id:42,skipAfter:IGNORE_LOCALHOST"
SecRule &REQUEST_HEADERS:Accept "@eq 0" "phase:1,deny,id:43"
SecMarker "IGNORE_LOCALHOST"
```

The manual explicitly states:

- `skip` and `skipAfter` work only within the **current phase**;
- they do not skip rules from later phases.

This is why phase selection must be decided first before relying on flow control.

---

## 10. `ctl` Changes Behavior for the Current Transaction

The manual defines `ctl` as a per-transaction configuration change. It does not change global configuration or parallel transactions.

Examples documented in the manual:

```apache
SecRule REQUEST_CONTENT_TYPE ^text/xml \
    "nolog,pass,id:50,ctl:requestBodyProcessor=XML"

SecRule REQUEST_URI "@beginsWith /index.php" \
    "phase:1,t:none,pass,nolog,ctl:ruleRemoveTargetById=981260;ARGS:user"
```

This means `ctl` is the main logic tool when the rule must:

- switch body parsing behavior;
- disable another rule for this transaction;
- remove a specific target from another rule;
- change rule engine or audit behavior for the current transaction.

The manual also notes that some `ctl` sub-options are not supported in v3, so `docs/actions/reference-actions.md` and `docs/actions/not-supported-actions.md` should be checked before using them.

---

## 11. `setvar` Builds Transaction and Persistent State

The manual defines `setvar` as the action for creating, updating, or deleting variables.

Examples from the manual:

```apache
setvar:TX.score
setvar:TX.score=10
setvar:TX.score=+5
setvar:!TX.score
```

This supports several kinds of rule logic:

- set a flag;
- initialize a counter;
- increment or decrement a score;
- remove a variable;
- carry state from one rule to a later rule through `TX`;
- carry state across requests using persistent collections such as `IP`, `SESSION`, or `USER`.

The CRS anomaly-scoring model is built on this mechanism: detection rules add to score variables, and later blocking-evaluation rules compare the accumulated score to thresholds.

---

## 12. Source-Grounded Rule-Writing Sequence

When writing a rule, the source documents support this sequence:

1. Decide **which phase** contains the data you need.
2. Choose the **variable** that corresponds to that data.
3. Decide whether the variable is a **single value** or a **collection**.
4. Choose the **operator** that matches the comparison you need to make.
5. Add only the **transformations** needed for that comparison, starting with `t:none` when using rule-local transforms.
6. Choose the **actions**:
   - metadata (`id`, `phase`, `msg`, etc.)
   - disruptive action (`block`, `deny`, `pass`, ...)
   - non-disruptive actions (`capture`, `setvar`, `ctl`, ...)
7. If one condition is insufficient, use **`chain`**.
8. If execution flow must jump over rules, use **`skip`** or **`skipAfter`**.
9. If behavior must change only for the current transaction, use **`ctl`**.
10. If state must persist across rules or requests, use **`setvar`** and the appropriate collection.

---

## 13. Where to Read Next

- `docs/reference-process.md` for the five phases
- `docs/variables/reference-variables.md` for variable semantics
- `docs/operators/reference-operators.md` for operator behavior
- `docs/transforms/reference-transforms.md` for available transformations
- `docs/actions/reference-actions.md` for action semantics
- `about-modSec-and-CRS/rule-dev.md` for CRS-oriented conventions and templates
