# Actions — Category Reference

Actions instruct ModSecurity *what to do* when a rule matches. See `reference-actions.md` for full documentation.

Each action belongs to one of five official groups:

| Group | Description |
|---|---|
| **Disruptive** | Affect how the transaction is handled (block, pass, allow, deny, etc.) |
| **Non-disruptive** | Execute side-effects without interrupting rule flow |
| **Flow** | Control which rules execute next |
| **Meta-data** | Annotate the rule with descriptive information |
| **Data** | Containers holding values used by other actions |

> **Chain rule restrictions:** Disruptive actions, `phase`, `id`, `msg`, `tag`, `skip`, and `skipAfter` can only appear in the **chain starter** rule. Non-disruptive actions may appear in any rule within a chain.

---

## Disruptive Actions

Affect how the transaction is processed. Only one disruptive action per rule (or chain starter). Not executed when `SecRuleEngine` is set to `DetectionOnly`.

| Name | Description |
|---|---|
| `block` | Executes the disruptive action defined in `SecDefaultAction`. **Preferred in CRS** — allows users to override blocking behavior |
| `deny` | Stops processing and immediately rejects the transaction |
| `drop` | In v3 behaves the same as `deny` |
| `allow` | Stops rule processing and allows the transaction to proceed. Supports `allow:phase` (stop current phase only) and `allow:request` (skip to response phase) |
| `redirect:URL` | Intercepts by redirecting the client to the specified URL (302 by default; use with `status:301/303/307` to change) |
| `pass` | Continues rule processing despite a match — no blocking, but non-disruptive actions still execute |
| `exec:/path/script.lua` | Executes an external Lua script on match, independently from the disruptive action |

---

## Flow Actions

Control which rules execute next. Can only be used in the chain starter rule.

| Name | Description |
|---|---|
| `chain` | ANDs this rule with the immediately following rule. The disruptive action fires only if all chained rules match |
| `skip:N` | Skips the next N rules (or chains) on match. Works only within the current phase |
| `skipAfter:MARKER` | Jumps to the `SecMarker` with the given name on match. Works only within the current phase |

---

## Metadata Actions

Annotate a rule with descriptive information. Can only be used in the chain starter rule.

| Name | Description |
|---|---|
| `id:N` | **Required.** Unique numeric identifier for the rule |
| `phase:N` | Places the rule in processing phase 1–5. Use numeric values: `phase:1`, `phase:2`, etc. Aliases `request`, `response`, `logging` exist but are discouraged |
| `msg:'text'` | Human-readable alert message logged with every match. Supports macro expansion |
| `tag:'value'` | Classification tag for automated categorization. Multiple tags allowed. Supports macro expansion |
| `severity:LEVEL` | Severity level: `CRITICAL`, `ERROR`, `WARNING`, `NOTICE`, `INFO`, `DEBUG` (use text, not numeric syslog values) |
| `rev:'N'` | Rule revision. Used with `id` to track changes |
| `ver:'CRS/4.0.0'` | Rule set version string |
| `accuracy:'N'` | Relative accuracy on false positive/negative scale 1–9 (9 = very accurate) |
| `maturity:'N'` | Rule maturity level 1–9 (9 = extensively tested, 1 = experimental) |

---

## Non-Disruptive Actions

Execute side-effects but do not interrupt rule processing flow. Can appear in any rule within a chain.

### Logging

| Name | Description |
|---|---|
| `log` | Logs the match to the web server error log and audit log |
| `nolog` | Suppresses logging of the match to both error log and audit log |
| `auditlog` | Marks the transaction for audit log output (implicit when `log` is set) |
| `noauditlog` | Prevents this match from contributing to audit log triggers. Does not affect other matching rules in the same transaction |
| `logdata:'text'` | Appends a data fragment to the alert message. Supports macro expansion (e.g., `logdata:'Matched: %{TX.0} in %{MATCHED_VAR_NAME}'`) |

### Variable Management

| Name | Description |
|---|---|
| `capture` | Stores regex capture groups from `@rx` into `TX:0` – `TX:99`. `TX:0` always holds the full match |
| `setvar:col.name=value` | Creates, updates, or deletes a collection variable. Supports `=`, `=+`, `=-`, `=!` (delete) |
| `expirevar:col.name=N` | Sets a collection variable to expire after N seconds. Use alongside `setvar` |
| `initcol:col=key` | Initializes a named persistent collection (IP, SESSION, etc.) from storage or creates a new one in memory |
| `setenv:name=value` | Creates or updates a web server environment variable accessible by both ModSecurity and the web server |

### Session / User Tracking

| Name | Description |
|---|---|
| `setsid:token` | Initializes the SESSION collection using the given session token |
| `setuid:username` | Initializes the USER collection using the given username |
| `setrsc:key` | Initializes the RESOURCE collection using the given key |

### Matching Behavior

| Name | Description |
|---|---|
| `t:none` | Clears all inherited transformation functions. Always use at the start of a transform chain |
| `t:transformName` | Adds a named transformation to the pipeline (e.g., `t:urlDecodeUni`, `t:lowercase`) |
| `multiMatch` | Runs the operator multiple times: once before transforms and once after each transform that changes the input. Prevents evasion via intermediate transform states |
| `ctl:option=value` | Modifies engine configuration for the current transaction only. See supported v3 options below |

### `ctl` sub-options (v3 supported)

| Option | Description |
|---|---|
| `ctl:ruleEngine=On/Off/DetectionOnly` | Toggle rule engine for this transaction |
| `ctl:ruleRemoveById=ID` | Disable a rule for this transaction (must appear before the rule) |
| `ctl:ruleRemoveByTag=tag` | Disable all rules matching a tag for this transaction |
| `ctl:ruleRemoveTargetById=ID;TARGET` | Remove a specific target from a rule's variable list |
| `ctl:ruleRemoveTargetByTag=tag;TARGET` | Remove a specific target from all rules matching a tag |
| `ctl:requestBodyAccess=On/Off` | Toggle request body access |
| `ctl:requestBodyProcessor=URLENCODED/XML/JSON/MULTIPART` | Set body parser |
| `ctl:auditEngine=On/Off/RelevantOnly` | Toggle audit logging |
| `ctl:auditLogParts=+E` | Modify which audit log parts to include |
| `ctl:parseXmlIntoArgs=On/Off` | Control XML node parsing into ARGS |

> See `not-supported-actions.md` for `ctl` sub-options not available in v3.

---

## Data Actions

Not actions in the traditional sense — containers for values used by other actions.

| Name | Description |
|---|---|
| `status:N` | HTTP status code to use with `deny` (default: 403) or `redirect` (301, 302, 303, 307) |
| `xmlns:prefix=URI` | Configures an XML namespace for use in XPath expressions |

---

## Macro Expansion

The following actions support macro expansion at runtime using `%{COLLECTION.VARIABLE}` or `%{VARIABLE}` syntax:

```
msg, logdata, tag, setvar, setenv, initcol, setsid, setuid, expirevar
```

Common macros:

| Macro | Value |
|---|---|
| `%{TX.0}` | Full regex match (requires `capture`) |
| `%{MATCHED_VAR}` | Value of the variable that triggered the match |
| `%{MATCHED_VAR_NAME}` | Name of the variable that triggered the match |
| `%{REMOTE_ADDR}` | Client IP address |
| `%{HIGHEST_SEVERITY}` | Highest severity triggered in this transaction |
| `%{rule.id}` | ID of the current rule |
| `%{rule.msg}` | Message of the current rule |
| `%{tx.anomaly_score}` | Current transaction anomaly score |

---

## Recommended Action Order (CRS Convention)

```
id → phase → allow|block|deny|drop|pass|redirect → status → capture
→ t:none → t:... → log/nolog → auditlog/noauditlog
→ msg → logdata → tag → ctl → ver → severity
→ multiMatch → initcol → setenv → setvar → expirevar
→ chain → skip → skipAfter
```
