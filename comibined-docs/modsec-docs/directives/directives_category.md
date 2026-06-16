# Directives — Category Reference

Directives configure the ModSecurity engine and declare rules. See
`reference-config-directives.md` for full documentation of rule/config directives,
`non-rule-directives.md` for logging directives, and `not-supported-directives.md` for what
is unavailable in v3.

> **Scope for rule generation:** A `SecRule`-generation workflow emits **rules**, not engine
> configuration. The directives that actually appear in generated output are `SecRule`,
> `SecAction`, and `SecMarker`. The rest are environment configuration the rule author
> assumes is already in place — know them for context, but do not emit them unless explicitly
> asked.

---

## Rule-Declaring Directives

The directives that produce or anchor rules. These are what a generator emits.

| Name | Description |
|---|---|
| `SecRule` | Declares a rule: `SecRule VARIABLES "OPERATOR" "ACTIONS"`. The core unit of detection |
| `SecAction` | Unconditionally executes an action list (no operator/variable). Used for setup such as initializing `tx` variables |
| `SecMarker` | A named, no-op anchor that `skipAfter` jumps to. Used to gate rule blocks (e.g. by paranoia level) |
| `SecRuleScript` | Declares a rule whose logic is implemented by an external script |

---

## Rule Management Directives

Modify or remove already-defined rules. Used in exclusion/tuning configs, not in new detection rules.

| Name | Description |
|---|---|
| `SecRuleRemoveById` | Disable rule(s) by ID |
| `SecRuleRemoveByMsg` | Disable rule(s) by `msg` |
| `SecRuleRemoveByTag` | Disable rule(s) by `tag` |
| `SecRuleUpdateActionById` | Change the action list of an existing rule |
| `SecRuleUpdateTargetById` | Change the target variables of an existing rule |
| `SecRuleUpdateTargetByMsg` | Change targets of rule(s) matched by `msg` |
| `SecRuleUpdateTargetByTag` | Change targets of rule(s) matched by `tag` |

---

## Engine & Default Behavior

Global engine state and inherited rule defaults.

| Name | Description |
|---|---|
| `SecRuleEngine` | `On` / `Off` / `DetectionOnly`. In `DetectionOnly`, disruptive actions are not enforced |
| `SecDefaultAction` | Default action list inherited by rules in the same context. Disruptive `block` delegates here |
| `SecAction` | (see Rule-Declaring) often used to set engine-wide `tx` variables at startup |
| `SecComponentSignature` | Declares a component/version signature |
| `SecWebAppId` | Names the application for collection namespacing |

---

## Request Body Handling

Control whether and how request bodies are parsed — they determine what data phase 2 sees.

| Name | Description |
|---|---|
| `SecRequestBodyAccess` | `On`/`Off` — whether the request body is buffered for inspection |
| `SecRequestBodyLimit` | Maximum request body size buffered |
| `SecRequestBodyNoFilesLimit` | Body-size limit excluding file uploads |
| `SecRequestBodyLimitAction` | What to do when the limit is exceeded (`Reject`/`ProcessPartial`) |
| `SecRequestBodyJsonDepthLimit` | Maximum nesting depth for JSON parsing |
| `SecArgumentSeparator` | Separator used when parsing `application/x-www-form-urlencoded` |
| `SecArgumentsLimit` | Maximum number of arguments parsed |
| `SecParseXmlIntoArgs` | Whether XML is parsed into `ARGS` |

---

## Response Body Handling

Control response inspection — they determine what data phases 3–4 see.

| Name | Description |
|---|---|
| `SecResponseBodyAccess` | `On`/`Off` — whether the response body is buffered for inspection |
| `SecResponseBodyLimit` | Maximum response body size buffered |
| `SecResponseBodyLimitAction` | Action when the response-body limit is exceeded |
| `SecResponseBodyMimeType` | MIME types whose response bodies are buffered |
| `SecResponseBodyMimeTypesClear` | Clears the buffered-MIME-type list |

---

## File Upload Handling

| Name | Description |
|---|---|
| `SecUploadDir` | Directory for storing intercepted uploads |
| `SecUploadFileLimit` | Maximum number of uploaded files handled |
| `SecUploadFileMode` | Filesystem permissions for stored uploads |
| `SecUploadKeepFiles` | Whether to retain uploaded files |

---

## PCRE / Matching Limits

| Name | Description |
|---|---|
| `SecPcreMatchLimit` | PCRE match limit (guards against catastrophic backtracking) |

---

## External Data & Lookups

| Name | Description |
|---|---|
| `SecGeoLookupDb` | Path to the geolocation database used by `@geoLookup` |
| `SecHttpBlKey` | API key for Project Honey Pot HTTP:BL lookups |
| `SecRemoteRules` | Load rules from a remote URL |
| `SecRemoteRulesFailAction` | Behavior when remote rule loading fails |
| `SecUnicodeMapFile` | Unicode mapping file used by Unicode-aware transforms |
| `SecXmlExternalEntity` | `On`/`Off` — whether XML external entities are processed |

---

## Logging Directives

Audit and debug logging. See `non-rule-directives.md` for full details. Not emitted by a
rule generator.

| Group | Directives |
|---|---|
| **Audit logging** | `SecAuditEngine`, `SecAuditLog`, `SecAuditLog2`, `SecAuditLogParts`, `SecAuditLogFormat`, `SecAuditLogType`, `SecAuditLogStorageDir`, `SecAuditLogDirMode`, `SecAuditLogFileMode`, `SecAuditLogRelevantStatus`, `SecAuditLogPrefix` |
| **Debug logging** | `SecComponentSignature`, `SecDebugLog`, `SecDebugLogLevel` |

---

## Not Supported in v3

See `not-supported-directives.md`. Do not emit directives listed there.
