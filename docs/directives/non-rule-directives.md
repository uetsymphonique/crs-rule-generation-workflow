# Non-Rule-Generation Directives
The following directives are supported in ModSecurity v3 but do NOT participate in the rule evaluation/matching pipeline.
They configure operational concerns (logging, debugging, server behavior) and are not needed as context for LLM-based CRS rule generation.

# Audit Logging

## SecAuditEngine
**Description:** Configures the audit logging engine. 

**Syntax:** `SecAuditEngine RelevantOnly` 

**Default:** Off 

**Version:** 3.0.0

The SecAuditEngine directive is used to configure the audit engine, which logs complete transactions.

The possible values for the audit log engine are as follows:
- **On**: log all transactions
- **Off**: do not log any transactions
- **RelevantOnly**: only the log transactions that have triggered a warning or an error, or have a status code that is considered to be relevant (as determined by the SecAuditLogRelevantStatus directive)

> **Note:** If you need to change the audit log engine configuration on a per-transaction basis (e.g., in response to some transaction data), use the ctl action (available as of 2cde1933a7be54cac64f960b84441b814e7722f6).

The following example demonstrates how SecAuditEngine is used:
```
SecAuditEngine RelevantOnly
SecAuditLog logs/audit/audit.log
SecAuditLogParts ABCFHZ 
SecAuditLogType Concurrent 
SecAuditLogStorageDir logs/audit 
SecAuditLogRelevantStatus ^(?:5|4(?!04))
```

## SecAuditLog
**Description:** Defines the path to the main audit log file (serial logging format), or the concurrent logging index file (concurrent logging format), or the url (HTTPS).

**Syntax:** `SecAuditLog /path/to/audit.log` 

**Version:** 3.0.0

This file will be used to store the audit log entries if serial audit logging format is used. If concurrent audit logging format is used this file will be used as an index, and contain a record of all audit log files created.

If using `SecAuditLogType HTTPS` specify the destination url. E.g. `SecAuditLog http://xxx.xxx.xxx.xxx:port` 

> **Note:** This audit log file is opened on startup when the server typically still runs as root. You should not allow non-root users to have write privileges for this file or for the directory.

## SecAuditLog2
**Description:** Defines the path to the secondary audit log index file when concurrent logging is enabled. See SecAuditLog for more details.

**Syntax:** `SecAuditLog2 /path/to/audit.log` 

This directive can be used only if SecAuditLog was previously configured and only if concurrent logging format is used.

## SecAuditLogDirMode
**Description:** Configures the mode (permissions) of any directories created for the concurrent audit logs, using an octal mode value as parameter (as used in chmod).

**Syntax:** `SecAuditLogDirMode octal_mode|"default"` 

**Default:** 0750 

You should use this directive with caution to avoid exposing potentially sensitive data to unauthorized users. Using the value default as parameter reverts the configuration back to the default setting. This feature is not available on operating systems not supporting octal file modes.

Example:
```
SecAuditLogDirMode 0740
```
> **Note:** The process umask may still limit the mode if it is being more restrictive than the mode set using this directive.

## SecAuditLogFormat
**Description:** Select the output format of the AuditLogs. The format can be either the native AuditLogs format or JSON.

**Syntax:** `SecAuditLogFormat JSON|Native` 

**Default:** Native

> **Note:** The JSON format is only available if ModSecurity was compiled with support to JSON via the YAJL library. During the compilation time, the yajl-dev package (or similar) must be part of the system. The configure scripts provides information if the YAJL support was enabled or not.

## SecAuditLogFileMode
**Description:** Configures the mode (permissions) of any files created for concurrent audit logs using an octal mode (as used in chmod). See SecAuditLogDirMode for controlling the mode of created audit log directories.

**Syntax:** `SecAuditLogFileMode octal_mode|"default"` 

**Default:** 0640

**Example Usage:** `SecAuditLogFileMode 0644` 

This feature is not available on operating systems not supporting octal file modes. Use this directive with caution to avoid exposing potentially sensitive data to unauthorized users. Using the value "default" will revert back to the default setting.

> **Note:** The process umask may still limit the mode if it is being more restrictive than the mode set using this directive.

## SecAuditLogParts
**Description:** Defines which parts of each transaction are going to be recorded in the audit log. Each part is assigned a single letter; when a letter appears in the list then the equivalent part will be recorded. See below for the list of all parts.

**Syntax:** `SecAuditLogParts PARTLETTERS`

**Example Usage:** `SecAuditLogParts ABCFHZ` 

**Default:** ABCFHZ Note

The format of the audit log format is documented in detail in the Audit Log Data Format Documentation.

Available audit log parts:
- A: Audit log header (mandatory).
- B: Request headers.
- C: Request body (present only if the request body exists and ModSecurity is configured to intercept it. This would require SecRequestBodyAccess to be set to on).
- D: Reserved for intermediary response headers; not implemented yet.
- E: Intermediary response body (present only if ModSecurity is configured to intercept response bodies, and if the audit log engine is configured to record it. Intercepting response bodies requires SecResponseBodyAccess to be enabled). Intermediary response body is the same as the actual response body unless ModSecurity intercepts the intermediary response body, in which case the actual response body will contain the error message (either the Apache default error message, or the ErrorDocument page).
- F: Final response headers (excluding the Date and Server headers, which are always added by Apache in the late stage of content delivery).
- G: Reserved for the actual response body; not implemented yet.
- H: Audit log trailer.
- I: This part has not been implemented in ModSecurity v3.
- J: This part contains information about the files uploaded using multipart/form-data encoding.
- K: This part has not been implemented in ModSecurity v3.
- Z: Final boundary, signifies the end of the entry (mandatory).

## SecAuditLogRelevantStatus
**Description:** Configures which response status code is to be considered relevant for the purpose of audit logging.

**Syntax:** `SecAuditLogRelevantStatus REGEX` 

**Example Usage:** `SecAuditLogRelevantStatus "^(?:5|4(?!04))"` 

**Version:** 3.0.0

**Dependencies/Notes:** Must have SecAuditEngine set to RelevantOnly. Additionally, the auditlog action is present by default in rules, this will make the engine bypass the 'SecAuditLogRelevantStatus' and send rule matches to the audit log regardless of status. You must specify noauditlog in the rules manually or set it in SecDefaultAction.

The main purpose of this directive is to allow you to configure audit logging for only the transactions that have the status code that matches the supplied regular expression. The example provided would log all 5xx and 4xx level status codes, except for 404s. Although you could achieve the same effect with a rule in phase 5, SecAuditLogRelevantStatus is sometimes better, because it continues to work even when SecRuleEngine is disabled.

## SecAuditLogStorageDir
**Description:** Configures the directory where concurrent audit log entries are to be stored. 

**Syntax**: `SecAuditLogStorageDir /path/to/storage/dir`

**Example Usage:** `SecAuditLogStorageDir /tmp/modsecurity_audit `

This directive is only needed when concurrent audit logging is used. The directory must be writable by the web server user. As with all logging mechanisms, ensure that you specify a file system location that has adequate disk space.

## SecAuditLogType
**Description:** Configures the type of audit logging mechanism to be used. 

**Syntax:** `SecAuditLogType Serial|Concurrent|HTTPS `

**Example Usage:** `SecAuditLogType Serial`

**Version:** 3.0.0 

The possible values are:
**Serial:** Audit log entries will be stored in a single file, specified by SecAuditLog. This is convenient for casual use, but it can slow down the server, because only one audit log entry can be written to the file at any one time.
**Concurrent:** One file per transaction is used for audit logging. This approach is more scalable when heavy logging is required (multiple transactions can be recorded in parallel).

## SecAuditLogPrefix
**Description:** Configures a text that will be prepended to each audit log line.

**Syntax**: `SecAuditLogPrefix "text"`

**Version:** 3.0.15 

This parameter is only used when audit log format is set to native. 
Intended to be used in situations where the log target receives entries from multiple log sources (for example when the audit log is written to stdout using `SecAuditLog /dev/stdout`).

**Example:** 
```
SecAuditEngine RelevantOnly
SecAuditLog /dev/stdout
SecAuditLogParts ABHZ
SecAuditLogType Serial
SecAuditLogRelevantStatus ^(?:5|4(?!04))
SecAuditLogPrefix "[audit.log]: "
```

**Audit log:** 
```
[audit.log]: ---Lm20Vggw---A--
[audit.log]: [07/Aug/2025:18:00:57 +0200] 17545824577.300397 200.249.12.31 2313 200.249.12.31 80
[audit.log]: ---Lm20Vggw---B--
[audit.log]: GET /test.pl?param1=   test   &param2=test2 HTTP/1.1
[audit.log]: Host: www.modsecurity.org
[audit.log]: User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)
[audit.log]: Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
[audit.log]: Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
[audit.log]: Accept-Language: en-us,en;q=0.5
[audit.log]: Accept-Encoding: gzip,deflate
[audit.log]: Keep-Alive: 300
[audit.log]: Connection: keep-alive
[audit.log]: Pragma: no-cache
[audit.log]: Cache-Control: no-cache
[audit.log]:
[audit.log]:
[audit.log]: ---Lm20Vggw---H--
[audit.log]: ModSecurity: Access denied with code 403 (phase 1). ...
[audit.log]:
[audit.log]: ---Lm20Vggw---Z--
```

# Debug Logging

## SecComponentSignature
**Description:** Appends component signature to the ModSecurity signature. 

**Syntax:** `SecComponentSignature "COMPONENT_NAME/X.Y.Z (COMMENT)" `

**Example usage**: `SecComponentSignature "core ruleset/2.1.3"`

This directive should be used to make the presence of significant rule sets known. The entire signature will be recorded in the transaction audit log.

> **Note:** The component signature is currently only included in audit log output when the JSON option is used with the SecAuditLogFormat directive.

## SecDebugLog
**Description**: Path to the ModSecurity debug log file. 

**Syntax:** `SecDebugLog /path/to/modsec-debug.log `

**Example Usage:** `SecDebugLog /var/log/modsec_debug.log `

**Version:** 3.0.0

## SecDebugLogLevel
**Description:** Configures the verboseness of the debug log data. 

**Syntax**: `SecDebugLogLevel 0|1|2|3|4|5|6|7|8|9`

**Example Usage:** `SecDebugLogLevel 4 `

**Version:** 3.0.0

Always having the debug log active in a production environment is typically not advised. Even when investigating a specific issue be aware that using a value of 4 or higher can impact performance significantly.

The possible values for the debug log level are: 
- 0: no logging 
- 1: errors only 
- 2: warnings
- 3: notices 
- 4: details of how transactions are handled 
- 5: as above, but including information about each piece of information handled 
- 9: log everything, including very detailed debugging information
