# Variables — Category Reference

Variables tell ModSecurity *where* to look for data. See `reference-variables.md` for full documentation.

Based on `creating.md`, variables fall into **6 categories**: Request, Response, Server, Time, Collection, and Miscellaneous.

---

## Collection Modifiers

These modifiers apply to any collection variable:

| Modifier | Syntax | Description |
|---|---|---|
| All members | `ARGS` | Use the entire collection |
| Specific key | `ARGS:p` | Select only the member named `p` |
| RegEx key | `ARGS:/^id_/` | Select members whose names match the regex |
| Exclude key | `ARGS\|!ARGS:z` | Use all members except `z` |
| Count | `&ARGS` | Returns the number of members in the collection |

---

## Request Variables

Data from the incoming HTTP request. Most are available from phase 1 (headers) or phase 2 (body).

### Request Line & Method

| Variable | Description | Phase |
|---|---|:---:|
| `REQUEST_LINE` | Full first line of the request (e.g., `GET /index.php HTTP/1.1`) | 1 |
| `REQUEST_METHOD` | HTTP method (e.g., `GET`, `POST`, `PUT`) | 1 |
| `REQUEST_PROTOCOL` | HTTP version (e.g., `HTTP/1.1`) | 1 |

### URL / Path

| Variable | Description | Phase |
|---|---|:---:|
| `REQUEST_URI` | Full request URL including query string, without domain | 1 |
| `REQUEST_URI_RAW` | Same as `REQUEST_URI` but includes domain if provided | 1 |
| `REQUEST_FILENAME` | URL path without query string (e.g., `/index.php`) | 1 |
| `REQUEST_BASENAME` | Filename portion only (e.g., `index.php`) | 1 |
| `QUERY_STRING` | Raw query string (not URL-decoded) | 1 |
| `PATH_INFO` | URI information before `?` | 1 |

### Request Headers

| Variable | Description | Phase |
|---|---|:---:|
| `REQUEST_HEADERS` | All request headers (collection). Use `:Header-Name` for specific header | 1 |
| `REQUEST_HEADERS_NAMES` | Collection of all request header names | 1 |

### Request Parameters (Arguments)

| Variable | Description | Phase |
|---|---|:---:|
| `ARGS` | All request parameters: GET + POST combined (collection) | 2 |
| `ARGS_NAMES` | All parameter names (GET + POST combined) | 2 |
| `ARGS_GET` | Query string parameters only | 1 |
| `ARGS_GET_NAMES` | Query string parameter names only | 1 |
| `ARGS_POST` | POST body parameters only | 2 |
| `ARGS_POST_NAMES` | POST body parameter names only | 2 |
| `ARGS_COMBINED_SIZE` | Total byte size of all request parameters (files excluded) | 2 |

### Request Body

| Variable | Description | Phase |
|---|---|:---:|
| `REQUEST_BODY` | Raw request body (available when URLENCODED processor is used) | 2 |
| `REQUEST_BODY_LENGTH` | Number of bytes in the request body | 2 |
| `REQBODY_PROCESSOR` | Name of body processor in use: `URLENCODED`, `MULTIPART`, `XML`, `JSON` | 2 |
| `REQBODY_ERROR` | Set to `1` if body parsing failed | 2 |
| `REQBODY_ERROR_MSG` | Error message when body parsing failed | 2 |
| `FULL_REQUEST` | Complete raw request (line + headers + body) | 2 |
| `FULL_REQUEST_LENGTH` | Byte size of `FULL_REQUEST` | 2 |
| `INBOUND_DATA_ERROR` | Set to `1` when request body exceeds `SecRequestBodyLimit` | 2 |
| `URLENCODED_ERROR` | Set when invalid URL encoding is detected during body parsing | 2 |

### Cookies

| Variable | Description | Phase |
|---|---|:---:|
| `REQUEST_COOKIES` | All cookie values (collection) | 1 |
| `REQUEST_COOKIES_NAMES` | All cookie names (collection) | 1 |

### File Upload (multipart/form-data)

| Variable | Description | Phase |
|---|---|:---:|
| `FILES` | Original filenames as provided by the client | 2 |
| `FILES_NAMES` | Form field names used for file upload | 2 |
| `FILES_SIZES` | Size of each uploaded file | 2 |
| `FILES_COMBINED_SIZE` | Total size of all uploaded files | 2 |
| `FILES_TMPNAMES` | Temporary file paths on disk (for use with `@inspectFile`) | 2 |
| `FILES_TMP_CONTENT` | Content of uploaded files (for use with `@fuzzyHash`; requires `SecUploadKeepFiles On`) | 2 |
| `MULTIPART_FILENAME` | Multipart `filename` field value | 2 |
| `MULTIPART_NAME` | Multipart `name` field value | 2 |
| `MULTIPART_PART_HEADERS` | Collection of all part headers in the multipart body | 2 |
| `MULTIPART_STRICT_ERROR` | Set to `1` when any multipart parsing anomaly is detected (aggregate flag) | 2 |
| `MULTIPART_CRLF_LF_LINES` | Set to `1` when mixed CRLF/LF line endings are detected | 2 |
| `MULTIPART_UNMATCHED_BOUNDARY` | Set to `1` or `2` when a possible boundary mismatch is detected | 2 |

### Authentication

| Variable | Description | Phase |
|---|---|:---:|
| `AUTH_TYPE` | HTTP authentication method (e.g., `Basic`, `Digest`) | 1 |
| `REMOTE_USER` | Username extracted from the `Authorization` header | 1 |

---

## Response Variables

Data from the server's HTTP response. Available from phase 3 (headers) or phase 4 (body).

| Variable | Description | Phase |
|---|---|:---:|
| `RESPONSE_STATUS` | HTTP response status code (e.g., `200`, `404`) | 3 |
| `RESPONSE_PROTOCOL` | HTTP response protocol version | 3 |
| `STATUS_LINE` | Full response status line (e.g., `HTTP/1.1 200 OK`) | 3 |
| `RESPONSE_HEADERS` | All response headers (collection). Use `:Header-Name` for specific header | 3 |
| `RESPONSE_HEADERS_NAMES` | Collection of all response header names | 3 |
| `RESPONSE_CONTENT_TYPE` | Response content type (from internal server structures) | 3 |
| `RESPONSE_CONTENT_LENGTH` | Response body length in bytes (may be 0 if unknown) | 3 |
| `RESPONSE_BODY` | Response body data (requires `SecResponseBodyAccess On`) | 4 |
| `OUTBOUND_DATA_ERROR` | Set to `1` when response body exceeds `SecResponseBodyLimit` | 4 |

---

## Server Variables

Information about the server and the TCP connection.

| Variable | Description |
|---|---|
| `REMOTE_ADDR` | Client IP address |
| `REMOTE_HOST` | Synonym for `REMOTE_ADDR` in v3 |
| `REMOTE_PORT` | Source port of the client connection |
| `SERVER_ADDR` | Server IP address |
| `SERVER_NAME` | Server hostname or IP (from the request; not trusted) |
| `SERVER_PORT` | Local port the server is listening on |
| `UNIQUE_ID` | Unique transaction identifier (millisecond timestamp + random 6-digit number) |
| `DURATION` | Milliseconds elapsed since the start of the current transaction |
| `WEBAPPID` | Current application name (set via `SecWebAppId`) |

---

## Time Variables

Current date and time values.

| Variable | Description |
|---|---|
| `TIME` | Formatted time string: `HH:MM:SS` |
| `TIME_EPOCH` | Unix timestamp (seconds since 1970) |
| `TIME_YEAR` | Four-digit year (e.g., `2025`) |
| `TIME_MON` | Month (0–11) |
| `TIME_DAY` | Day of the month (1–31) |
| `TIME_WDAY` | Weekday (1=Monday … 7=Sunday) |
| `TIME_HOUR` | Hour (0–23) |
| `TIME_MIN` | Minute (0–59) |
| `TIME_SEC` | Second (0–59) |

---

## Collection Variables (Persistent & Transient)

Named collections for storing and sharing data across rules.

### Transient (per-transaction)

| Variable | Description |
|---|---|
| `TX` | Transaction-scoped storage. Use `setvar:tx.name=value` to write, `TX:NAME` to read. `TX:0`–`TX:99` reserved for regex captures |
| `ENV` | Environment variables set by ModSecurity (`setenv`) or other server modules |

### Persistent (cross-request)

| Variable | Description | Initialized with |
|---|---|---|
| `IP` | Per-client-IP persistent storage | `initcol:ip=%{REMOTE_ADDR}` |
| `SESSION` | Per-session persistent storage | `setsid:token` |
| `USER` | Per-user persistent storage | `setuid:username` |
| `RESOURCE` | Per-resource persistent storage | `setrsc:key` |
| `GLOBAL` | Global persistent storage | `initcol:global=1` |

All persistent collections contain built-in read-only fields:
`CREATE_TIME`, `IS_NEW`, `KEY`, `LAST_UPDATE_TIME`, `TIMEOUT`, `UPDATE_COUNTER`, `UPDATE_RATE`

### Result / Geolocation

| Variable | Description |
|---|---|
| `GEO` | Collection populated by `@geoLookup`. Fields: `COUNTRY_CODE`, `COUNTRY_NAME`, `REGION`, `CITY`, `POSTAL_CODE`, `LATITUDE`, `LONGITUDE` |
| `RULE` | Current rule metadata: `RULE.id`, `RULE.rev`, `RULE.severity`, `RULE.msg`, `RULE.logdata` |

---

## Miscellaneous Variables

| Variable | Description |
|---|---|
| `MATCHED_VAR` | Value of the **last** matched variable. Automatically set by all operators (no `capture` needed) |
| `MATCHED_VARS` | Collection of **all** matched values for the current operator check |
| `MATCHED_VAR_NAME` | Full name of the **last** matched variable (e.g., `ARGS:q`) |
| `MATCHED_VARS_NAMES` | Collection of all matched variable names for the current check |
| `HIGHEST_SEVERITY` | Highest severity triggered so far in the transaction (255 = none set; **lower number = higher severity**) |
| `XML` | Special collection for XPath queries against XML-parsed body. Use with `validateDTD`, `validateSchema`, or XPath expressions |
| `USERID` | Value set by `setuid`. Available after `setuid` is executed |
| `SESSIONID` | Value set by `setsid`. Available after `setsid` is executed |
| `WEBAPPID` | Current app name set by `SecWebAppId` |
| `MODSEC_BUILD` | ModSecurity build number, for feature-checking rules |
| `MSC_PCRE_LIMITS_EXCEEDED` | Set to `1` when `@rx`/`@rxGlobal` exceeds `SecPcreMatchLimit` |

---

## Not Supported in v3

The following variables exist in ModSecurity v2 but are **not available in v3**:

| Variable |
|---|
| `PERF_ALL`, `PERF_COMBINED`, `PERF_GC`, `PERF_LOGGING` |
| `PERF_PHASE1` – `PERF_PHASE5`, `PERF_RULES`, `PERF_SREAD`, `PERF_SWRITE` |
| `SCRIPT_BASENAME`, `SCRIPT_FILENAME`, `SCRIPT_GID`, `SCRIPT_GROUPNAME` |
| `SCRIPT_MODE`, `SCRIPT_UID`, `SCRIPT_USERNAME` |
| `SDBM_DELETE_ERROR` |
| `STREAM_INPUT_BODY`, `STREAM_OUTPUT_BODY` |
| `USERAGENT_IP`, `WEBSERVER_ERROR_LOG` |
