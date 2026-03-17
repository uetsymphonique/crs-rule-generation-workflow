# Variables
The following variables are supported in ModSecurity 3.x:

## ARGS
ARGS is a collection and can be used on its own (means all arguments including the POST Payload), with a static parameter (matches arguments with that name), or with a regular expression (matches all arguments with name that matches the regular expression). To look at only the query string or body arguments, see the ARGS_GET and ARGS_POST collections.

Some variables are actually collections, which are expanded into more variables at runtime. The following example will examine all request arguments:

`SecRule ARGS dirty "id:7"`

Sometimes, however, you will want to look only at parts of a collection. This can be achieved with the help of the selection operator(colon). The following example will only look at the arguments named p (do note that, in general, requests can contain multiple arguments with the same name):

`SecRule ARGS:p dirty "id:8"`

It is also possible to specify exclusions. The following will examine all request arguments for the word dirty, except the ones named z (again, there can be zero or more arguments named z):

`SecRule ARGS|!ARGS:z dirty "id:9"`

There is a special operator that allows you to count how many variables there are in a collection. The following rule will trigger if there is more than zero arguments in the request (ignore the second parameter for the time being):

`SecRule &ARGS !^0$ "id:10"`

And sometimes you need to look at an array of parameters, each with a slightly different name. In this case you can specify a regular expression in the selection operator itself. The following rule will look into all arguments whose names begin with id_:

`SecRule ARGS:/^id_/ dirty "id:11"`

> **Note:** Using ARGS:p will not result in any invocations against the operator if argument p does not exist.

> **Note:** Matching in the selection operator (both string and regular expression forms) is performed in a case-insensitive manner.

## ARGS_COMBINED_SIZE
Contains the combined size of all request parameters. Files are excluded from the calculation. This variable can be useful, for example, to create a rule to ensure that the total size of the argument data is below a certain threshold. The following rule detects a request whose parameters are more than 2500 bytes long:

`SecRule ARGS_COMBINED_SIZE "@gt 2500" "id:12"`

## ARGS_GET
ARGS_GET is similar to ARGS, but contains only query string parameters.

## ARGS_GET_NAMES
ARGS_GET_NAMES is similar to ARGS_NAMES, but contains only the names of query string parameters.

## ARGS_NAMES
Contains all request parameter names. You can search for specific parameter names that you want to inspect. In a positive policy scenario, you can also whitelist (using an inverted rule with the exclamation mark) only the authorized argument names.
This example rule allows only two argument names: p and a: 

`SecRule ARGS_NAMES "!^(p|a)$" "id:13"`

## ARGS_POST
ARGS_POST is similar to ARGS, but only contains arguments from the POST body.

## ARGS_POST_NAMES
ARGS_POST_NAMES is similar to ARGS_NAMES, but contains only the names of request body parameters.

## AUTH_TYPE
This variable holds the authentication method used to validate a user, if any of the methods built into HTTP are used. In a reverse-proxy deployment, this information will not be available if the authentication is handled in the backend web server.

`SecRule AUTH_TYPE "Basic" "id:14"`

## DURATION
Contains the number of milliseconds elapsed since the beginning of the current transaction.

## ENV
Collection that provides access to environment variables set by ModSecurity, via setenv, or other server modules. Requires a single parameter to specify the name of the desired variable.
```
# Set environment variable 
SecRule REQUEST_FILENAME "printenv" \
"phase:2,id:15,pass,setenv:tag=suspicious" 

# Inspect environment variable
SecRule ENV:tag "suspicious" "id:16"

# Reading an environment variable from other Apache module (mod_ssl)
SecRule TX:ANOMALY_SCORE "@gt 0" "phase:5,id:16,msg:'%{env.ssl_cipher}'"
```

## FILES
Contains a collection of original file names (as they were called on the remote user’s filesystem). Available only on inspected multipart/form-data requests.

`SecRule FILES "@rx \.conf$" "id:17"`

> **Note:** Only available if files were extracted from the request body.

## FILES_COMBINED_SIZE
Contains the total size of the files transported in request body. Available only on inspected multipart/form-data requests.

`SecRule FILES_COMBINED_SIZE "@gt 100000" "id:18"`

## FILES_NAMES
Contains a list of form fields that were used for file upload. Available only on inspected multipart/form-data requests.

`SecRule FILES_NAMES "^upfile$" "id:19"`

## FULL_REQUEST
Contains the complete request: Request line, Request headers and Request body (if any).

`SecRule FULL_REQUEST "User-Agent: ModSecurity Regression Tests" "id:21"`

> **Note:** The current implementation appears to omit the Request line

## FULL_REQUEST_LENGTH
Represents the amount of bytes that FULL_REQUEST may use. 

`SecRule FULL_REQUEST_LENGTH "@eq 205" "id:21"`

## FILES_SIZES
Contains a list of individual file sizes. Useful for implementing a size limitation on individual uploaded files. Available only on inspected multipart/form-data requests.

`SecRule FILES_SIZES "@gt 100" "id:20"`

## FILES_TMPNAMES
Contains a list of temporary files’ names on the disk. This is Useful when used together with @inspectFile. The executed script can use the provided filename to open the file and examine the contents. Available only on inspected multipart/form-data requests.

`SecRule FILES_TMPNAMES "@inspectFile /path/to/inspect_script.lua" "id:21"`

## FILES_TMP_CONTENT
Contains a key-value set where value is the content of the file which was uploaded.
Useful when used together with @fuzzyHash.

> **Note:** SecUploadKeepFiles should be set to 'On' in order to have this collection filled.

`SecRule FILES_TMP_CONTENT "@fuzzyHash $ENV{CONF_DIR}/ssdeep.txt 1" "id:192372,log,deny"`

## GEO
GEO is a collection populated by the results of the last @geoLookup operator. The collection can be used to match geographical fields looked from an IP address or hostname.

Fields:
- COUNTRY_CODE: Two character country code. EX: US, GB, etc.
- COUNTRY_CODE3: Up to three character country code.
- COUNTRY_NAME: The full country name.
- COUNTRY_CONTINENT: The two character continent that the country is located. EX: EU
- REGION: The two character region. For US, this is state. For Canada, providence, etc.
- CITY: The city name if supported by the database.
- POSTAL_CODE: The postal code if supported by the database.
- LATITUDE: The latitude if supported by the database.
- LONGITUDE: The longitude if supported by the database.
- DMA_CODE: The metropolitan area code if supported by the database. (US only)
- AREA_CODE: The phone system area code. (US only)

Example:
```
SecGeoLookupDB /usr/share/GeoIP/GeoLite2-Country.mmdb
...
SecRule REMOTE_ADDR "@geoLookup" "chain,id:22,drop,msg:'Non-GB IP address'"
SecRule GEO:COUNTRY_CODE "!@streq GB" ""
```
## HIGHEST_SEVERITY
This variable holds the highest severity of any rules that have matched so far. Severities are numeric values and thus can be used with comparison operators such as @lt, and so on. A value of 255 indicates that no severity has been set.

`SecRule HIGHEST_SEVERITY "@le 2" "phase:2,id:23,deny,status:500,msg:'severity %{HIGHEST_SEVERITY}'"`
> **Note:** Higher severities have a lower numeric value.

## INBOUND_DATA_ERROR
This variable will be set to 1 when the request body size is above the setting configured by SecRequestBodyLimit directive.  Your policies should always contain a rule to check this variable.  Depending on the rate of false positives and your default policy you should decide whether to block or just warn when the rule is triggered.

The best way to use this variable is as in the example below:

`SecRule INBOUND_DATA_ERROR "@eq 1" "phase:2,id:24,t:none,log,pass,msg:'Request Body Larger than SecRequestBodyLimit Setting'"`

## MATCHED_VAR
This variable holds the value of the most-recently matched variable. It is similar to the TX:0, but it is automatically supported by all operators and there is no need to specify the capture action.
```
SecRule ARGS pattern chain,deny,id:25
  SecRule MATCHED_VAR "further scrutiny"
```
> **Note:** Be aware that this variable holds data for the ***last*** operator match.  This means that if there are more than one matches, only the last one will be populated.  Use MATCHED_VARS variable if you want all matches.

## MATCHED_VARS
Similar to MATCHED_VAR except that it is a collection of ***all matches*** for the current operator check.
```
SecRule ARGS pattern "chain,deny,id:26"
  SecRule MATCHED_VARS "@eq ARGS:param"
```

## MATCHED_VAR_NAME
This variable holds the full name of the variable that was matched against.
```
SecRule ARGS pattern "chain,deny,id:27"
  SecRule MATCHED_VAR_NAME "@eq ARGS:param"
```

> **Note:** Be aware that this variable holds data for the ***last*** operator match.  This means that if there are more than one matches, only the last one will be populated.  Use MATCHED_VARS_NAMES variable if you want all matches.

## MATCHED_VARS_NAMES
Similar to MATCHED_VAR_NAME except that it is a collection of ***all matches*** for the current operator check.
```
SecRule ARGS pattern "chain,deny,id:28"
  SecRule MATCHED_VARS_NAMES "@eq ARGS:param"
```

## MODSEC_BUILD
This variable holds the ModSecurity build number. This variable is intended to be used to check the build number prior to using a feature that is available only in a certain build. Example:
```
SecRule MODSEC_BUILD "!@ge 030006100" "skipAfter:12345,id:29"
SecRule ARGS "@pm some key words" "id:12345,deny,status:500"
```

## MSC_PCRE_LIMITS_EXCEEDED
MSC_PCRE_LIMITS_EXCEEDED will be set to 1 if an execution of either the @rx or @rxGlobal operator exceeds the limits set by SecPcreMatchLimit.

For compatibility convenience with ModSecurity v2, a synonym of this variable is also set as TX:MSC_PCRE_LIMITS_EXCEEDED.

## MULTIPART_CRLF_LF_LINES

This flag variable will be set to 1 whenever a multi-part request uses mixed line terminators. The multipart/form-data RFC requires CRLF sequence to be used to terminate lines. Since some client implementations use only LF to terminate lines you might want to allow them to proceed under certain circumstances (if you want to do this you will need to stop using MULTIPART_STRICT_ERROR and check each multi-part flag variable individually, avoiding MULTIPART_LF_LINE). However, mixing CRLF and LF line terminators is dangerous as it can allow for evasion. Therefore, in such cases, you will have to add a check for MULTIPART_CRLF_LF_LINES.

## MULTIPART_FILENAME
This variable contains the multipart data from field FILENAME.

## MULTIPART_NAME
This variable contains the multipart data from field NAME.

## MULTIPART_PART_HEADERS
This variable is a collection of all part headers found within the request body with Content-Type multipart/form-data. The key of each item in the collection is the name of the part in which it was found, while the value is the entire part-header line -- including both the part-header name and the part-header value.

`SecRule MULTIPART_PART_HEADERS:parm1 "@rx content-type:.*jpeg" "phase:2,deny,status:403,id:500074,t:lowercase"`

> **Note:** Available beginning with v3.0.8.

## MULTIPART_STRICT_ERROR
MULTIPART_STRICT_ERROR will be set to 1 when any of the following variables is also set to 1: REQBODY_PROCESSOR_ERROR, MULTIPART_BOUNDARY_QUOTED, MULTIPART_BOUNDARY_WHITESPACE, MULTIPART_DATA_BEFORE, MULTIPART_DATA_AFTER, MULTIPART_HEADER_FOLDING, MULTIPART_LF_LINE, MULTIPART_MISSING_SEMICOLON MULTIPART_INVALID_QUOTING MULTIPART_INVALID_HEADER_FOLDING MULTIPART_FILE_LIMIT_EXCEEDED. Each of these variables covers one unusual (although sometimes legal) aspect of the request body in multipart/form-data format. Your policies should always contain a rule to check either this variable (easier) or one or more individual variables (if you know exactly what you want to accomplish). Depending on the rate of false positives and your default policy you should decide whether to block or just warn when the rule is triggered.

The best way to use this variable is as in the example below:
```
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
"phase:2,id:30,t:none,log,deny,msg:'Multipart request body \
failed strict validation: \
PE %{REQBODY_PROCESSOR_ERROR}, \
BQ %{MULTIPART_BOUNDARY_QUOTED}, \
BW %{MULTIPART_BOUNDARY_WHITESPACE}, \
DB %{MULTIPART_DATA_BEFORE}, \
DA %{MULTIPART_DATA_AFTER}, \
HF %{MULTIPART_HEADER_FOLDING}, \
LF %{MULTIPART_LF_LINE}, \
SM %{MULTIPART_MISSING_SEMICOLON}, \
IQ %{MULTIPART_INVALID_QUOTING}, \
IQ %{MULTIPART_INVALID_HEADER_FOLDING}, \
FE %{MULTIPART_FILE_LIMIT_EXCEEDED}'"
```
The multipart/form-data parser actively looks for certain signs of evasion. Many variables (as listed above) expose various facts discovered during the parsing process. The MULTIPART_STRICT_ERROR variable is handy to check on all abnormalities at once. The individual variables allow detection to be fine-tuned according to your circumstances in order to reduce the number of false positives.

> **Note:** This section follows the manual text, which refers to `REQBODY_PROCESSOR_ERROR`. The same manual also documents `REQBODY_ERROR` and `REQBODY_ERROR_MSG` as the primary request-body error variables elsewhere.

## MULTIPART_UNMATCHED_BOUNDARY
The intention of this variable is to identify possible evasion attempts by identifying lines that begin with '--' but are followed by characters such that it is not a match to the boundary. Even in its original implementation (in ModSecurity v2) this detection was known to be prone to false positives. A change made in ModSecurity v3 resulted in two detection variations, one that was still prone to false positives, and a revised detection that will detect very little. The ongoing utility and suitability of this detection is subject to review.

Set to either 1 or 2 when, during the parsing phase of a multipart/request-body, ModSecurity encounters what feels like a boundary but it is not.

See the description of rule 200004 in modsecurity.conf-recommended for more detail.

You can also change the rule from blocking to logging-only if many false positives are encountered.

## OUTBOUND_DATA_ERROR
This variable will be set to 1 when the response body size is above the setting configured by SecResponseBodyLimit directive.  Your policies should always contain a rule to check this variable.  Depending on the rate of false positives and your default policy you should decide whether to block or just warn when the rule is triggered.

The best way to use this variable is as in the example below:

`SecRule OUTBOUND_DATA_ERROR "@eq 1" "phase:1,id:32,t:none,log,pass,msg:'Response Body Larger than SecResponseBodyLimit Setting'"`

## PATH_INFO
Contains the request URI information that precedes any '?' character.

`SecRule PATH_INFO "^/(php)" "id:33"`

## PERF_ALL
Not supported in v3

## PERF_COMBINED
Not supported in v3

## PERF_GC
Not supported in v3

## PERF_LOGGING
Not supported in v3

## PERF_PHASE1
Not supported in v3

## PERF_PHASE2
Not supported in v3

## PERF_PHASE3
Not supported in v3

## PERF_PHASE4
Not supported in v3

## PERF_PHASE5
Not supported in v3

## PERF_RULES
Not supported in v3

## PERF_SREAD
Not supported in v3

## PERF_SWRITE
Not supported in v3

## QUERY_STRING
Contains the query string part of a request URI. The value in QUERY_STRING is always provided raw, without URL decoding taking place.

`SecRule QUERY_STRING "attack" "id:34"`

## REMOTE_ADDR
This variable holds the IP address of the remote client.

`SecRule REMOTE_ADDR "@ipMatch 192.168.1.101" "id:35"`

## REMOTE_HOST
In ModSecurity v3, this variable is a synonym for REMOTE_ADDR.

## REMOTE_PORT
This variable holds information on the source port that the client used when initiating the connection to our web server.

In the following example, we are evaluating to see whether the REMOTE_PORT is less than 1024, which would indicate that the user is a privileged user:

`SecRule REMOTE_PORT "@lt 1024" "id:37"`

## REMOTE_USER
This variable holds the username associated with the transaction, if the username was successfully extracted from the 'Authorization' request header, if present.

`SecRule REMOTE_USER "@streq admin" "id:38"`

## REQBODY_ERROR
Contains the status of the request body processor used for request body parsing. The values can be 0 (no error) or 1 (error). This variable will be set by request body processors (typically the multipart/request-data parser, JSON or the XML parser) when they fail to do their work.

`SecRule REQBODY_ERROR "@eq 1" deny,phase:2,id:39 `

> **Note:** Your policies must have a rule to check for request body processor errors at the very beginning of phase 2. Failure to do so will leave the door open for impedance mismatch attacks. It is possible, for example, that a payload that cannot be parsed by ModSecurity can be successfully parsed by more tolerant parser operating in the application. If your policy dictates blocking, then you should reject the request if error is detected. When operating in detection-only mode, your rule should alert with high severity when request body processing fails.

> **Note:** The manual is not fully consistent here: some sections use `REQBODY_PROCESSOR_ERROR` / `REQBODY_PROCESSOR_ERROR_MSG`, while this variables section documents `REQBODY_ERROR` / `REQBODY_ERROR_MSG`.

## REQBODY_ERROR_MSG
If there has been an error during request body parsing that resulted in REQBODY_ERROR getting set to 1, this variable will contain a text message containing additional information about the error that was encountered. The variable can be tested just as any other variable can:

`SecRule REQBODY_ERROR_MSG "parsing error" "id:40"`

It is more common, however, simply to output the content in a log line, as in rule 200002 in modsecurity.conf-recommended.

## REQBODY_PROCESSOR
Contains the name of the currently used request body processor. If set, the possible values are URLENCODED, MULTIPART, XML, and JSON.

```
SecRule REQBODY_PROCESSOR "^XML$ chain,id:41 
  SecRule XML "@validateDTD /opt/apache-frontend/conf/xml.dtd"
```

## REQUEST_BASENAME
This variable holds just the filename part of REQUEST_FILENAME (e.g., index.php). 

`SecRule REQUEST_BASENAME "^login\.php$" phase:2,id:42,t:none,t:lowercase`

> **Note:** Please note that anti-evasion transformations are not applied to this variable by default. REQUEST_BASENAME will recognise both / and \ as path separators. You should understand that the value of this variable depends on what was provided in request, and that it does not have to correspond to the resource (on disk) that will be used by the web server.

## REQUEST_BODY
Holds the raw request body. This variable is available only if the URLENCODED request body processor was used, which will occur by default when the application/x-www-form-urlencoded content type is detected, or if the use of the URLENCODED request body parser was forced. 

`SecRule REQUEST_BODY "^username=\w{25,}\&password=\w{25,}\&Submit\=login$" "id:43"`

As of 2.5.7, it is possible to force the presence of the REQUEST_BODY variable, but only when there is no request body processor defined using the ctl:forceRequestBodyVariable option in the REQUEST_HEADERS phase.

> **Note:** The ModSecurity v3 manual is inconsistent around `REQUEST_BODY` availability: this variable entry limits it to the URLENCODED processor, while the `ctl:forceRequestBodyVariable` note elsewhere says that option is not implemented in v3 because `REQUEST_BODY` is always populated.

## REQUEST_BODY_LENGTH
Contains the number of bytes read from a request body.

## REQUEST_COOKIES
This variable is a collection of all of request cookies (values only).  Example: the following example is using the Ampersand special operator to count how many variables are in the collection. In this rule, it would trigger if the request does not include any Cookie headers.

`SecRule &REQUEST_COOKIES "@eq 0" "id:44"`

## REQUEST_COOKIES_NAMES
This variable is a collection of the names of all request cookies. For example, the following rule will trigger if the JSESSIONID cookie is not present:

`SecRule &REQUEST_COOKIES_NAMES:JSESSIONID "@eq 0" "id:45"`

## REQUEST_FILENAME
This variable holds the relative request URL without the query string part (e.g., /index.php). 

`SecRule REQUEST_FILENAME "^/cgi-bin/login\.php$" phase:2,id:46,t:none,t:normalizePath`

> **Note:** Please note that anti-evasion transformations are not used on REQUEST_FILENAME, which means that you will have to specify them in the rules that use this variable.

## REQUEST_HEADERS
This variable can be used as either a collection of all of the request headers or can be used to inspect selected headers (by using the REQUEST_HEADERS:Header-Name syntax).

`SecRule REQUEST_HEADERS:Host "^[\d\.]+$" "deny,id:47,log,status:400,msg:'Host header is a numeric IP address'"`

> **Note:** ModSecurity will treat multiple headers that have identical names in accordance with how the webserver treats them. For Apache this means that they will all be concatenated into a single header with a comma as the deliminator. 

## REQUEST_HEADERS_NAMES
This variable is a collection of the names of all of the request headers.

`SecRule REQUEST_HEADERS_NAMES "^x-forwarded-for" "log,deny,id:48,status:403,t:lowercase,msg:'Proxy Server Used'"`

## REQUEST_LINE
This variable holds the complete request line sent to the server (including the request method and HTTP version information).

```
# Allow only POST, GET and HEAD request methods, as well as only
# the valid protocol versions 
SecRule REQUEST_LINE "!(^((?:(?:POS|GE)T|HEAD))|HTTP/(0\.9|1\.0|1\.1)$)" "phase:1,id:49,log,block,t:none"
```

## REQUEST_METHOD
This variable holds the request method used in the transaction.

`SecRule REQUEST_METHOD "^(?:CONNECT|TRACE)$" "id:50,t:none"`

## REQUEST_PROTOCOL
This variable holds the request protocol version information.

`SecRule REQUEST_PROTOCOL "!^HTTP/(0\.9|1\.0|1\.1)$" "id:51"`

## REQUEST_URI
This variable holds the full request URL including the query string data (e.g., /index.php? p=X). However, it will never contain a domain name, even if it was provided on the request line.

`SecRule REQUEST_URI "attack" "phase:1,id:52,t:none,t:urlDecode,t:lowercase,t:normalizePath"`

> **Note:** Please note that anti-evasion transformations are not used on REQUEST_URI, which means that you will have to specify them in the rules that use this variable.

## REQUEST_URI_RAW
Same as REQUEST_URI but will contain the domain name if it was provided on the request line (e.g., http://www.example.com/index.php?p=X).

`SecRule REQUEST_URI_RAW "http:/" "phase:1,id:53,t:none,t:urlDecode,t:lowercase,t:normalizePath"`

> **Note:** Please note that anti-evasion transformations are not used on REQUEST_URI_RAW, which means that you will have to specify them in the rules that use this variable.

## RESPONSE_BODY
This variable holds the data for the response body, but only when response body buffering is enabled.

`SecRule RESPONSE_BODY "ODBC Error Code" "phase:4,id:54,t:none"`

## RESPONSE_CONTENT_LENGTH
Response body length in bytes. Can be available starting with phase 3, but it does not have to be (as the length of response body is not always known in advance). If the size is not known, this variable will contain a zero. If RESPONSE_CONTENT_LENGTH contains a zero in phase 5 that means the actual size of the response body was 0.

## RESPONSE_CONTENT_TYPE
Response content type. Available only starting with phase 3. The value available in this variable is taken directly from the internal structures of Apache, which means that it may contain the information that is not yet available in response headers. In embedded deployments, you should always refer to this variable, rather than to RESPONSE_HEADERS:Content-Type.

## RESPONSE_HEADERS
This variable refers to response headers, in the same way as REQUEST_HEADERS does to request headers.

`SecRule RESPONSE_HEADERS:X-Cache "MISS" "id:55"`

This variable may not have access to some headers when running in embedded mode. Headers such as Server, Date, Connection, and Content-Type could be added just prior to sending the data to the client. This data should be available in phase 5 or when deployed in proxy mode.

## RESPONSE_HEADERS_NAMES
This variable is a collection of the response header names.

`SecRule RESPONSE_HEADERS_NAMES "Set-Cookie" "phase:3,id:56,t:none"`

The same limitations apply as the ones discussed in RESPONSE_HEADERS.

## RESPONSE_PROTOCOL
This variable holds the HTTP response protocol information.

`SecRule RESPONSE_PROTOCOL "^HTTP\/0\.9" "phase:3,id:57,t:none"`

## RESPONSE_STATUS
This variable holds the HTTP response status code:

`SecRule RESPONSE_STATUS "^[45]" "phase:3,id:58,t:none"`

This variable may not work as expected in embedded mode, as Apache sometimes handles certain requests differently, and without invoking ModSecurity (all other modules).

## RULE
This is a special collection that provides access to the id, rev, severity, logdata, and msg fields of the rule that triggered the action. It can be used to refer to only the same rule in which it resides.

`SecRule &REQUEST_HEADERS:Host "@eq 0" "log,deny,id:59,setvar:tx.varname=%{RULE.id}"`

## SCRIPT_BASENAME
Not supported in v3

## SCRIPT_FILENAME
Not supported in v3

## SCRIPT_GID
Not supported in v3

## SCRIPT_GROUPNAME
Not supported in v3

## SCRIPT_MODE
Not supported in v3

## SCRIPT_UID
Not supported in v3

## SCRIPT_USERNAME
Not supported in v3

## SDBM_DELETE_ERROR
Not supported in v3

## SERVER_ADDR
This variable contains the IP address of the server.

`SecRule SERVER_ADDR "@ipMatch 192.168.1.100" "id:67"`

## SERVER_NAME
This variable contains the transaction’s hostname or IP address, taken from the request itself (which means that, in principle, it should not be trusted).

`SecRule SERVER_NAME "hostname\.com$" "id:68"`

## SERVER_PORT
This variable contains the local port that the web server (or reverse proxy) is listening on.

`SecRule SERVER_PORT "^80$" "id:69"`

## SESSION
This variable is a collection that contains session information. It becomes available only after setsid is executed.

The following example shows how to initialize SESSION using setsid, how to use setvar to increase the SESSION.score values, how to set the SESSION.blocked variable, and finally, how to deny the connection based on the SESSION:blocked value:

```
# Initialize session storage 
SecRule REQUEST_COOKIES:PHPSESSID !^$ "phase:2,id:70,nolog,pass,setsid:%{REQUEST_COOKIES.PHPSESSID}"

# Increment session score on attack 
SecRule REQUEST_URI "^/cgi-bin/finger$" "phase:2,id:71,t:none,t:lowercase,t:normalizePath,pass,setvar:SESSION.score=+10" 

# Detect too many attacks in a session
SecRule SESSION:score "@gt 50" "phase:2,id:72,pass,setvar:SESSION.blocked=1"

# Enforce session block 
SecRule SESSION:blocked "@eq 1" "phase:2,id:73,deny,status:403"
```

## SESSIONID
This variable contains the value set with setsid. See SESSION (above) for a complete example.

## STATUS_LINE
This variable holds the full status line sent by the server (including the request method and HTTP version information).

```
# Generate an alert when the application generates 500 errors.
SecRule STATUS_LINE "@contains 500" "phase:3,id:49,log,pass,logdata:'Application error detected!,t:none"
```

## STREAM_INPUT_BODY
Not supported in v3

## STREAM_OUTPUT_BODY
Not supported in v3

## TIME
This variable holds a formatted string representing the time (hour:minute:second).

`SecRule TIME "^(([1](8|9))|([2](0|1|2|3))):\d{2}:\d{2}$" "id:74"`

## TIME_DAY
This variable holds the current date (1–31). The following rule triggers on a transaction that’s happening anytime between the 10th and 20th in a month:

`SecRule TIME_DAY "^(([1](0|1|2|3|4|5|6|7|8|9))|20)$" "id:75"`

## TIME_EPOCH
This variable holds the time in seconds since 1970.

## TIME_HOUR
This variable holds the current hour value (0–23). The following rule triggers when a request is made “off hours”:

`SecRule TIME_HOUR "^(0|1|2|3|4|5|6|[1](8|9)|[2](0|1|2|3))$" "id:76"`

## TIME_MIN
This variable holds the current minute value (0–59). The following rule triggers during the last half hour of every hour:

`SecRule TIME_MIN "^(3|4|5)" "id:77"`

## TIME_MON
This variable holds the current month value (0–11). The following rule matches if the month is either November (value 10) or December (value 11):

`SecRule TIME_MON "^1" "id:78"`

## TIME_SEC
This variable holds the current second value (0–59).

`SecRule TIME_SEC "@gt 30" "id:79"`

## TIME_WDAY
This variable holds the current weekday value (1–7), where Monday is 1. The following rule triggers only on Saturday and Sunday:

`SecRule TIME_WDAY "^(6|7)$" "id:80"`

## TIME_YEAR
This variable holds the current four-digit year value.

`SecRule TIME_YEAR "^2022$" "id:81"`

## TX
This is the transient transaction collection, which is used to store pieces of data, create a transaction anomaly score, and so on. The variables placed into this collection are available only until the transaction is complete.

```
# Increment transaction attack score on attack 
SecRule ARGS attack "phase:2,id:82,nolog,pass,setvar:TX.score=+5"

# Block the transactions whose scores are too high 
SecRule TX:SCORE "@gt 20" "phase:2,id:83,log,deny"
```

Some variable names in the TX collection are reserved and cannot be used: 
- TX:0: the matching value when using the @rx or @pm operator with the capture action
- TX:1-TX:99: the captured subexpression value when using the @rx operator with capturing parens and the capture action

## UNIQUE_ID
This variable holds an identifier intended to be unique to the each transaction. The ModSecurity v3 implementation is to use a millisecond timestamp, followed by a dot character ('.'), followed by a random six-digit number.

## URLENCODED_ERROR
This variable is created when an invalid URL encoding is encountered during the parsing of a query string (on every request) or during the parsing of an application/x-www-form-urlencoded request body (only on the requests that use the URLENCODED request body processor).

## USERID
This variable contains the value set with setuid. 

```
# Initialize user tracking
SecAction "nolog,id:84,pass,setuid:%{REMOTE_USER}" 

# Is the current user the administrator?
SecRule USERID "admin" "id:85"
```

## USERAGENT_IP
Not supported in v3

## WEBAPPID
This variable contains the current application name, which is set in configuration using SecWebAppId.

## WEBSERVER_ERROR_LOG
Not supported in v3

## XML
Special collection used to interact with the XML parser. It can be used standalone as a target for the validateDTD and validateSchema operator. Otherwise, it must contain a valid XPath expression, which will then be evaluated against a previously parsed XML DOM tree.

```
SecDefaultAction log,deny,status:403,phase:2,id:90
SecRule REQUEST_HEADERS:Content-Type ^text/xml$ "phase:1,id:87,t:lowercase,nolog,pass,ctl:requestBodyProcessor=XML"
SecRule REQBODY_PROCESSOR "!^XML$" skipAfter:12345,id:88

SecRule XML:/employees/employee/name/text() Fred "id:89"
SecRule XML:/xq:employees/employee/name/text() Fred "id:12345,xmlns:xq=http://www.example.com/employees"
```

The first XPath expression does not use namespaces. It would match against payload such as this one:
```
<employees>
    <employee>
        <name>Fred Jones</name>
        <address location="home">
            <street>900 Aurora Ave.</street>
            <city>Seattle</city>
            <state>WA</state>
            <zip>98115</zip>
        </address>
        <address location="work">
            <street>2011 152nd Avenue NE</street>
            <city>Redmond</city>
            <state>WA</state>
            <zip>98052</zip>
        </address>
        <phone location="work">(425)555-5665</phone>
        <phone location="home">(206)555-5555</phone>
        <phone location="mobile">(206)555-4321</phone>
    </employee>
</employees>
```

The second XPath expression does use namespaces. It would match the following payload:
```
<xq:employees xmlns:xq="http://www.example.com/employees">
    <employee>
        <name>Fred Jones</name>
        <address location="home">
            <street>900 Aurora Ave.</street>
            <city>Seattle</city>
            <state>WA</state>
            <zip>98115</zip>
        </address>
        <address location="work">
            <street>2011 152nd Avenue NE</street>
            <city>Redmond</city>
            <state>WA</state>
            <zip>98052</zip>
        </address>
        <phone location="work">(425)555-5665</phone>
        <phone location="home">(206)555-5555</phone>
        <phone location="mobile">(206)555-4321</phone>
    </employee>
</xq:employees>
```

Note the different namespace used in the second example.

# Persistent Storage
At this time it is only possible to have five collections in which data is stored persistently (i.e. data available to multiple requests). These are: GLOBAL, RESOURCE, IP, SESSION and USER.

Every collection contains several built-in variables that are available and are read-only unless otherwise specified:
1. **CREATE_TIME** - date/time of the creation of the collection.
1. **IS_NEW** - set to 1 if the collection is new (not yet persisted) otherwise set to 0.
1. **KEY** - the value of the initcol variable (the client's IP address in the example).
1. **LAST_UPDATE_TIME** - date/time of the last update to the collection.
1. **TIMEOUT** - date/time in seconds when the collection will be updated on disk from memory (if no other updates occur). This variable may be set if you wish to specifiy an explicit expiration time (default is 3600 seconds). The TIMEOUT is updated every time that the values of an entry is changed.
1. **UPDATE_COUNTER** - how many times the collection has been updated since creation.
1. **UPDATE_RATE** - is the average rate updates per minute since creation.

To create a collection to hold session variables (SESSION) use action setsid. To create a collection to hold user variables (USER) use action setuid. To create a collection to hold client address variables (IP), global data or resource-specific data, use action initcol.

> **Note:** Persistent collections can only be initialized once per transaction.

> **Note:** ModSecurity implements atomic updates of persistent variables only for integer variables (counters) at this time. Variables are read from storage whenever initcol is encountered in the rules and persisted at the end of request processing. Counters are adjusted by applying a delta generated by re-reading the persisted data just before being persisted. This keeps counter data consistent even if the counter was modified and persisted by another thread/process during the transaction.

> **Note:** When using on-disk storage rather than in-memory storage, libModSecurity uses LMDB. This type of database has, by default, a maximum key length of 511 bytes. This may be a limitation if you are attempting to store a considerable amount of data in variables for a single key.
