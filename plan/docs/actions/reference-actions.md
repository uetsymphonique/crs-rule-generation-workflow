# Actions
Each action belongs to one of five groups:
- **Disruptive actions** - Cause ModSecurity to do something. In many cases something means block transaction, but not in all. For example, the allow action is classified as a disruptive action, but it does the opposite of blocking. There can only be one disruptive action per rule (if there are multiple disruptive actions present, or inherited, only the last one will take effect), or rule chain (in a chain, a disruptive action can only appear in the first rule).
> **Note:** **Disruptive actions will NOT be executed if the SecRuleEngine is set to DetectionOnly**.  If you are creating exception/whitelisting rules that use the allow action, you should also add the ctl:ruleEngine=On action to execute the action.
- **Non-disruptive action**s - Do something, but that something does not and cannot affect the rule processing flow. Setting a variable, or changing its value is an example of a non-disruptive action. Non-disruptive action can appear in any rule, including each rule belonging to a chain.
- **Flow actions** - These actions affect the rule flow (for example skip or skipAfter).
- **Meta-data actions** - Meta-data actions are used to provide more information about rules. Examples include id, rev, severity and msg.
- **Data actions** - Not really actions, these are mere containers that hold data used by other actions. For example, the status action holds the status that will be used for blocking (if it takes place).

## accuracy
**Description:** Specifies the relative accuracy level of the rule related to false positives/negatives.  The value is a string based on a numeric scale (1-9 where 9 is very strong and 1 has many false positives).

**Action Group:** Meta-data

**Example:**
```
SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "\bgetparentfolder\b" \
    "phase:2,ver:'CRS/2.2.4,accuracy:'9',maturity:'9',capture,t:none,t:htmlEntityDecode,t:compressWhiteSpace,t:lowercase,ctl:auditLogParts=+E,block,msg:'Cross-site Scripting (XSS) Attack',id:'958016',tag:'WEB_ATTACK/XSS',tag:'WASCTC/WASC-8',tag:'WASCTC/WASC-22',tag:'OWASP_TOP_10/A2',tag:'OWASP_AppSensor/IE1',tag:'PCI/6.5.1',logdata:'% \
{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.xss_score=+%{tx.critical_anomaly_score},setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/XSS-%{matched_var_name}=%{tx.0}"
```

## allow
**Description:** Stops rule processing on a successful match and allows the transaction to proceed.

**Action Group:** Disruptive

Example:
```
# Allow unrestricted access from 192.168.1.100 
SecRule REMOTE_ADDR "^192\.168\.1\.100$" phase:1,id:95,nolog,allow
```

The action supports some finer-grained control of what is done. The following options are available:
1. If used on its own, like in the example above, allow will affect the entire transaction, stopping processing of the current phase but also skipping over all other phases apart from the logging phase. (The logging phase is special; it is designed to always execute.)
1. If used with parameter "phase", allow will cause the engine to stop processing the current phase. Other phases will continue as normal.
1. If used with parameter "request", allow will cause the engine to stop processing the current phase. The next phase to be processed will be phase RESPONSE_HEADERS.

Examples:
```
# Do not process request but process response.
SecAction phase:1,allow:request,id:96

# Do not process transaction (request and response).
SecAction phase:1,allow,id:97
```

If you want to allow a response through, put a rule in phase RESPONSE_HEADERS and simply use allow on its own:
```
# Allow response through.
SecAction phase:3,allow,id:98
```

## auditlog
**Description:** Marks the transaction for logging in the audit log.

**Action Group**: Non-disruptive

Example:

`SecRule REMOTE_ADDR "^192\.168\.1\.100$" auditlog,phase:1,id:100,allow`

> **Note:** The auditlog action is now explicit if log is already specified.

## block
**Description:** Performs the disruptive action defined by the previous SecDefaultAction.

**Action Group:** Disruptive

This action is essentially a placeholder that is intended to be used by rule writers to request a blocking action, but without specifying how the blocking is to be done. The idea is that such decisions are best left to rule users, as well as to allow users, to override blocking if they so desire. 
In future versions of ModSecurity, more control and functionality will be added to define "how" to block.

Examples:
```
# Specify how blocking is to be done 
SecDefaultAction phase:2,deny,id:101,status:403,log,auditlog

# Detect attacks where we want to block 
SecRule ARGS attack1 phase:2,block,id:102

# Detect attacks where we want only to warn 
SecRule ARGS attack2 phase:2,pass,id:103
```

It is possible to use the SecRuleUpdateActionById directive to override how a rule handles blocking. This is useful in three cases:
1. If a rule has blocking hard-coded, and you want it to use the policy you determine 
1. If a rule was written to block, but you want it to only warn 
1. If a rule was written to only warn, but you want it to block

The following example demonstrates the first case, in which the hard-coded block is removed in favor of the user-controllable block:
```
# Specify how blocking is to be done 
SecDefaultAction phase:2,deny,status:403,log,auditlog,id:104

# Detect attacks and block 
SecRule ARGS attack1 phase:2,id:1,deny

# Change how rule ID 1 blocks 
SecRuleUpdateActionById 1 block
```

## capture
**Description:** When used together with the regular expression operator (@rx), the capture action will create copies of the regular expression captures and place them into the transaction variable collection.

**Action Group:** Non-disruptive

Example:
```
SecRule REQUEST_BODY "^username=(\w{25,})" phase:2,capture,t:none,chain,id:105
  SecRule TX:1 "(?:(?:a(dmin|nonymous)))"
```

Up to 100 captures will be copied on a successful pattern match, each with a name consisting of a number from 0 to 99. The TX.0 variable always contains the entire area that the regular expression matched. All the other variables contain the captured values, in the order in which the capturing parentheses appear in the regular expression.

## chain
**Description:** Chains the current rule with the rule that immediately follows it, creating a rule chain. Chained rules allow for more complex processing logic.

**Action Group:** Flow

Example:
```
# Refuse to accept POST requests that do not contain Content-Length header. 
# (Do note that this rule should be preceded by a rule 
# that verifies only valid request methods are used.) 
SecRule REQUEST_METHOD "^POST$" phase:1,chain,t:none,id:105
  SecRule &REQUEST_HEADERS:Content-Length "@eq 0" t:none
```

> **Note:** Rule chains allow you to simulate logical AND. The disruptive actions specified in the first portion of the chained rule will be triggered only if all of the variable checks return positive hits. If any one aspect of a chained rule comes back negative, then the entire rule chain will fail to match. Also note that disruptive actions, execution phases, metadata actions (id, rev, msg, tag, severity, logdata), skip, and skipAfter actions can be specified only by the chain starter rule.

The following directives can be used in rule chains: 
- SecAction
- SecRule
- SecRuleScript 
Special rules control the usage of actions in chained rules:
- Any actions that affect the rule flow (i.e., the disruptive actions, skip and skipAfter) can be used only in the chain starter. They will be executed only if the entire chain matches.
- Non-disruptive actions can be used in any rule; they will be executed if the rule that contains them matches and not only when the entire chain matches.
- The metadata actions (e.g., id, rev, msg) can be used only in the chain starter.

## ctl
**Description**: Changes ModSecurity configuration on transient, per-transaction basis. Any changes made using this action will affect only the transaction in which the action is executed. The default configuration, as well as the other transactions running in parallel, will be unaffected.

**Action Group:** Non-disruptive

**Example:**
```
# Parse requests with Content-Type "text/xml" as XML 
SecRule REQUEST_CONTENT_TYPE ^text/xml "nolog,pass,id:106,ctl:requestBodyProcessor=XML"

# white-list the user parameter for rule #981260 when the REQUEST_URI is /index.php
SecRule REQUEST_URI "@beginsWith /index.php" "phase:1,t:none,pass, \
  nolog,ctl:ruleRemoveTargetById=981260;ARGS:user
```

The following configuration options are supported in v3:

| Option | Notes |
|---|---|
| `auditEngine` | |
| `auditLogParts` | |
| `parseXmlIntoArgs` | controls XML nodes' parsing into `ARGS` |
| `requestBodyAccess` | |
| `requestBodyProcessor` | |
| `ruleEngine` | |
| `ruleRemoveById` | must be specified **before** the rule it disables |
| `ruleRemoveByTag` | |
| `ruleRemoveTargetById` | no need to use `!` before target list |
| `ruleRemoveTargetByTag` | no need to use `!` before target list |

> **Note:** `debugLogLevel`, `requestBodyLimit`, `responseBodyAccess`, `responseBodyLimit`, `ruleRemoveByMsg`, `forceRequestBodyVariable`, and `ruleRemoveTargetByMsg` are **not supported in v3**. See [not-supported-actions.md](not-supported-actions.md).

With the exception of the requestBodyProcessor, each configuration option corresponds to one configuration directive and the usage is identical.

The requestBodyProcessor option allows you to configure the request body processor. By default, ModSecurity will use the URLENCODED and MULTIPART processors to process an application/x-www-form-urlencoded and a multipart/form-data body, respectively. Other two processors are also supported: JSON and XML, but they are never used implicitly. Instead, you must tell ModSecurity to use it by placing a few rules in the REQUEST_HEADERS processing phase. After the request body is processed as XML, you will be able to use the XML-related features to inspect it.

Request body processors will not interrupt a transaction if an error occurs during parsing. The manual text in this section refers to `REQBODY_PROCESSOR_ERROR` and `REQBODY_PROCESSOR_ERROR_MSG`, while the variables reference documents `REQBODY_ERROR` and `REQBODY_ERROR_MSG`. Treat this as a manual inconsistency and verify the exact variable names against the variables reference and your deployed version.

## deny
**Description:** Stops rule processing and intercepts transaction.

**Action Group:** Disruptive

Example:
`SecRule REQUEST_HEADERS:User-Agent "nikto" "log,deny,id:107,msg:'Nikto Scanners Identified'"`

## drop
**Description:** Unlike in v2, in ModSecurity v3 this action currently functions the same as the deny action.

## exec
**Description:** Executes an external script supplied as parameter. ModSecurity v3 currently only supports Lua scripts (detected by the .lua extension). Please read the SecRuleScript documentation for more details on how to write Lua scripts.

**Action Group:** Non-disruptive

**Example:**
```
# Run Lua script on rule match 
SecRule ARGS:p attack "phase:2,id:113,block,exec:/usr/local/apache/conf/exec.lua"
```
The exec action is executed independently from any disruptive actions specified. External scripts will always be called with no parameters. Some transaction information will be placed in environment variables. All the usual CGI environment variables will be there. You should be aware that forking a threaded process results in all threads being replicated in the new process. Forking can therefore incur larger overhead in a multithreaded deployment. The script you execute must write something (anything) to stdout; if it doesn’t, ModSecurity will assume that the script failed, and will record the failure.

## expirevar
**Description:** Configures a collection variable to expire after the given time period (in seconds).

**Action Group:** Non-disruptive

**Example:**
```
SecRule REQUEST_COOKIES:JSESSIONID "!^$" "nolog,phase:1,id:114,pass,setsid:%{REQUEST_COOKIES:JSESSIONID}"
SecRule REQUEST_URI "^/cgi-bin/script\.pl" "phase:2,id:115,t:none,t:lowercase,t:normalizePath,log,allow,setvar:session.suspicious=1,expirevar:session.suspicious=3600"
```

You should use the expirevar actions at the same time that you use setvar actions. Only one expirevar action per rule will be executed.

> **Note:** Available beginning with v3.0.11.

## id
**Description**: Assigns a unique, numeric ID to the rule or chain in which it appears.

This action is required for both SecRule directives and SecAction directives. It is not currently mandatory for SecRuleScript directives but it is strongly recommended.

**Action Group:** Meta-data

**Example:**
```
SecRule &REQUEST_HEADERS:Host "@eq 0" "log,id:60008,severity:2,msg:'Request Missing a Host Header'"
```

> **Note:** The id is an identifier only; it does not determine the relative order in which rules are executed. I.e. a rule with id 5001 will not be executed before rule 5002 just because the former is numerically smaller.

These are the reserved ranges:

- 1–99,999: reserved for local (internal) use. Use as you see fit, but do not use this range for rules that are distributed to others
- 100,000–199,999: reserved for rules published by Oracle
- 200,000–299,999: reserved for rules published Comodo
- 300,000–399,999: reserved for rules published at gotroot.com
- 400,000–419,999: unused (available for reservation)
- 420,000–429,999: reserved for ScallyWhack <http://projects.otaku42.de/wiki/Scally-Whack>
- 430,000–439,999: reserved for rules published by Flameeyes <http://www.flameeyes.eu/projects/modsec> 
- 440.000-599,999: unused (available for reservation)
- 600,000-699,999: reserved for use by Akamai <http://www.akamai.com/html/solutions/waf.html>
- 700,000–799,999: reserved for Ivan Ristic
- 900,000–999,999: reserved for the OWASP ModSecurity Core Rule Set <http://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project> project
- 1,000,000-1,009,999: reserved for rules published by Redhat Security Team
- 1,010,000-1,999,999: reserved for WAF | Web Application Firewall and Load Balancer Security (kemptechnologies.com) <https://kemptechnologies.com/solutions/waf/> 
- 2,000,000-2,999,999: reserved for rules from Trustwave's SpiderLabs Research team
- 3,000,000-3,999,999: reserved for use by Akamai <http://www.akamai.com/html/solutions/waf.html>
- 4,000,000-4,099,999 reserved: in use by AviNetworks <https://kb.avinetworks.com/docs/latest/vantage-web-app-firewall-beta/>
- 4,100,000-4,199,999 reserved: in use by Fastly <https://www.fastly.com/products/cloud-security/#products-cloud-security-web-application-firewall>
- 4,200,000-4,299,999 reserved: in use by CMS-Garden <https://www.cms-garden.org/en>
- 4,300,000-4,300,999 reserved: in use by Ensim.hu <http://ensim.hu/>
- 4,301,000-19,999,999: unused (available for reservation)
- 8,000,000-8,999,999 reserved: in use by Yandex
- 20,000,000-21,999,999: reserved for rules from Trustwave's SpiderLabs Research team
- 22,000,000-69,999,999: unused (available for reservation)
- 77,000,000-77,999,999 - reserved: in use by Imunify360 - production rules
- 88,000,000-88,999,999 - reserved: in use by Imunify360 - beta users
- 99,000,000-99,099,999  reserved for use by Microsoft https://azure.microsoft.com/en-us/services/web-application-firewall/
- 99,100,000-99,199,999 reserved for use by WPScan/Jetpack
- 99,200,000-99,209,999 reserved for use by SKUDONET <https://www.skudonet.com>

## initcol
**Description:** Initializes a named persistent collection, either by loading data from storage or by creating a new collection in memory.

**Action Group:** Non-disruptive

**Example:** The following example initiates IP address tracking, which is best done in phase 1:
```
SecAction phase:1,id:116,nolog,pass,initcol:ip=%{REMOTE_ADDR}
```

Collections are loaded into memory on-demand, when the initcol action is executed. A collection will be persisted only if a change was made to it in the course of transaction processing.

See the "Persistent Storage" section for further details.

## log
**Description:** Indicates that a successful match of the rule needs to be logged.

**Action Group:** Non-disruptive

**Example:**
```
SecAction phase:1,id:117,pass,initcol:ip=%{REMOTE_ADDR},log
```

This action will log matches to the web server's error log file and the ModSecurity audit log.

## logdata
**Description:** Logs a data fragment as part of the alert message.

**Action Group:** Non-disruptive

**Example:**
```
SecRule ARGS:p "@rx <script>" "phase:2,id:118,log,pass,logdata:%{MATCHED_VAR}"
```

The logdata information appears in the error and/or audit log files. Macro expansion is performed, so you may use variable names such as %{TX.0} or %{MATCHED_VAR}. The information is properly escaped for use with logging of binary data.

## maturity
**Description:** Specifies the relative maturity level of the rule related to the length of time a rule has been public and the amount of testing it has received.  The value is a string based on a numeric scale (1-9 where 9 is extensively tested and 1 is a brand new experimental rule).

**Action Group:** Meta-data

**Example:**
```
SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "\bgetparentfolder\b" \
    "phase:2,ver:'CRS/2.2.4,accuracy:'9',maturity:'9',capture,t:none,t:htmlEntityDecode,t:compressWhiteSpace,t:lowercase,ctl:auditLogParts=+E,block,msg:'Cross-site Scripting (XSS) Attack',id:'958016',tag:'WEB_ATTACK/XSS',tag:'WASCTC/WASC-8',tag:'WASCTC/WASC-22',tag:'OWASP_TOP_10/A2',tag:'OWASP_AppSensor/IE1',tag:'PCI/6.5.1',logdata:'% \
{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.xss_score=+%{tx.critical_anomaly_score},setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/XSS-%{matched_var_name}=%{tx.0}"
```

## msg
**Description:** Assigns a custom message to the rule or chain in which it appears. The message will be logged along with every alert.

**Action Group:** Meta-data

**Example:**
```
SecRule &REQUEST_HEADERS:Host "@eq 0" "log,id:60008,severity:2,msg:'Request Missing a Host Header'"
```

> **Note:** The msg information appears in the error and/or audit log files and is not sent back to the client in response headers.

## multiMatch
**Description:** If enabled, ModSecurity will perform multiple operator invocations for every target, before and after every anti-evasion transformation is performed.

**Action Group:** Non-disruptive

**Example:**
```
SecRule ARGS "attack" "phase1,log,deny,id:119,t:removeNulls,t:lowercase,multiMatch"
```

Normally, variables are inspected only once per rule, and only after all transformation functions have been completed. With multiMatch, variables are checked against the operator before and after every transformation function that changes the input.

## noauditlog
**Description:** Indicates that a successful match of the rule should not be used as criteria to determine whether the transaction should be logged to the audit log.

**Action Group:** Non-disruptive

**Example:**
```
SecRule REQUEST_HEADERS:User-Agent "Test" allow,noauditlog,id:120
```

If the SecAuditEngine is set to On, all of the transactions will be logged. If it is set to RelevantOnly, then you can control the logging with the noauditlog action.

The noauditlog action affects only the current rule. If you prevent audit logging in one rule only, a match in another rule will still cause audit logging to take place. If you want to prevent audit logging from taking place, regardless of whether any rule matches, use ctl:auditEngine=Off.

## nolog
**Description:** Prevents rule matches from appearing in both the error and audit logs.

**Action Group:** Non-disruptive

**Example:**
```
SecRule REQUEST_HEADERS:User-Agent "Test" allow,nolog,id:121
```

Although nolog implies noauditlog, you can override the former by using nolog,auditlog.

## pass
**Description:** Continues processing with the next rule in spite of a successful match.

**Action Group:** Disruptive

**Example:**
```
SecRule REQUEST_HEADERS:User-Agent "Test" "log,pass,id:122"
```

When using pass with a SecRule with multiple targets, all variables will be inspected and all non-disruptive actions trigger for every match. In the following example, the TX.test variable will be incremented once for every request parameter:
```
# Set TX.test to zero 
SecAction "phase:2,nolog,pass,setvar:TX.test=0,id:123"

# Increment TX.test for every request parameter 
SecRule ARGS "test" "phase:2,log,pass,setvar:TX.test=+1,id:124"
```

## phase
**Description**: Places the rule or chain into one of five available processing phases. It can also be used in SecDefaultAction to establish the rule defaults for that phase.

**Action Group:** Meta-data

**Example:**
```
# Initialize IP address tracking in phase 1
SecAction phase:1,nolog,pass,id:126,initcol:IP=%{REMOTE_ADDR}
```

There are aliases for three of the five phase numbers:
- **2 - request**
- **4 - response**
- **5 - logging**

**Example:**
```
SecRule REQUEST_HEADERS:User-Agent "Test" "phase:request,log,deny,id:127"
```

> **Warning:** Keep in mind that if you specify the incorrect phase, the variable used in the rule may not yet be available. This could lead to a false negative situation where your variable and operator may be correct, but it misses malicious data because you specified the wrong phase.


## redirect
**Description:** Intercepts transaction by issuing an external (client-visible) redirection to the given location..

**Action Group:** Disruptive

**Example:**
```
SecRule REQUEST_HEADERS:User-Agent "Test" "phase:1,id:130,log,redirect:http://www.example.com/failed.html"
```

If the status action is present on the same rule, and its value can be used for a redirection (i.e., is one of the following: 301, 302, 303, or 307), the value will be used for the redirection status code. Otherwise, status code 302 will be used.

## rev
**Description:** Specifies rule revision. It is useful in combination with the id action to provide an indication that a rule has been changed.

**Action Group:** Meta-data

**Example:**
```
SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "(?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))" \
                    "phase:2,rev:'2.1.3',capture,t:none,t:normalizePath,t:lowercase,ctl:auditLogParts=+E,block,msg:'System Command Injection',id:'950907',tag:'WEB_ATTACK/COMMAND_INJECTION',tag:'WASCTC/WASC-31',tag:'OWASP_TOP_10/A1',tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.command_injection_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/COMMAND_INJECTION-%{matched_var_name}=%{tx.0},skipAfter:END_COMMAND_INJECTION1"
```

> **Note:** This action is used in combination with the id action to allow the same rule ID to be used after changes take place but to still provide some indication the rule changed.


## severity
**Description:** Assigns severity to the rule in which it is used.

**Action Group:** Meta-data

**Example:**
```
SecRule REQUEST_METHOD "^PUT$" "id:340002,rev:1,severity:CRITICAL,msg:'Restricted HTTP function'"
```

Severity values in ModSecurity follows the numeric scale of syslog (where 0 is the most severe):
- **0 - EMERGENCY**
- **1 - ALERT**
- **2 - CRITICAL**
- **3 - ERROR**
- **4 - WARNING**
- **5 - NOTICE**
- **6 - INFO**
- **7 - DEBUG**

It is possible to specify severity levels using either the numerical values or the text values, but you should always specify severity levels using the text values, because it is difficult to remember what a number stands for. The use of the numerical values is deprecated and may be removed in one of the subsequent major updates.

## setuid
**Description:** Special-purpose action that initializes the USER collection using the username provided as parameter.

**Action Group:** Non-disruptive

**Example:**
```
SecRule ARGS:username ".*" "phase:2,id:137,t:none,pass,nolog,noauditlog,capture,setvar:session.username=%{TX.0},setuid:%{TX.0}"
```

After initialization takes place, the variable USERID will be available for use in the subsequent rules. This action understands application namespaces (configured using SecWebAppId), and will use one if it is configured.

## setrsc
**Description:** Special-purpose action that initializes the RESOURCE collection using a key provided as parameter.

**Action Group:** Non-disruptive

**Example:**
```
SecAction "phase:1,pass,id:3,log,setrsc:'abcd1234'"
```

This action understands application namespaces (configured using SecWebAppId), and will use one if it is configured.

## setsid
**Description:** Special-purpose action that initializes the SESSION collection using the session token provided as parameter.

**Action Group:** Non-disruptive

**Example:**
```
# Initialise session variables using the session cookie value 
SecRule REQUEST_COOKIES:PHPSESSID !^$ "nolog,pass,id:138,setsid:%{REQUEST_COOKIES.PHPSESSID}"
```
Note

After the initialization takes place, the variable SESSION will be available for use in the subsequent rules. This action understands application namespaces (configured using SecWebAppId), and will use one if it is configured.

Setsid takes an individual variable, not a collection. Variables within an action, such as setsid, use the format [collection].[variable] .

## setenv
**Description:** Creates and updates environment variables that can be accessed by both ModSecurity and the web server.

**Action Group:** Non-disruptive

**Examples:**
```
SecRule RESPONSE_HEADERS:/Set-Cookie2?/ "(?i:(j?sessionid|(php)?sessid|(asp|jserv|jw)?session[-_]?(id)?|cf(id|token)|sid))" "phase:3,t:none,pass,id:139,nolog,setvar:tx.sessionid=%{matched_var}"
SecRule TX:SESSIONID "!(?i:\;? ?httponly;?)" "phase:3,id:140,t:none,setenv:httponly_cookie=%{matched_var},pass,log,auditlog,msg:'AppDefect: Missing HttpOnly Cookie Flag.'"
```

> **Note:** Unlike in ModSecurity v2, setenv on the first rule of a chain will only execute if the entirel chain matches.

## setvar
**Description:** Creates, removes, or updates a variable. Variable names are case-insensitive.

**Action Group:** Non-disruptive

**Examples:**
To create a variable and set its value to 1 (usually used for setting flags), use: `setvar:TX.score`

To create a variable and initialize it at the same time, use: `setvar:TX.score=10`

To remove a variable, prefix the name with an exclamation mark: `setvar:!TX.score`

To increase or decrease variable value, use + and - characters in front of a numerical value: `setvar:TX.score=+5`

> **Note:** When used in a chain this action will be executed when an individual rule matches and not the entire chain.This means that 
```
SecRule REQUEST_FILENAME "@contains /test.php" "chain,id:7,phase:1,t:none,nolog,setvar:tx.auth_attempt=+1" 
    SecRule ARGS_POST:action "@streq login" "t:none"
```
**will increment every time that test.php is visited (regardless of the parameters submitted). If the desired goal is to set the variable only if the entire rule matches, it should be included in the last rule of the chain . For instance:** 
```
SecRule REQUEST_FILENAME "@streq test.php" "chain,id:7,phase:1,t:none,nolog"
    SecRule ARGS_POST:action "@streq login" "t:none,setvar:tx.auth_attempt=+1"
```
## skip
**Description:** Skips one or more rules (or chains) on successful match.

**Action Group:** Flow

**Example:**
```
# Require Accept header, but not from access from the localhost 
SecRule REMOTE_ADDR "^127\.0\.0\.1$" "phase:1,skip:1,id:141" 

# This rule will be skipped over when REMOTE_ADDR is 127.0.0.1 
SecRule &REQUEST_HEADERS:Accept "@eq 0" "phase:1,id:142,deny,msg:'Request Missing an Accept Header'"
```

The skip action works only within the current processing phase and not necessarily in the order in which the rules appear in the configuration file. If you place a phase 2 rule after a phase 1 rule that uses skip, it will not skip over the phase 2 rule. It will skip over the next phase 1 rule that follows it in the phase.

## skipAfter
Description: Skips one or more rules (or chains) on a successful match, resuming rule execution with the first rule that follows the rule (or marker created by SecMarker) with the provided ID.

**Action Group:** Flow

**Example:** The following rules implement the same logic as the skip example, but using skipAfter:
```
# Require Accept header, but not from access from the localhost 
SecRule REMOTE_ADDR "^127\.0\.0\.1$" "phase:1,id:143,skipAfter:IGNORE_LOCALHOST" 

# This rule will be skipped over when REMOTE_ADDR is 127.0.0.1 
SecRule &REQUEST_HEADERS:Accept "@eq 0" "phase:1,deny,id:144,msg:'Request Missing an Accept Header'" 
SecMarker IGNORE_LOCALHOST
```

Example from the OWASP ModSecurity CRS:
```
SecMarker BEGIN_HOST_CHECK

    SecRule &REQUEST_HEADERS:Host "@eq 0" \
            "skipAfter:END_HOST_CHECK,phase:2,rev:'2.1.3',t:none,block,msg:'Request Missing a Host Header',id:'960008',tag:'PROTOCOL_VIOLATION/MISSING_HEADER_HOST',tag:'WASCTC/WASC-21', \
tag:'OWASP_TOP_10/A7',tag:'PCI/6.5.10',severity:'5',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.notice_anomaly_score}, \
setvar:tx.protocol_violation_score=+%{tx.notice_anomaly_score},setvar:tx.%{rule.id}-PROTOCOL_VIOLATION/MISSING_HEADER-%{matched_var_name}=%{matched_var}"

    SecRule REQUEST_HEADERS:Host "^$" \
            "phase:2,rev:'2.1.3',t:none,block,msg:'Request Missing a Host Header',id:'960008',tag:'PROTOCOL_VIOLATION/MISSING_HEADER_HOST',tag:'WASCTC/WASC-21',tag:'OWASP_TOP_10/A7', \
tag:'PCI/6.5.10',severity:'5',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.notice_anomaly_score},setvar:tx.protocol_violation_score=+%{tx.notice_anomaly_score}, \
setvar:tx.%{rule.id}-PROTOCOL_VIOLATION/MISSING_HEADER-%{matched_var_name}=%{matched_var}"

SecMarker END_HOST_CHECK
```

The skipAfter action works only within the current processing phase and not necessarily the order in which the rules appear in the configuration file. If you place a phase 2 rule after a phase 1 rule that uses skipAfter, it will not skip over the phase 2 rule. It will skip over the next phase 1 rule that follows it in the phase.

## status
**Description:** Specifies the response status code to use with actions deny and redirect.

**Action Group:** Data

**Example:**
```
# Deny with status 403
SecDefaultAction "phase:1,log,deny,id:145,status:403"
```

## t
**Description:** This action is used to specify the transformation pipeline to use to transform the value of each variable used in the rule before matching.

**Action Group:** Non-disruptive

**Example:**
```
SecRule ARGS "(asfunction|javascript|vbscript|data|mocha|livescript):" "id:146,t:none,t:htmlEntityDecode,t:lowercase,t:removeNulls,t:removeWhitespace"
```

Any transformation functions that you specify in a SecRule will be added to the previous ones specified in SecDefaultAction. It is recommended that you always use t:none in your rules, which prevents them depending on the default configuration.

## tag
**Description:** Assigns a tag (category) to a rule or a chain.

**Action Group:** Meta-data

**Example:**
```
SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "\bgetparentfolder\b" \
    "phase:2,rev:'2.1.3',capture,t:none,t:htmlEntityDecode,t:compressWhiteSpace,t:lowercase,ctl:auditLogParts=+E,block,msg:'Cross-site Scripting (XSS) Attack',id:'958016',tag:'WEB_ATTACK/XSS',tag:'WASCTC/WASC-8',tag:'WASCTC/WASC-22',tag:'OWASP_TOP_10/A2',tag:'OWASP_AppSensor/IE1',tag:'PCI/6.5.1',logdata:'% \
{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.xss_score=+%{tx.critical_anomaly_score},setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/XSS-%{matched_var_name}=%{tx.0}"
```

The tag information appears along with other rule metadata. The purpose of the tagging mechanism to allow easy automated categorization of events. Multiple tags can be specified on the same rule. Use forward slashes to create a hierarchy of categories (as in the example). The tag action includes support for macro expansion.

## ver
**Description:** Specifies the rule set version.

**Action Group:** Meta-data

**Example:**
```
SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "\bgetparentfolder\b" \
    "phase:2,ver:'CRS/2.2.4,capture,t:none,t:htmlEntityDecode,t:compressWhiteSpace,t:lowercase,ctl:auditLogParts=+E,block,msg:'Cross-site Scripting (XSS) Attack',id:'958016',tag:'WEB_ATTACK/XSS',tag:'WASCTC/WASC-8',tag:'WASCTC/WASC-22',tag:'OWASP_TOP_10/A2',tag:'OWASP_AppSensor/IE1',tag:'PCI/6.5.1',logdata:'% \
{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.xss_score=+%{tx.critical_anomaly_score},setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/XSS-%{matched_var_name}=%{tx.0}"
```

## xmlns
**Description:** Configures an XML namespace, which will be used in the execution of XPath expressions.

**Action Group:** Data

**Example:**
```
SecRule REQUEST_HEADERS:Content-Type "text/xml" "phase:1,id:147,pass,ctl:requestBodyProcessor=XML,ctl:requestBodyAccess=On, \
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
SecRule XML:/soap:Envelope/soap:Body/q1:getInput/id() "123" phase:2,deny,id:148
```

# Macro Expansion
Macros allow for using place holders in rules that will be expanded out to their values at runtime. Currently only variable expansion is supported, however more options may be added in future versions of ModSecurity.

Format:
```
%{VARIABLE}
%{COLLECTION.VARIABLE}
```
Macro expansion can be used in actions such as initcol, setsid, setuid, setvar, setenv, logdata. Operators that are evaluated at runtime support expansion and are noted above. Such operators include @beginsWith, @endsWith, @contains, @within and @streq. You can use macro expansion for operators that are "compiled" such @rx, etc. however you will have some impact in efficiency.

Some values you may want to expand include: TX, REMOTE_ADDR, USERID, HIGHEST_SEVERITY, MATCHED_VAR, MATCHED_VAR_NAME, MULTIPART_STRICT_ERROR, RULE, SESSION, USERID, among others.
