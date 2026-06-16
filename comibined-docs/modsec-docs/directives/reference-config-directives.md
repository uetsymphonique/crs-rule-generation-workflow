# Configuration Directives
The following section outlines all of the ModSecurity directives. Most of the ModSecurity directives can be used inside the various Apache Scope Directives such as VirtualHost, Location, LocationMatch, Directory, etc... There are others, however, that can only be used once in the main configuration file. This information is specified in the Scope sections below. The first version to use a given directive is given in the Version sections below.

These rules, along with the Core rules files, should be contained in files outside of the httpd.conf file and called up with Apache "Include" directives. This allows for easier updating/migration of the rules. If you create your own custom rules that you would like to use with the Core rules, you should create a file called - modsecurity_crs_15_customrules.conf and place it in the same directory as the Core rules files. By using this file name, your custom rules will be called up after the standard ModSecurity Core rules configuration file but before the other Core rules. This allows your rules to be evaluated first which can be useful if you need to implement specific "allow" rules or to correct any false positives in the Core rules as they are applied to your site.

> **Note:** It is highly encouraged that you do not edit the Core rules files themselves but rather place all changes (such as SecRuleRemoveByID, etc...) in your custom rules file. This will allow for easier upgrading as newer Core rules are released.
## SecAction
**Description:** Unconditionally processes the action list it receives as the first and only parameter. The syntax of the parameter is identical to that of the third parameter of `SecRule`.

**Syntax:** `SecAction "action1,action2,action3,...“`

**Version:** 3.0.0

This directive is commonly used to set variables and initialize persistent collections using the initcol action. For example:
```
SecAction nolog,phase:1,initcol:RESOURCE=%{REQUEST_FILENAME}
```
## SecArgumentSeparator
**Description:** Specifies which character to use as the separator for application/x-www-form- urlencoded content.

**Syntax:** `SecArgumentSeparator character`

**Default:** & 

**Version:** 3.0.0

This directive is needed if a backend web application is using a nonstandard argument separator. Applications are sometimes (very rarely) written to use a semicolon separator. You should not change the default setting unless you establish that the application you are working with requires a different separator. If this directive is not set properly for each web application, then ModSecurity will not be able to parse the arguments appropriately and the effectiveness of the rule matching will be significantly decreased.

## SecArgumentsLimit
**Description:** Configures the maximum number of ARGS that will be accepted for processing.

**Syntax:** `SecArgumentsLimit LIMIT `

**Example Usage:** `SecArgumentsLimit 1000 `

**Version:** 3.0.5

**Default:** no limit

When using this setting, it is recommended to accompany it with a rule that will test for that same integer value and deny the request if it is reached. E.g.
```
SecRule &ARGS "@ge 1000" "id:'200007', phase:2,t:none,log,deny,status:400,msg: ...
```
Without such a matching rule, an attacker could potentially evade detection by placing the attack payload in a parameter occurring beyond the limit.

> **Project note:** In this project, audit logging directives (SecAuditEngine, SecAuditLog, SecAuditLogParts, etc.) and debug logging directives (SecDebugLog, SecDebugLogLevel, SecComponentSignature) are documented separately in `non-rule-directives.md` because they do not participate in rule evaluation.

## SecDefaultAction
**Description**: Defines the default list of actions for a particular phase, which will be inherited by the rules in the same phase and in the same configuration context.

**Syntax:** `SecDefaultAction "action1,action2,action3“ `

**Example Usage:** `SecDefaultAction "phase:2,log,auditlog,deny,status:403,tag:'SLA 24/7'“ `

**Version:** 3.0.0

**Default:** phase:2,log,auditlog,pass

Every rule following a previous `SecDefaultAction` directive in the same configuration context will inherit its settings unless more specific actions are used. Every `SecDefaultAction` directive must specify a disruptive action and a processing phase and cannot contain metadata actions.

> **Warning:** `SecDefaultAction` is not inherited across configuration contexts. (For an example of why this may be a problem, read the following ModSecurity Blog entry http://blog.spiderlabs.com/2008/07/three-modsecurity-rule-language-annoyances.html .)

## SecGeoLookupDb
**Description**: Defines the path to the database that will be used for geolocation lookups. 

**Syntax:** `SecGeoLookupDb /path/to/db `

**Example Usage**: `SecGeoLookupDB /path/to/GeoLite2-Country.mmdb`

ModSecurity v3 uses the newer GeoIP2 format from MaxMind <http://www.maxmind.com>.

> **Note:** Recent versions of ModSecurity require a MaxMind version >= 1.4.2
> **Note:** libmaxminddb-dev and libmaxminddb0 are used for this. Some users have reported difficulties if libgeoip-dev and libgeoip1 are also installed; it was found by the reporter that removing these latter packages resolved the problem (see issue #2829).

## SecHttpBlKey
**Description:** Configures the user's registered Honeypot Project HTTP BL API Key to use with @rbl.

**Syntax:** `SecHttpBlKey [12 char access key] `

**Example Usage:** `SecHttpBlKey whdkfieyhtnf `

**Scope:** Main 

If the @rbl operator uses the dnsbl.httpbl.org RBL (http://www.projecthoneypot.org/httpbl_api.php) you must provide an API key.  This key is registered to individual users and is included within the RBL DNS requests.

## SecMarker
**Description:** Adds a fixed rule marker that can be used as a target in a skipAfter action. A SecMarker directive essentially creates a rule that does nothing and whose only purpose is to carry the given ID.

**Syntax:** `SecMarker ID|TEXT `

**Example Usage**: `SecMarker 9999 `

The value can be either a number or a text string.  The SecMarker directive is available to allow you to choose the best way to implement a skip-over. Here is an example used from the Core Rule Set:
```
SecMarker BEGIN_HOST_CHECK

        SecRule &REQUEST_HEADERS:Host "@eq 0" \
                "skipAfter:END_HOST_CHECK,phase:2,rev:'2.1.1',t:none,block,msg:'Request Missing a Host Header',id:'960008',tag:'PROTOCOL_VIOLATION/MISSING_HEADER_HOST',tag:'WASCTC/WASC-21',tag:'OWASP_TOP_10/A7',tag:'PCI/6.5.10',severity:'5',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.notice_anomaly_score},setvar:tx.protocol_violation_score=+%{tx.notice_anomaly_score},setvar:tx.%{rule.id}-PROTOCOL_VIOLATION/MISSING_HEADER-%{matched_var_name}=%{matched_var}"
        SecRule REQUEST_HEADERS:Host "^$" \
                "phase:2,rev:'2.1.1',t:none,block,msg:'Request Missing a Host Header',id:'960008',tag:'PROTOCOL_VIOLATION/MISSING_HEADER_HOST',tag:'WASCTC/WASC-21',tag:'OWASP_TOP_10/A7',tag:'PCI/6.5.10',severity:'5',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.notice_anomaly_score},setvar:tx.protocol_violation_score=+%{tx.notice_anomaly_score},setvar:tx.%{rule.id}-PROTOCOL_VIOLATION/MISSING_HEADER-%{matched_var_name}=%{matched_var}"

SecMarker END_HOST_CHECK
```

## SecParseXmlIntoArgs
**Description:** Controls how XML processing is done. If you turn it on with `On` or `OnlyArgs`, then XML nodes will 
appear in `ARGS`. In these cases, the <a href="./Reference-Manual-(v3.x)#user-content-SecArgumentsLimit>SecArgumentsLimit</a> directive will set the limit to number of loadable arguments.

**Syntax:** `SecParseXmlIntoArgs Off|On|OnlyArgs `

**Example Usage:** `SecParseXmlIntoArgs Off`

**Scope:** Any 

**Version:** 3.0.15

**Default:** default is `Off`

**NOTE:** You must enable this directive with `On` or `OnlyArgs` if you want to load XML nodes into `ARGS`.

This is an optional directive that allow the user to load XML payload's nodes into `ARGS` (and XML tags into `ARGS_NAMES`). The default value is `Off`. If the user set it to `On` then XML nodes will appear in `ARGS` collection with key `xml.tag.chain`, but the `XML` target will fill too. If the value is `OnlyArgs`, then `XML` will be empty. Notice that in this case the <a href="./Reference-Manual-(v3.x)#validatedtd">@validateDTD</a> and <a href="./Reference-Manual-(v3.x)#validateSchema">@validateSchema</a> operators will return with false value (because the `XML` target is empty).

<a href="./Reference-Manual-(v3.x)#ctl">`ctl:parseXmlIntoArgs`</a> action's behavior is the same, you can control it during the transaction.

<b>Example</b>
Consider the XML payload:
<code>
<?xml version="1.0" encoding="UTF-8"?>
<root>
    <level1>
        <level2>foo</level2>
        <level2>bar</level2>
    </level1>
</root>
</code>

This payload will generate value for `XML` target like this:
`            foo        bar    `.

If you turn on this feature, the nodes will apear under `ARGS`:

<code>Adding XML argument 'xml.root.level1.level2' with value 'foo'
Adding XML argument 'xml.root.level1.level2' with value 'bar'</code>

(These lines are from debug.log)

## SecPcreMatchLimit
**Description:** Sets the PCRE match limit for executions of the @rx and @rxGlobal operators.

**Syntax:** `SecPcreMatchLimit value `

**Example Usage**: `SecPcreMatchLimit 1500 `

**Version**: 3.0.10

If the configured limit is exceeded, the variable MSC_PCRE_LIMITS_EXCEEDED will be set.

## SecRemoteRules
**Description**: Load rules from a given file hosted on a HTTPS site.

**Syntax:** `SecRemoteRules key https://url `

**Example Usage**: `SecRemoteRules some-key https://www.yourserver.com/plain-text-rules.txt`

This is an optional directive that allows the user to load rules from a remote server. Notice that besides the URL the user also needs to supply a key, which could be used by the target server to provide different content for different keys. 

Along with the key, supplied by the users, ModSecurity will also send its Unique ID and the `status call' in the format of headers to the target web server. The following headers are used:
 - ModSec-status
 - ModSec-unique-id
 - ModSec-key

> **Note:** A valid and trusted digital certificate is expected on the end server. It is also expected that the server uses TLS, preferable TLS 1.2. 

## SecRemoteRulesFailAction
**Description**: Action that will be taken if SecRemoteRules specify an URL that ModSecurity was not able to download.

**Syntax:** `SecRemoteRulesFailAction Abort|Warn `

**Example Usage**: `SecRemoteRulesFailAction Abort`

The default action is to Abort whenever there is a problem downloading a given URL.

## SecRequestBodyAccess
**Description**: Configures whether request bodies will be buffered and processed by ModSecurity.

**Syntax:** `SecRequestBodyAccess On|Off `

**Example Usage**: `SecRequestBodyAccess On`

This directive is required if you want to inspect the data transported request bodies (e.g., POST parameters). Request buffering is also required in order to make reliable blocking possible.  The possible values are:
- On: buffer request bodies
- Off: do not buffer request bodies

## SecRequestBodyJsonDepthLimit
**Description:** Configures the maximum parsing depth that is allowed when parsing a JSON object.

**Syntax:** `SecRequestBodyJsonDepthLimit LIMIT `

**Example Usage:** `SecRequestBodyJsonDepthLimit 100 `

**Version:** 3.0.6

**Default:** 10000 

During parsing of a JSON object, if nesting exceeds the configured depth limit then parsing will halt and REQBODY_ERROR will be set.

## SecRequestBodyLimit
**Description:** Configures the maximum request body size ModSecurity will accept for buffering.

**Syntax:** `SecRequestBodyLimit LIMIT_IN_BYTES `

**Example Usage:** `SecRequestBodyLimit 134217728 `

**Default:** 134217728 (131072 KB) 

Anything over the limit will be rejected with status code 413 (Request Entity Too Large). There is a hard limit of 1 GB.

## SecRequestBodyNoFilesLimit
**Description**: Configures the maximum request body size ModSecurity will accept for buffering, excluding the size of any files being transported in the request. This directive is useful to reduce susceptibility to DoS attacks when someone is sending request bodies of very large sizes. Web applications that require file uploads must configure SecRequestBodyLimit to a high value, but because large files are streamed to disk, file uploads will not increase memory consumption. However, it’s still possible for someone to take advantage of a large request body limit and send non-upload requests with large body sizes. This directive eliminates that loophole.

**Syntax:** `SecRequestBodyNoFilesLimit NUMBER_IN_BYTES `

**Example Usage:** `SecRequestBodyNoFilesLimit 131072 `

**Default:** 1048576 (1 MB)

Generally speaking, the default value is not small enough. For most applications, you should be able to reduce it down to 128 KB or lower. Anything over the limit will be rejected with status code 413 (Request Entity Too Large). There is a hard limit of 1 GB.

## SecRequestBodyLimitAction
**Description**: Controls what happens once a request body limit, configured with SecRequestBodyLimit, is encountered

**Syntax:** `SecRequestBodyLimitAction Reject|ProcessPartial `

**Example Usage:** `SecRequestBodyLimitAction ProcessPartial`

**Version**: 3.0.0

By default, ModSecurity will reject a request body that is longer than specified.  This is problematic especially when ModSecurity is being run in DetectionOnly mode and the intent is to be totally passive and not take any disruptive actions against the transaction. With the ability to choose what happens once a limit is reached, site administrators can choose to inspect only the first part of the request, the part that can fit into the desired limit, and let the rest through.  This is not ideal from a possible evasion issue perspective, however it may be acceptable under certain circumstances.

> **Note:** When the SecRuleEngine is set to DetectionOnly, SecRequestBodyLimitAction is automatically set to ProcessPartial in order to not cause any disruptions.  If you want to know if/when a request body size is over your limit, you can create a rule to check for the existence of the INBOUND_DATA_ERROR variable.

## SecResponseBodyLimit
**Description:** Configures the maximum response body size that will be accepted for buffering.

**Syntax:** `SecResponseBodyLimit LIMIT_IN_BYTES `

**Example Usage:** `SecResponseBodyLimit 524228 `

**Default**: 524288 (512 KB)

Anything over this limit will be rejected. This setting will not affect the responses with MIME types that are not selected for buffering. There is a hard limit of 1 GB.

## SecResponseBodyLimitAction
**Description:** Controls what happens once a response body limit, configured with SecResponseBodyLimit, is encountered. 

**Syntax:** `SecResponseBodyLimitAction Reject|ProcessPartial `

**Example Usage:** `SecResponseBodyLimitAction ProcessPartial `

By default, ModSecurity will reject a response body that is longer than specified. Some web sites, however, will produce very long responses, making it difficult to come up with a reasonable limit. Such sites would have to raise the limit significantly to function properly, defying the purpose of having the limit in the first place (to control memory consumption). With the ability to choose what happens once a limit is reached, site administrators can choose to inspect only the first part of the response, the part that can fit into the desired limit, and let the rest through. Some could argue that allowing parts of responses to go uninspected is a weakness. This is true in theory, but applies only to cases in which the attacker controls the output (e.g., can make it arbitrary long). In such cases, however, it is not possible to prevent leakage anyway. The attacker could compress, obfuscate, or even encrypt data before it is sent back, and therefore bypass any monitoring device.

## SecResponseBodyMimeType
**Description:** Configures which MIME types are to be considered for response body buffering. 

**Syntax:** `SecResponseBodyMimeType MIMETYPE MIMETYPE ... `

**Example Usage**: `SecResponseBodyMimeType text/plain text/html text/xml`

**Default:** text/plain text/html

Multiple SecResponseBodyMimeType directives can be used to add MIME types. Use SecResponseBodyMimeTypesClear to clear previously configured MIME types and start over.

## SecResponseBodyMimeTypesClear
**Description:** Clears the list of MIME types considered for response body buffering, allowing you to start populating the list from scratch.

**Syntax:** `SecResponseBodyMimeTypesClear `

**Example Usage:** `SecResponseBodyMimeTypesClear `

## SecResponseBodyAccess
**Description:** Configures whether response bodies are to be buffered. 

**Syntax:** `SecResponseBodyAccess On|Off `

**Example Usage:** `SecResponseBodyAccess On `

**Default:** Off

This directive is required if you plan to inspect HTML responses and implement response blocking.  Possible values are: 
- On: buffer response bodies (but only if the response MIME type matches the list configured with SecResponseBodyMimeType). 
- Off: do not buffer response bodies.

## SecRule
**Description:** Creates a rule that will analyze the selected variables using the selected operator. 

**Syntax:** `SecRule VARIABLES OPERATOR [ACTIONS] `

**Example Usage:** `SecRule ARGS "@rx attack" "phase:1,log,deny,id:1" `

Every rule must provide one or more variables along with the operator that should be used to inspect them. If no actions are provided, the default list will be used. (There is always a default list, even if one was not explicitly set with SecDefaultAction.) If there are actions specified in a rule, they will be merged with the default list to form the final actions that will be used. (The actions in the rule will overwrite those in the default list.) Refer to SecDefaultAction for more information.

## SecRuleEngine
**Description:** Configures the rules engine. 

**Syntax:** `SecRuleEngine On|Off|DetectionOnly`

**Example Usage:** `SecRuleEngine On `

**Default:** Off

The possible values are: 
- **On**: process rules
- **Off**: do not process rules 
- **DetectionOnly**: process rules but never executes any disruptive actions (block, deny, drop, allow, proxy and redirect)

> **Note:** The manual text here still lists `proxy`, but the actions reference marks `proxy` as not supported in ModSecurity v3.

## SecRuleRemoveById
**Description:** Removes the matching rules from the current configuration context. 

**Syntax:** `SecRuleRemoveById ID ID RANGE ... `

**Example Usage:** `SecRuleRemoveByID 1 2 9000-9010 `

This directive supports multiple parameters, each of which can be a rule ID or a range.

## SecRuleRemoveByMsg
**Description:** Removes the matching rules from the current configuration context. 

**Syntax:** `SecRuleRemoveByMsg TEXT `

**Example Usage:** `SecRuleRemoveByMsg FAIL `

Normally, you would use SecRuleRemoveById to remove rules, but this directive supports removal by matching against the rule's msg action. Matching is by case-sensitive string equality.

> **Note:** This functionality differs from ModSecurity v2, where matching is performed by a regular expression.

## SecRuleRemoveByTag
**Description:** Removes the matching rules from the current configuration context. 

**Syntax:** `SecRuleRemoveByTag TEXT `

**Example Usage:** `SecRuleRemoveByTag attack-dos `

Normally, you would use SecRuleRemoveById to remove rules, but it may occasionally be easier to disable an entire group of rules with SecRuleRemoveByTag. Matching is by case-sensitive string equality.

> **Note:** This functionality differs from ModSecurity v2, where matching is performed by a regular expression.

## SecRuleScript
Description: This directive creates a special rule that executes a Lua script to decide whether to match or not. The main difference from SecRule is that there are no targets nor operators. The script can fetch any variable from the ModSecurity context and use any (Lua) operator to test them. The second optional parameter is the list of actions whose meaning is identical to that of SecRule.

**Syntax:** `SecRuleScript /path/to/script.lua [ACTIONS]`

**Example Usage:** `SecRuleScript "/path/to/file.lua" "id:2,block"`

> **Note:** Although the software does not enforce including the 'id' action, including it is strongly advised. Omitting an id can cause problems.
> **Note:** All Lua scripts are compiled at configuration time and cached in memory. To reload scripts you must reload the entire ModSecurity configuration.

Example script:
```
-- Your script must define the main entry
-- point, as below.
function main()
    -- Log something at level 1. Normally you shouldn't be
    -- logging anything, especially not at level 1, but this is
    -- just to show you can. Useful for debugging.
    m.log(1, "Hello world!");

    -- Retrieve one variable.
    local var1 = m.getvar("REMOTE_ADDR");

    -- Retrieve one variable, applying one transformation function.
    -- The second parameter is a string.
    local var2 = m.getvar("ARGS", "lowercase");

    -- Retrieve one variable, applying several transformation functions.
    -- The second parameter is now a list. You should note that m.getvar()
    -- requires the use of comma to separate collection names from
    -- variable names. This is because only one variable is returned.
    local var3 = m.getvar("ARGS.p", { "lowercase", "compressWhitespace" } );

    -- If you want this rule to match return a string
    -- containing the error message. The message must contain the name
    -- of the variable where the problem is located.
    -- return "Variable ARGS:p looks suspicious!"

    -- Otherwise, simply return nil.
    return nil;
end
```
In this first example we were only retrieving one variable at the time. In this case the name of the variable is known to you. In many cases, however, you will want to examine variables whose names you won't know in advance, for example script parameters.

Example showing use of m.getvars() to retrieve many variables at once:
```
function main()
    -- Retrieve script parameters.
    local d = m.getvars("ARGS", { "lowercase", "htmlEntityDecode" } );

    -- Loop through the parameters.
    for i = 1, #d do
        -- Examine parameter value.
        if (string.find(d[i].value, "<script")) then
            -- Always specify the name of the variable where the
            -- problem is located in the error message.
            return ("Suspected XSS in variable " .. d[i].name .. ".");
        end
    end

    -- Nothing wrong found.
    return nil;
end
```
> **Note:** Go to http://www.lua.org/ to find more about the Lua programming language. The reference manual too is available online, at http://www.lua.org/manual/5.2/.

> **Note:** Lua support is marked as experimental as the way the programming interface may continue to evolve while we are working for the best implementation style. Any user input into the programming interface is appreciated.

> **Note:** ModSecurity v3 is compatible with Lua 5.2+.

## SecRuleUpdateActionById
**Description:** Updates the action list of the specified rule.

**Syntax:** `SecRuleUpdateActionById RULEID ACTIONLIST`

**Example Usage:** `SecRuleUpdateActionById 12345 "deny,status:403"`

This directive will overwrite the action list of the specified rule with the actions provided in the second parameter. It has two limitations: it cannot be used to change the ID or phase of a rule. Only the actions that can appear only once are overwritten. The actions that are allowed to appear multiple times in a list, will be appended to the end of the list.
```
SecRule ARGS attack "phase:2,id:12345,t:lowercase,log,pass,msg:'Message text'"
SecRuleUpdateActionById 12345 "t:none,t:compressWhitespace,deny,status:403,msg:'New message text'"
```
The effective resulting rule in the previous example will be as follows:
```
SecRule ARGS attack "phase:2,id:12345,t:lowercase,t:none,t:compressWhitespace,deny,status:403,msg:'New Message text'"
```
The addition of t:none will neutralize any previous transformation functions specified (t:lowercase, in the example).

> **Note:** If the target rule is a chained rule, action updates may only be made to the main (first) rule in the chain.

## SecRuleUpdateTargetById
**Description:** Updates the target (variable) list of the specified rule.

**Syntax:** `SecRuleUpdateTargetById RULEID TARGET1[,TARGET2,TARGET3] `

**Example Usage:** `SecRuleUpdateTargetById 12345 "!ARGS:foo"`

This directive will append (or replace) variables to the current target list of the specified rule with the targets provided in the second parameter.

**Explicitly Appending Targets**

This is useful for implementing exceptions where you want to externally update a target list to exclude inspection of specific variable(s).
```
SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "[\;\|\`]\W*?\bmail\b" \
     "phase:2,rev:'2.1.1',capture,t:none,t:htmlEntityDecode,t:compressWhitespace,t:lowercase,ctl:auditLogParts=+E,block,msg:'System Command Injection',id:'958895',tag:'WEB_ATTACK/COMMAND_INJECTION',tag:'WASCTC/WASC-31',tag:'OWASP_TOP_10/A1',tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.command_injection_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/COMMAND_INJECTION-%{matched_var_name}=%
{tx.0}"

SecRuleUpdateTargetById 958895 !ARGS:email
```
The effective resulting rule in the previous example will append the target to the end of the variable list as follows:
```
SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/*|!ARGS:email "[\;\|\`]\W*?\bmail\b" \
     "phase:2,capture,t:none,t:htmlEntityDecode,t:compressWhitespace,t:lowercase,ctl:auditLogParts=+E,block,msg:'System Command Injection',id:'958895',tag:'WEB_ATTACK/COMMAND_INJECTION',tag:'WASCTC/WASC-31',tag:'OWASP_TOP_10/A1',tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.command_injection_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/COMMAND_INJECTION-%{matched_var_name}=%
{tx.0}""
```

Note that is is also possible to use regular expressions in the target specification:

```
SecRuleUpdateTargetById 981172 "!REQUEST_COOKIES:/^appl1_.*/"
SecRuleUpdateTargetById 981173 "!REQUEST_COOKIES:'/^(appl1_.*|foo_.*)/'"
```

Please note that if you want to use grouping in your regular expression, you must enclose it in single quotes.

**Explicitly Replacing Targets**

You can also replace a target to something more appropriate for your environment.  For example, let's say you want to inspect REQUEST_URI instead of REQUEST_FILENAME, you could do this:
```
SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "[\;\|\`]\W*?\bmail\b" \
     "phase:2,capture,t:none,t:htmlEntityDecode,t:compressWhitespace,t:lowercase,ctl:auditLogParts=+E,block,msg:'System Command Injection',id:'958895',tag:'WEB_ATTACK/COMMAND_INJECTION',tag:'WASCTC/WASC-31',tag:'OWASP_TOP_10/A1',tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.command_injection_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/COMMAND_INJECTION-%{matched_var_name}=%
{tx.0}"

SecRuleUpdateTargetById 958895 !REQUEST_FILENAME,REQUEST_URI
```
The effective resulting rule in the previous example replaces the target in the begin of the variable list as follows:
```
SecRule REQUEST_URI|ARGS_NAMES|ARGS|XML:/* "[\;\|\`]\W*?\bmail\b" \
     "phase:2,capture,t:none,t:htmlEntityDecode,t:compressWhitespace,t:lowercase,ctl:auditLogParts=+E,block,msg:'System Command Injection',id:'958895',tag:'WEB_ATTACK/COMMAND_INJECTION',tag:'WASCTC/WASC-31',tag:'OWASP_TOP_10/A1',tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.command_injection_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/COMMAND_INJECTION-%{matched_var_name}=%
{tx.0}""
```

> **Note:** You could also do the same by using the ctl action with the ruleRemoveById directive. That would be useful if you want to only update the targets for a particular URL, thus conditionally appending targets.

## SecRuleUpdateTargetByMsg
**Description:** Updates the target (variable) list of the specified rule(s) by rule message.

**Syntax:** `SecRuleUpdateTargetByMsg TEXT TARGET1[,TARGET2,TARGET3] `

**Example Usage:** `SecRuleUpdateTargetByMsg "Cross-site Scripting (XSS) Attack" "!ARGS:foo"`

This directive will append (or replace) variables to the current target list of the specified rule with the targets provided in the second parameter.

**Explicitly Appending Targets**

This is useful for implementing exceptions where you want to externally update a target list to exclude inspection of specific variable(s).
```
SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "[\;\|\`]\W*?\bmail\b" \
     "phase:2,capture,t:none,t:htmlEntityDecode,t:compressWhitespace,t:lowercase,ctl:auditLogParts=+E,block,msg:'System Command Injection',id:'958895',tag:'WEB_ATTACK/COMMAND_INJECTION',tag:'WASCTC/WASC-31',tag:'OWASP_TOP_10/A1',tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.command_injection_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/COMMAND_INJECTION-%{matched_var_name}=%
{tx.0}"

SecRuleUpdateTargetByMsg "System Command Injection" !ARGS:email
```
The effective resulting rule in the previous example will append the target to the end of the variable list as follows:
```
SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/*|!ARGS:email "[\;\|\`]\W*?\bmail\b" \
     "phase:2,capture,t:none,t:htmlEntityDecode,t:compressWhitespace,t:lowercase,ctl:auditLogParts=+E,block,msg:'System Command Injection',id:'958895',tag:'WEB_ATTACK/COMMAND_INJECTION',tag:'WASCTC/WASC-31',tag:'OWASP_TOP_10/A1',tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.command_injection_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/COMMAND_INJECTION-%{matched_var_name}=%
{tx.0}""
```
**Explicitly Replacing Targets**

You can also entirely replace the target list to something more appropriate for your environment.  For example, lets say you want to inspect REQUEST_URI instead of REQUEST_FILENAME, you could do this:
```
SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "[\;\|\`]\W*?\bmail\b" \
     "phase:2,capture,t:none,t:htmlEntityDecode,t:compressWhitespace,t:lowercase,ctl:auditLogParts=+E,block,msg:'System Command Injection',id:'958895',tag:'WEB_ATTACK/COMMAND_INJECTION',tag:'WASCTC/WASC-31',tag:'OWASP_TOP_10/A1',tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.command_injection_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/COMMAND_INJECTION-%{matched_var_name}=%
{tx.0}"

SecRuleUpdateTargetByMsg "System Command Injection" !REQUEST_FILENAME|REQUEST_URI
```
The effective resulting rule in the previous example will append the target to the end of the variable list as follows:
```
SecRule REQUEST_URI|ARGS_NAMES|ARGS|XML:/* "[\;\|\`]\W*?\bmail\b" \
     "phase:2,capture,t:none,t:htmlEntityDecode,t:compressWhitespace,t:lowercase,ctl:auditLogParts=+E,block,msg:'System Command Injection',id:'958895',tag:'WEB_ATTACK/COMMAND_INJECTION',tag:'WASCTC/WASC-31',tag:'OWASP_TOP_10/A1',tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.command_injection_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/COMMAND_INJECTION-%{matched_var_name}=%
{tx.0}""
```

## SecRuleUpdateTargetByTag
**Description:** Updates the target (variable) list of the specified rule(s) by rule tag.

**Syntax:** `SecRuleUpdateTargetByTag TEXT TARGET1[,TARGET2,TARGET3] `

**Example Usage:** `SecRuleUpdateTargetByTag "WEB_ATTACK/XSS" "!ARGS:foo"`

This directive will append (or replace) variables to the current target list of the specified rule with the targets provided in the second parameter.

**Explicitly Appending Targets**

This is useful for implementing exceptions where you want to externally update a target list to exclude inspection of specific variable(s).
```
SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "[\;\|\`]\W*?\bmail\b" \
     "phase:2,capture,t:none,t:htmlEntityDecode,t:lowercase,ctl:auditLogParts=+E,block,msg:'System Command Injection',id:'958895',tag:'WEB_ATTACK/COMMAND_INJECTION',tag:'WASCTC/WASC-31',tag:'OWASP_TOP_10/A1',tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.command_injection_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/COMMAND_INJECTION-%{matched_var_name}=%
{tx.0}"

SecRuleUpdateTargetByTag "WASCTC/WASC-31" !ARGS:email
```
The effective resulting rule in the previous example will append the target to the end of the variable list as follows:
```
SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/*|!ARGS:email "[\;\|\`]\W*?\bmail\b" \
     "phase:2,capture,t:none,t:htmlEntityDecode,t:compressWhitespace,t:lowercase,ctl:auditLogParts=+E,block,msg:'System Command Injection',id:'958895',tag:'WEB_ATTACK/COMMAND_INJECTION',tag:'WASCTC/WASC-31',tag:'OWASP_TOP_10/A1',tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.command_injection_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/COMMAND_INJECTION-%{matched_var_name}=%
{tx.0}""
```
**Explicitly Replacing Targets**

You can also entirely replace the target list to something more appropriate for your environment.  For example, lets say you want to inspect REQUEST_URI instead of REQUEST_FILENAME, you could do this:
```
SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "[\;\|\`]\W*?\bmail\b" \
     "phase:2,capture,t:none,t:htmlEntityDecode,t:compressWhitespace,t:lowercase,ctl:auditLogParts=+E,block,msg:'System Command Injection',id:'958895',tag:'WEB_ATTACK/COMMAND_INJECTION',tag:'WASCTC/WASC-31',tag:'OWASP_TOP_10/A1',tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.command_injection_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/COMMAND_INJECTION-%{matched_var_name}=%
{tx.0}"

SecRuleUpdateTargetByTag "WASCTC/WASC-31" !REQUEST_FILENAME|REQUEST_URI
```
The effective resulting rule in the previous example will append the target to the end of the variable list as follows:
```
SecRule REQUEST_URI|ARGS_NAMES|ARGS|XML:/* "[\;\|\`]\W*?\bmail\b" \
     "phase:2,capture,t:none,t:htmlEntityDecode,t:compressWhitespace,t:lowercase,ctl:auditLogParts=+E,block,msg:'System Command Injection',id:'958895',tag:'WEB_ATTACK/COMMAND_INJECTION',tag:'WASCTC/WASC-31',tag:'OWASP_TOP_10/A1',tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.command_injection_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/COMMAND_INJECTION-%{matched_var_name}=%
{tx.0}""
```
## SecUnicodeMapFile
**Description:** Defines the path to the file that will be used by the urlDecodeUni transformation function to map Unicode code points during normalization and specifies the Code Point to use.

**Syntax:** `SecUnicodeMapFile /path/to/unicode.mapping CODEPOINT`

**Example Usage:** `SecUnicodeMapFile ./unicode.mapping 20127`

> **Note:** You may need to place the unicode.mapping file in the same directory where the modsecurity.conf file is located.

## SecUploadDir
**Description:** Configures the directory where intercepted files will be stored.

**Syntax:** `SecUploadDir /path/to/dir`

**Example Usage:** `SecUploadDir /tmp`

This directory must be on the same filesystem as the temporary directory defined with SecTmpDir. This directive is used with SecUploadKeepFiles.

## SecUploadFileLimit
**Description:** Configures the maximum number of file uploads processed in a multipart POST.

**Syntax:** `SecUploadFileLimit number`

**Example Usage:** `SecUploadFileLimit 10`

The default is set to 100 files, but you are encouraged to reduce this value. Any file over the limit will not be extracted and the MULTIPART_FILE_LIMIT_EXCEEDED and MULTIPART_STRICT_ERROR flags will be set. To prevent bypassing any file checks, you must check for one of these flags.

> **Note:** If the limit is exceeded, the part name and file name will still be recorded in FILES_NAME and FILES, the file size will be recorded in FILES_SIZES, but there will be no record in FILES_TMPNAMES as a temporary file was not created.

## SecUploadFileMode
**Description:** Configures the mode (permissions) of any uploaded files using an octal mode (as used in chmod).

**Syntax:** `SecUploadFileMode octal_mode`

**Example Usage:** `SecUploadFileMode 0640`

**Default:** 0600

This feature is not available on operating systems not supporting octal file modes. The default mode (0600) only grants read/write access to the account writing the file. If access from another account is needed, then this directive may be required. However, use this directive with caution to avoid exposing potentially sensitive data to unauthorized users.

> **Note:** The process umask may still limit the mode if it is being more restrictive than the mode set using this directive.

## SecUploadKeepFiles
**Description:** Configures whether or not the intercepted files will be kept after transaction is processed.

**Syntax:** `SecUploadKeepFiles On|Off`

**Example Usage:** `SecUploadKeepFiles On`

This directive requires the storage directory to be defined (using SecUploadDir).

Possible values are:

- **On** - Keep uploaded files.
- **Off** - Do not keep uploaded files.

> **Note:** The syntax above documents `On|Off`. Some older manual text still mentions `RelevantOnly`; treat that as a documentation inconsistency rather than a valid value for `SecUploadKeepFiles`.

## SecWebAppId
**Description:** Creates an application namespace, allowing for separate persistent session and user storage.

**Syntax:** `SecWebAppId "NAME" `

**Example Usage:** `SecWebAppId "WebApp1" `

**Default:** default

Application namespaces are used to avoid collisions between session IDs and user IDs when multiple applications are deployed on the same server. If it isn’t used, a collision between session IDs might occur.
```
server { 
    linsten 80;
    server_name app1.example.com 
    modsecurity_rules 'SecWebAppId "App1"';
    ... 
}

server { 
    linsten 80;
    server_name app2.example.com 
    modsecurity_rules 'SecWebAppId "App2"';
    ... 
}
```
In the two examples configurations shown, SecWebAppId is being used in conjunction with the nginx server blocks. The configured value is available in the WEBAPPID variable.

## SecXmlExternalEntity
**Description:** Enable or Disable the loading process of xml external entity. Loading external entity without correct verifying process can lead to a security issue.

**Syntax:** `SecXmlExternalEntity On|Off `

**Example Usage:** `SecXmlExternalEntity Off `

**Default:** default is Off

**NOTE:** You must enable this directive if you need to use the `@validateSchema` or `@validateDtd` operators.
