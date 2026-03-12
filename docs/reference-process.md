# Processing Phases
ModSecurity 3.x allows rules to be placed in one of the following five phases of HTTP request:
- Request headers (REQUEST_HEADERS)
- Request body (REQUEST_BODY)
- Response headers (RESPONSE_HEADERS)
- Response body (RESPONSE_BODY)
- Logging (LOGGING)

In order to select the phase a rule executes during, use the phase action in the rule or in the SecDefaultAction directive:
```
SecDefaultAction "log,pass,phase:2,id:4"
SecRule REQUEST_HEADERS:Host "!^$" "deny,phase:1,id:5"
```
> **Note:** The data available in each phase is cumulative.  This means that as you move onto later phases, you have access to more and more data from the transaction.
> **Note:** Keep in mind that rules are executed according to phases, so even if two rules are adjacent in a configuration file, but are set to execute in different phases, they would not happen one after the other. The order of rules in the configuration file is important only within the rules of each phase. This is especially important when using the skip and skipAfter actions.

> **Note:** The LOGGING phase is special. It is executed at the end of each transaction no matter what happened in the previous phases. This means it will be processed even if the request was intercepted or the allow action was used to pass the transaction through.
## Phase Request Headers
Rules in this phase are processed immediately after the request headers have been received. At this point the request body has not been read yet, meaning not all request arguments are available. Rules should be placed in this phase if you need to have them run early, to do something before the request body has been read, or decide how you want the request body to be processed (e.g. whether to parse it as XML or not).

## Phase Request Body
This is the general-purpose input analysis phase. Most of the application-oriented rules should go here. In this phase you are guaranteed to have received the request arguments (provided the request body has been read). ModSecurity supports four types of request body parsing:
- **application/x-www-form-urlencoded**
- **multipart/form-data**
- **xml**
- **JSON**

## Phase Response Headers
This phase takes place just before response headers are sent back to the client. Run here if you want to observe the response before that happens.

## Phase Response Body
This is the general-purpose output analysis phase. At this point you can run rules against the response body (provided it was buffered, of course). This is the phase where you would want to inspect the outbound HTML for information disclosure, error messages or failed authentication text.

> **Note:** In order to access the Response Body phase data, you must have SecResponseBodyAccess set to On

## Phase Logging
This phase is run just before logging takes place. The rules placed into this phase can only affect how the logging is performed. You cannot deny/block connections in this phase as it is too late.
