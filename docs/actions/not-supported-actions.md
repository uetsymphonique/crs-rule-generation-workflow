# Actions Not Supported in ModSecurity v3

The following actions exist in ModSecurity v2 but are **NOT supported in v3**.
Listed here for reference only — do not use in CRS rule generation.

## append

**Not supported in v3**

Description (v2): Appends the value of a variable to the output stream.

## deprecatevar

**Not supported in v3**

Description (v2): Removes and deprecates a rule variable from the transaction.

## pause

**Not supported in v3**

Description (v2): Pauses transaction processing for the specified number of milliseconds.

## prepend

**Not supported in v3**

Description (v2): Prepends the contents of a variable to the response body.

## proxy

**Not supported in v3**

Description (v2): Proxies the transaction to the given URL.

## sanitiseArg

**Not supported in v3**

Description (v2): Removes all matching arguments from the log.

## sanitiseMatched

**Not supported in v3**

Description (v2): Removes the matched string from the audit log.

## sanitiseMatchedBytes

**Not supported in v3**

Description (v2): Removes matched bytes from the audit log.

## sanitiseRequestHeader

**Not supported in v3**

Description (v2): Removes the specified request header from the log.

## sanitiseResponseHeader

**Not supported in v3**

Description (v2): Removes the specified response header from the log.

---

## Partially Unsupported: `ctl` sub-options

The `ctl` action itself is supported in v3, but the following sub-options are **not supported**:

- `ctl:debugLogLevel` - Not supported in ModSecurity v3
- `ctl:forceRequestBodyVariable` - Not implemented (REQUEST_BODY is always populated in v3)
- `ctl:requestBodyLimit` - Not supported in ModSecurity v3
- `ctl:responseBodyAccess` - Not supported in ModSecurity v3
- `ctl:responseBodyLimit` - Not supported in ModSecurity v3
- `ctl:ruleRemoveByMsg` - Not supported in ModSecurity v3
- `ctl:ruleRemoveTargetByMsg` - Not supported in ModSecurity v3
