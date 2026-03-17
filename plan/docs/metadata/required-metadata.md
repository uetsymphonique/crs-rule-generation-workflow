# Required Metadata for CRS Rules

This document outlines the mandatory metadata attributes and tags required when writing rules for the OWASP Core Rule Set (CRS). This metadata is used for identification, logging, classification, and anomaly scoring.

---

## 1. Mandatory Metadata Fields

Every CRS rule (or the first rule in a `chain`) must include the following fields:

- **`id`**: A unique numerical identifier for the rule (e.g., `id:942100`). It must fall within the ID range designated for its specific attack category.
- **`phase`**: The processing phase where the rule executes (e.g., `phase:1` for Request Headers, `phase:2` for Request Body). Always specify this as a number, never use aliases.
- **`msg`**: A concise description of the attack type or the rule's purpose. This message appears in log files (e.g., `msg:'SQL Injection Attack Detected'`).
- **`logdata`**: Contains specific details about the matched payload to aid in forensic investigation (e.g., `logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}'`).
- **`severity`**: The severity level of the rule (e.g., `severity:'CRITICAL'`). This field maps directly to the anomaly score incremented via `setvar`.

---

## 2. Classification Tags

Tags are crucial in CRS. They are used for statistics, analysis, and allow administrators to easily disable groups of rules (via `ctl:ruleRemoveByTag`). Each rule must include the following standard tags:

### Context Tags
- `tag:'application-*'`: Specifies the target application type (e.g., `application-multi` for generic rules, or `application-php`, `application-nodejs`).
- `tag:'language-*'`: Specifies the target programming language (e.g., `language-multi`, `language-php`, `language-java`).
- `tag:'platform-*'`: Specifies the target platform or system configuration (e.g., `platform-multi`, `platform-windows`, `platform-mysql`).

### Attack Type Tags
- **General Category**: `tag:'attack-*'`
  Describes the broad category of the attack (e.g., `tag:'attack-sqli'`, `tag:'attack-xss'`, `tag:'attack-lfi'`, `tag:'attack-rce'`).
- **Specific Technique**: `tag:'attack-*/*'`
  Provides a detailed slug describing the specific technique or behavior (e.g., `tag:'attack-sqli/boolean-based'`, `tag:'attack-xss/stored'`, `tag:'attack-rce/cmd-injection'`).

### Paranoia Level & Inheritance Tags
Besides the basic tags above, the following two structural tags are **MANDATORY**:
- **`tag:'paranoia-level/x'`**: Defines the Paranoia Level (PL) of the rule (where `x` is 1, 2, 3, or 4). This rule will only execute if the system's global PL is set to `x` or higher. This tag is mandatory for any rule that logs an event.
- **`tag:'OWASP_CRS'`**: Identifies this rule as part of the official Core Rule Set.

---

## 3. Mapping Severity to Anomaly Score (`setvar`)

`severity` is not just a display label—it directly maps to the score added to the transaction's anomaly threshold evaluation (`setvar`).

Standard severity levels increase the transaction's accumulated score through global configuration variables (typically used in tandem, e.g., `setvar:'tx.attack-type_score=+%{tx.xxx_anomaly_score}'` and `setvar:'tx.inbound_anomaly_score_plX=+%{tx.xxx_anomaly_score}'`):

| Declared Severity | Corresponding Score Variable (`setvar`) | Default Score | Description |
| :--- | :--- | :--- | :--- |
| `severity:'CRITICAL'` | `%{tx.critical_anomaly_score}` | 5 | Confirmed, unambiguous attack payload. |
| `severity:'ERROR'` | `%{tx.error_anomaly_score}` | 4 | Highly likely to be an attack, but carries some risk of false positives (FP). |
| `severity:'WARNING'` | `%{tx.warning_anomaly_score}` | 3 | Suspicious behavior or pattern (moderate FP risk). |
| `severity:'NOTICE'` | `%{tx.notice_anomaly_score}` | 2 | Policy violation or minor anomaly. |

**Example of a standard rule utilizing Severity:**
```apache
SecRule ARGS "@detectSQLi" \
    "id:942100,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Injection detected',\
    logdata:'Matched Data: %{TX.0}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'attack-sqli/boolean-based',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    severity:'CRITICAL',\
    setvar:'tx.sqli_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```
