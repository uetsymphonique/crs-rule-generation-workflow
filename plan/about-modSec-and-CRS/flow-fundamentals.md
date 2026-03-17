# ModSecurity & CRS — Request Processing Flow Fundamentals

## 1. Overview

ModSecurity is a **Web Application Firewall (WAF) engine** that inspects HTTP transactions in multiple processing **phases**. Rules are attached to a phase with the `phase` action and only run when the corresponding data is available.

The **OWASP Core Rule Set (CRS)** is a rule set that runs on top of ModSecurity. In the CRS documentation, two ideas are central:

- **Paranoia level** controls how many rules are enabled.
- **Anomaly scoring** controls when a transaction is blocked.

Together, they form a phased inspection pipeline:

```text
Client request
  -> Phase 1: Request headers
  -> Phase 2: Request body
  -> Backend application
  -> Phase 3: Response headers
  -> Phase 4: Response body
  -> Phase 5: Logging
  -> Client response
```

---

## 2. ModSecurity Processing Phases

The ModSecurity v3 manual defines **five phases**:

### Phase 1 — Request Headers
- Runs immediately after request headers are received.
- The request body is not yet available.
- Typical use: method checks, URI/header validation, deciding how the body should be parsed.

### Phase 2 — Request Body
- General-purpose input analysis phase.
- Request parameters and body content are available after buffering/parsing.
- Typical use: most attack-detection rules.

> **Note:** To inspect request bodies, `SecRequestBodyAccess On` must be enabled.

### Phase 3 — Response Headers
- Runs just before response headers are sent.
- Typical use: inspect response status and response headers.

### Phase 4 — Response Body
- General-purpose output analysis phase.
- Typical use: inspect response body content such as error messages or leaked data.

> **Note:** To inspect response bodies, `SecResponseBodyAccess On` must be enabled.

### Phase 5 — Logging
- Runs just before logging.
- Too late to block or deny the transaction.
- Used only to influence logging behavior.

---

## 3. CRS Anomaly Scoring

The CRS documentation describes CRS as an **anomaly scoring** rule set. Detection rules typically do not block immediately. Instead, they add to a transaction score using `setvar`, and blocking happens later in dedicated evaluation files.

At a high level:

1. Execute request rules.
2. Compare the **inbound** anomaly score to the inbound threshold.
3. Execute response rules.
4. Compare the **outbound** anomaly score to the outbound threshold.

The CRS docs identify these evaluation files:

- `REQUEST-949-BLOCKING-EVALUATION.conf`
- `RESPONSE-959-BLOCKING-EVALUATION.conf`

The CRS docs also emphasize that inbound and outbound scoring are separate, with default thresholds of:

- inbound: `5`
- outbound: `4`

---

## 4. Paranoia Levels

The CRS documentation makes a clear distinction between **paranoia level** and **anomaly score threshold**:

- **Paranoia level** determines how many rules run.
- **Anomaly threshold** determines how many rule matches are needed before blocking.

In native CRS installations, the paranoia level is configured via `tx.paranoia_level` in `crs-setup.conf`.

The CRS docs further explain the idea of an **executing paranoia level**: higher-level rules can be executed for observation and tuning without necessarily contributing to blocking decisions in the same way as the active blocking level.

---

## 5. Rule Flow Control in CRS

The ModSecurity manual defines `chain`, `skip`, `skipAfter`, and `SecMarker` as core flow-control tools. CRS uses these heavily to organize rules and gate rule groups.

### Chain

`chain` creates a logical AND across adjacent rules:

```apache
SecRule REQUEST_METHOD "^POST$" "phase:1,chain,t:none,id:1000"
    SecRule &REQUEST_HEADERS:Content-Length "@eq 0" "t:none"
```

Only the chain starter may carry disruptive actions, `id`, `phase`, and other metadata actions.

### skipAfter and SecMarker

`skipAfter` jumps forward to a marker created by `SecMarker`:

```apache
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" \
    "id:942013,phase:2,pass,nolog,skipAfter:END-REQUEST-942-SQLI"

# ... rules skipped when PL < 2 ...

SecMarker "END-REQUEST-942-SQLI"
```

This is the basic mechanism CRS uses to gate rule sections by paranoia level.

---

## 6. Practical Reading Order

For understanding how request processing works in this project, the most useful references are:

1. `docs/reference-process.md` for the five phases.
2. `about-modSec-and-CRS/rule-dev.md` for CRS-oriented rule writing.
3. `docs/variables/reference-variables.md` for what data is available in each phase.
4. `docs/actions/reference-actions.md` for flow-control and scoring actions such as `phase`, `setvar`, `chain`, `skip`, and `skipAfter`.
