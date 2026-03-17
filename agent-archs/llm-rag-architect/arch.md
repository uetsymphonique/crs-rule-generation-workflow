# LLM RAG Architect

## Goal

Input: `Nuclei templates`  
Output: `1..N recommended SecRule` definitions to detect the behavior described by the template, along with a short trace explaining the rule-design logic.

## High-Level Architecture

The proposed architecture uses `1 orchestrator + 2 specialist agents`:

1. `Orchestrator`
   - Parses and normalizes the Nuclei template into a `DetectionSpec`
   - Decides whether to use the `fast path` or the `full path`
   - Selects the most suitable `attack family` for rule design
   - Produces the final output: `SecRule + short trace`

2. `Agent 1 - IntentExtractor`
   - Understands what attack behavior the template is actually describing
   - Extracts observable signals, constraints, and false-positive risks
   - Determines whether detection should use a single rule, multiple rules, or may require `chain`

3. `Agent 2 - RuleDesigner`
   - Uses RAG over the ModSecurity/CRS documentation to convert `DetectionSpec` into `SecRule`
   - Must explicitly resolve all 4 parts of a `SecRule`:
     - `variables`
     - `operator`
     - `transformations`
     - `actions`
   - Must make explicit decisions about:
     - which phase to use
     - whether to use `chain`
     - which transformation pipeline to use and why

## Family-Specialized Rule Design

`RuleDesigner` should not use one generic prompt for every attack type. Instead, it should be routed into a small set of high-level `attack families`, inspired by how CRS organizes rules under `coreruleset/rules/`.

Recommended families:

- `protocolAndMethod`
- `scannerAndFingerprint`
- `pathTraversalAndFileInclusion`
- `injectionXssSqli`
- `codeExecAndAppAttack`
- `responseDisclosure`

The purpose of family routing is to improve:

- how `variables` are selected
- how the `operator` is selected
- whether `chain` is needed
- how the `transform pipeline` is selected
- how literal or generalized the detection logic should be

## Design Principles

- Prioritize `detection logic` over payload mirroring
- Do not use unsupported actions / directives / operators
- Treat `chain` as a separate logic decision, not a rendering detail
- Treat `transformations` as a first-class decision: minimal, but sufficient for evasion resistance
- Treat CRS families as a `design prior`, not as a rigid template to force every case into
- If the mapping is not clean, the output should allow a `partial rule` or clearly state assumptions

## Output Shape

The final output should include:

- `RuleSet`: one or more `SecRule` definitions
- `Why`: a short trace for `phase / variables / operator / transforms / actions / chain decision`
- `Assumptions`: only when truly necessary

## Example LLM Output Schemas

The following examples show the kind of structured outputs expected from the LLM-driven steps.

### `DetectionSpec` example

```json
{
  "template_id": "CVE-2023-XXXX-nuclei",
  "detection_goal": "Detect a request pattern consistent with SQL injection probing against a login endpoint",
  "request_observables": [
    "POST request to login path",
    "Suspicious SQLi keywords in username or password parameters"
  ],
  "response_observables": [],
  "required_conditions": [
    "Request targets a login-like endpoint",
    "At least one input parameter contains SQLi-like content"
  ],
  "optional_conditions": [
    "Response indicates authentication error"
  ],
  "preferred_phase": 2,
  "candidate_variables": ["REQUEST_FILENAME", "ARGS", "ARGS_POST"],
  "candidate_operators": ["@beginsWith", "@detectSQLi", "@rx"],
  "transform_candidates": ["t:none", "t:urlDecodeUni", "t:lowercase"],
  "family_hypotheses": ["injectionXssSqli"],
  "literal_indicators": ["/login", "username", "password"],
  "generalized_patterns": ["SQLi probing in credential parameters"],
  "chain_candidate": true,
  "constraints": [
    "Do not rely on response-only evidence for the primary rule"
  ],
  "fp_risks": [
    "Generic SQL keywords may appear in benign text"
  ]
}
```

### `FamilyRouterOutput` example

```json
{
  "primary_family": "injectionXssSqli",
  "secondary_family": null,
  "confidence": 0.91,
  "reason": "The template focuses on request-side payload inspection and SQL injection indicators in parameters."
}
```

### `RuleDecisionObject` example

```json
{
  "family": "injectionXssSqli",
  "phase": 2,
  "variables": ["REQUEST_FILENAME", "ARGS_POST"],
  "operator": {
    "name": "@detectSQLi",
    "value": ""
  },
  "transformations": ["t:none", "t:urlDecodeUni"],
  "actions": [
    "id:1000001",
    "phase:2",
    "block",
    "capture",
    "t:none",
    "t:urlDecodeUni",
    "msg:'Possible SQL injection probe against login flow'"
  ],
  "chain_decision": {
    "mode": "chained_rule",
    "reason": "The path constraint and the payload condition should both hold to reduce false positives."
  },
  "transform_decision": {
    "use_t_none": true,
    "pipeline": ["urlDecodeUni"],
    "reason": "The template suggests encoded request payloads, but no extra normalization is required.",
    "omitted_transforms": ["lowercase"],
    "omission_reason": "The selected operator does not require case normalization."
  },
  "rule_count_decision": {
    "mode": "single_rule_pair",
    "reason": "One chained rule is sufficient for the described behavior."
  },
  "fp_notes": [
    "If the endpoint is too generic, the path predicate may need refinement."
  ]
}
```

### Final output example

```json
{
  "rules": [
    "SecRule REQUEST_FILENAME \"@beginsWith /login\" \"id:1000001,phase:2,deny,log,chain,msg:'Possible SQL injection probe against login flow',t:none\"",
    "    SecRule ARGS_POST \"@detectSQLi\" \"capture,t:none,t:urlDecodeUni\""
  ],
  "why": [
    "Phase 2 is used because request parameters are needed.",
    "REQUEST_FILENAME narrows the scope to the login flow.",
    "ARGS_POST is used for credential parameters submitted in the request body.",
    "@detectSQLi is preferred over a large literal regex.",
    "A chain is used so both the endpoint context and the payload condition must match."
  ],
  "assumptions": [
    "The protected application exposes the login endpoint under /login or an equivalent path."
  ]
}
```

## Next Step

The following parts should be defined next:

- `DetectionSpec`
- `FamilyRouterOutput`
- `RuleDecisionObject`
- prompt for `IntentExtractor`
- prompt for `RuleDesigner`
