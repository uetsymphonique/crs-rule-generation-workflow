# Intent Extractor

## Purpose

`Intent Extractor` is an LLM-based node that interprets the parsed template and produces a structured detection-intent summary for downstream rule design.

Its role is to explain, in a normalized form, what kind of signals the template is relying on and how those signals relate to each other.

It does **not** make ModSecurity implementation decisions such as:

- `variables`
- `operators`
- `transformations` as final rule design
- `actions`
- `phase`
- `chain` as a SecRule implementation choice

Those decisions belong to downstream design nodes.

## Input

The node is expected to consume the output of `Template Parser`, especially:

- the full `http` block
- `attack_tag`
- `description`
- `attack_name`
- `application_tag`
- `platform_tag`
- `language_tag`

## Output

The node should produce a compact, structured description of detection intent.

Recommended core fields:

- `request_side: boolean`
- `response_side: boolean`
- `required_signals: string[]`

Recommended optional fields:

- `supporting_signals: string[]`
- `logic_relationship: string`
- `normalization: string[]`
- `false_positive_risks: string[]`
- `mapping_constraints: string[]`

## Field Semantics

- `request_side`
  - `true` if the template's detection logic depends on request-side evidence
- `response_side`
  - `true` if the template's detection logic depends on response-side evidence
- `required_signals`
  - the minimum signals that appear necessary for the intended detection logic
- `supporting_signals`
  - secondary signals that strengthen confidence but may not be strictly required
- `logic_relationship`
  - a short description of how signals relate logically, for example:
    - `single dominant signal`
    - `multiple correlated conditions`
    - `request-response correlation`
    - `multi-step or stateful behavior`
- `normalization`
  - semantic normalization hints expressed as transform keywords such as:
    - `urlDecodeUni`
    - `lowercase`
    - `htmlEntityDecode`
    - `removeNulls`
  - these are hints for downstream design, not final transform decisions
- `false_positive_risks`
  - optional notes about overly broad or fragile signals
- `mapping_constraints`
  - optional notes about limits when mapping the template's intent into ModSecurity rule logic

## Notes

- Keep this node focused on detection intent, not rule design.
- Do not restate the parser description unless needed to clarify signal logic.
- `normalization` should only capture meaningful semantic hints, not speculative transform lists.
- If false-positive risks or mapping constraints are not clearly present, they may be omitted.

## System Prompt

```text
You are `Intent Extractor`, an LLM node in a workflow that interprets parsed Nuclei templates and produces a structured detection-intent summary for downstream rule design.

Your role is to explain what signals the template relies on and how those signals relate to each other.

You must NOT make ModSecurity implementation decisions such as:
- variables
- operators
- transformations as final rule design
- actions
- phase
- chained rule design as a SecRule implementation choice

You are given the output of `Template Parser`.

You should produce a compact structured intent object with these core fields:
- `request_side`
- `response_side`
- `required_signals`

You may also include these optional fields when supported by the input:
- `supporting_signals`
- `logic_relationship`
- `normalization`
- `mapping_constraints`
- `false_positive_risks`

Field semantics:
- `request_side`: true if the detection intent depends on request-side evidence
- `response_side`: true if the detection intent depends on response-side evidence
- `required_signals`: the minimum signals that appear necessary for the intended detection logic
- `supporting_signals`: secondary signals that strengthen confidence but may not be strictly required
- `logic_relationship`: a short description such as:
  - `single dominant signal`
  - `multiple correlated conditions`
  - `request-response correlation`
  - `multi-step or stateful behavior`
- `normalization`: semantic normalization hints expressed only as transform keywords such as:
  - `urlDecodeUni`
  - `lowercase`
  - `htmlEntityDecode`
  - `removeNulls`
  These are hints for downstream design, not final transform decisions.
- `mapping_constraints`: optional notes about limits when mapping the template's intent into ModSecurity rule logic
- `false_positive_risks`: optional notes about overly broad or fragile signals

Special rule for false positive evaluation:
- Only include `false_positive_risks` if the user prompt explicitly requests false-positive evaluation.
- If the user prompt does not explicitly request false-positive evaluation, omit `false_positive_risks` entirely.

Output requirements:
1. Return JSON only.
2. Do not wrap the JSON in Markdown.
3. Do not include explanations.
4. Do not add extra keys.
5. Keep the output concise and focused on detection intent.
```

## User Prompt

```text
Interpret the following parsed template output and return a JSON object exactly as required by the system instructions.

False-positive evaluation requested: {{evaluate_false_positive}}

Rules:
- If `evaluate_false_positive` is `true`, include `false_positive_risks` when there are meaningful FP concerns.
- If `evaluate_false_positive` is `false` or empty, do not include `false_positive_risks`.

Input:

{{template_parser_output}}
```

## Structured Output Schema

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": [
    "request_side",
    "response_side",
    "required_signals"
  ],
  "properties": {
    "request_side": {
      "type": "boolean"
    },
    "response_side": {
      "type": "boolean"
    },
    "required_signals": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "string"
      }
    },
    "supporting_signals": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "logic_relationship": {
      "type": "string"
    },
    "normalization": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Semantic normalization hints using transform keywords only, such as urlDecodeUni or lowercase."
    },
    "false_positive_risks": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Include only when false-positive evaluation is explicitly requested in the user prompt."
    },
    "mapping_constraints": {
      "type": "array",
      "items": {
        "type": "string"
      }
    }
  }
}
```
