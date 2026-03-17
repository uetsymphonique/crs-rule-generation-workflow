# Template Parser

## Purpose

`Template Parser` is an LLM-based node that extracts only the minimum template data needed by the current workflow.

At this stage, it does **not** try to infer ModSecurity choices such as:

- `variables`
- `operators`
- `transformations`
- `actions`

Those decisions belong to downstream design nodes.

## Current Extraction Scope

The parser should extract:

- the full `http` block from the Nuclei template
- `attack_tag: string`
- `new_attack_tag?: string`
- `description: string`
- `attack_name: string`
- `application_tag: string`
- `platform_tag: string`
- `language_tag: string`

## Why These Fields

The `http` block preserves the request/detection logic from the source template.

The tag fields are intentionally kept simple for now and are expected to support downstream metadata generation, especially CRS-style metadata and classification such as:

- `attack-*`
- `attack-*/*`
- `application-*`
- `platform-*`
- `language-*`

In this model:

- `attack_tag` is expected to be an enum value taken from the set of broad `attack-*` tags already present in `coreruleset/rules/`
- if no existing CRS-style broad tag fits, use `attack-generic`
- when `attack_tag` is `attack-generic`, the parser may additionally provide `new_attack_tag` to propose a new broad tag name following the existing naming style
- `attack_name` is expected to capture the more specific technique or behavior, aligned with the detailed metadata style represented by tags such as `attack-sqli/boolean-based`

Examples of currently observed broad tags in `coreruleset/rules/` include:

- `attack-deprecated-header`
- `attack-disclosure`
- `attack-fixation`
- `attack-generic`
- `attack-injection-generic`
- `attack-injection-java`
- `attack-injection-php`
- `attack-lfi`
- `attack-multipart-header`
- `attack-protocol`
- `attack-rce`
- `attack-reputation-scanner`
- `attack-rfi`
- `attack-sqli`
- `attack-ssrf`
- `attack-ssti`
- `attack-xss`

See [required metadata](../../plan/docs/metadata/required-metadata.md) for the target metadata model this will support later.

## Output Shape

```json
{
  "http": [],
  "attack_tag": "attack-sqli",
  "new_attack_tag": null,
  "description": "Detect SQL injection probing against a login endpoint",
  "attack_name": "boolean-based",
  "application_tag": "application-multi",
  "platform_tag": "platform-multi",
  "language_tag": "language-multi"
}
```

## Notes

- Keep the parser minimal.
- Preserve the `http` block as faithfully as possible.
- Prefer an existing CRS-style `attack_tag` whenever possible.
- Use `new_attack_tag` only when `attack_tag` falls back to `attack-generic`.
- More complex template schema parsing can be added later if needed.

## System Prompt

```text
You are `Template Parser`, an LLM node in a workflow that parses Nuclei templates for downstream rule-design tasks.

Your job is to extract only the minimum data required by the current workflow.

You must NOT infer or suggest ModSecurity design choices such as:
- variables
- operators
- transformations
- actions
- phase
- chain decisions

You only extract:
- the full `http` block from the input template
- `attack_tag`
- `new_attack_tag` (optional)
- `description`
- `attack_name`
- `application_tag`
- `platform_tag`
- `language_tag`

Output requirements:
1. Return JSON only.
2. Do not wrap the JSON in Markdown.
3. Do not include explanations.
4. Do not add extra keys.
5. Preserve the `http` block as faithfully as possible.

Field semantics:
- `attack_tag` must preferentially be selected from the known broad CRS-style attack tags:
  - `attack-deprecated-header`
  - `attack-disclosure`
  - `attack-fixation`
  - `attack-generic`
  - `attack-injection-generic`
  - `attack-injection-java`
  - `attack-injection-php`
  - `attack-lfi`
  - `attack-multipart-header`
  - `attack-protocol`
  - `attack-rce`
  - `attack-reputation-scanner`
  - `attack-rfi`
  - `attack-sqli`
  - `attack-ssrf`
  - `attack-ssti`
  - `attack-xss`
- If none of the known broad attack tags fits well, set `attack_tag` to `attack-generic`.
- Only when `attack_tag` is `attack-generic`, you may provide `new_attack_tag` to propose a new broad tag name following the existing CRS naming style.
- `attack_name` is the specific technique or behavior, aligned with the detailed metadata style. Example:
  - `attack_tag = attack-sqli`
  - `attack_name = boolean-based`
- `description` should be a short plain-language summary of what the template is trying to detect.
- `application_tag`, `platform_tag`, and `language_tag` should follow CRS-style metadata conventions. Prefer broad fallbacks such as:
  - `application-multi`
  - `platform-multi`
  - `language-multi`
  when the template does not clearly target a narrower scope.

If the template does not contain an `http` block, return `"http": []` and still fill the metadata fields as best as possible.

Use `null` for `new_attack_tag` when it is not needed.
```

## User Prompt

```text
Parse the following Nuclei template and return the JSON object exactly as required by the system instructions.

Input template:

{{template_content}}
```

## Structured Output Schema

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": [
    "http",
    "attack_tag",
    "new_attack_tag",
    "description",
    "attack_name",
    "application_tag",
    "platform_tag",
    "language_tag"
  ],
  "properties": {
    "http": {
      "type": "array",
      "description": "The full http block extracted from the Nuclei template. Preserve request entries as faithfully as possible.",
      "items": {
        "type": "object"
      }
    },
    "attack_tag": {
      "type": "string",
      "enum": [
        "attack-deprecated-header",
        "attack-disclosure",
        "attack-fixation",
        "attack-generic",
        "attack-injection-generic",
        "attack-injection-java",
        "attack-injection-php",
        "attack-lfi",
        "attack-multipart-header",
        "attack-protocol",
        "attack-rce",
        "attack-reputation-scanner",
        "attack-rfi",
        "attack-sqli",
        "attack-ssrf",
        "attack-ssti",
        "attack-xss"
      ]
    },
    "new_attack_tag": {
      "type": [
        "string",
        "null"
      ],
      "description": "Optional proposed new broad attack tag. Use only when attack_tag is attack-generic."
    },
    "description": {
      "type": "string"
    },
    "attack_name": {
      "type": "string",
      "description": "Specific technique or behavior, such as boolean-based, time-based, reflected, or cmd-injection."
    },
    "application_tag": {
      "type": "string"
    },
    "platform_tag": {
      "type": "string"
    },
    "language_tag": {
      "type": "string"
    }
  }
}
```
