# probe-engine

Engine-as-oracle for the CRS rule-generation pipeline. It loads the local OWASP
CRS fork (`coreruleset/`) into an embedded [Coraza](https://github.com/corazawaf/coraza)
WAF, runs an HTTP request through a full transaction, and reports which rules
matched, the inbound anomaly score, and whether the request would be blocked.

It exists so the skills can replace LLM "does this rule match?" guesswork with
ground truth from a real WAF engine (keystone action B1; see
`skill-review-stage1.md` and section 5 of `skill-review-stage2.md`).

## Build

Requires Go >= 1.25. Coraza is pulled from the module proxy (no `replace`); the
`coraza/` submodule is for reading/debugging only and is not a build dependency.

```bash
cd tools/probe-engine
go build -o probe-engine.exe .   # drop .exe on Linux/macOS
```

## Usage

The tool reads JSON from stdin (or a file) and writes JSON to stdout (or a
file). There are three input shapes:

| Shape | Input | Output | Compiles |
|-------|-------|--------|----------|
| **single** | `{"request": {...}}` | one flat result object | 1× |
| **batch** | `{"requests": [{...}, ...]}` | `{"results": [...]}` array | 1× (shared) |
| **sweep** | `{"request"\|"requests": ..., "sweep": true}` | `{"results": [...]}`, each request at PL1-4 | 4× (one per PL) |

Batch mode compiles the ruleset once and reuses it across all requests, so a
probe-first flow (PoC + N bypass variants at one PL) costs a single compile.
Sweep mode iterates PL1-4 so the caller reads the block decision per tier.

```bash
# single (stdin → stdout)
echo '{"request":{"method":"GET","uri":"/search?q=1%27%20OR%20%271%27=%271"}}' \
  | ./probe-engine --crs ./coreruleset --paranoia 1

# single (file → file)
./probe-engine --crs ./coreruleset --paranoia 1 --input request.json --output result.json

# batch: PoC + bypass variants, one compile
./probe-engine --crs ./coreruleset --paranoia 2 --input batch.json

# sweep: same request across PL1-4
echo '{"request":{"method":"GET","uri":"/p?q=PAYLOAD"},"sweep":true}' \
  | ./probe-engine --crs ./coreruleset
```

### Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--crs` | `coreruleset` | Path to the CRS fork dir (must contain `crs-setup.conf.example` and `rules/`). Point at a patched copy for differential before/after probing. |
| `--paranoia` | `1` | CRS paranoia level (1-4). Overridden by `paranoia` in the request JSON when non-zero. |
| `--input` | _stdin_ | Path to a JSON input file. When omitted, JSON is read from stdin. |
| `--output` | _stdout_ | Path to write the JSON result. When omitted, JSON is written to stdout. Errors from `--check` always go to stdout regardless of this flag. |
| `--candidate-rule-file` | _none_ | Path to a file holding one extra `SecRule`/`SecAction` to load on top of CRS (author parse-check). Overrides `candidate_rule` in the JSON. |
| `--check` | `false` | Build the WAF, print the loaded rule count to stdout, and exit. No request probing. |

## Input contract (stdin / file JSON)

```json
{
  "request": {
    "method": "GET",
    "uri": "/search?q=...",
    "headers": { "Host": "localhost", "Content-Type": "application/json" },
    "body": "",
    "proto": "HTTP/1.1"
  },
  "requests": null,
  "paranoia": 1,
  "sweep": false,
  "candidate_rule": null
}
```

- Provide **either** `request` (single) **or** `requests` (a list, batch mode).
  When both are present `requests` wins. Supplying `requests` always selects the
  array output shape, even for a single-element list.
- `sweep: true` probes every supplied request at paranoia levels 1-4 and selects
  the array output shape; the `paranoia` field / `--paranoia` flag is then
  ignored.
- `paranoia` (or `--paranoia`) sets the level for single/batch mode (1-4).
- `uri` must be a properly URL-encoded request target. Raw spaces or quotes in
  the query string will trip protocol-enforcement rules (e.g. 920100 "Invalid
  HTTP Request Line") on top of the intended detection.
- `headers` is optional; if no `Host` is supplied, `localhost` is used.
- `body` is fed only when the engine has request-body access (it does by
  default). Set `Content-Type` to engage the JSON/XML body processors.

## Output contract (stdout / file JSON)

Single mode returns one flat result:

```json
{
  "status": "ok",
  "parse_ok": true,
  "matched_rules": [
    {
      "id": 942100,
      "msg": "SQL Injection Attack Detected via libinjection",
      "phase": 2,
      "severity": "critical",
      "paranoia_level": 1,
      "variables": [{ "variable": "ARGS", "key": "q", "value": "1' OR '1'='1", "chain_level": 0 }]
    }
  ],
  "anomaly_score": { "inbound": 5, "threshold": 5, "to_block": 0 },
  "blocked": true,
  "interruption": null,
  "error": null
}
```

| Field | Meaning |
|-------|---------|
| `status` | `ok` for a normal run; `error` for an operational failure (bad `--crs` path, broken ruleset, invalid input JSON). |
| `parse_ok` | `false` when a supplied `candidate_rule` fails to compile (with `status: ok`); `true` otherwise. |
| `matched_rules` | Detection rules that matched. A matched rule is excluded when **either** its message is empty (silent `nolog` setvars: initialization, per-rule paranoia-level setters, skip markers) **or** it lacks both an `attack-*` and a `paranoia-level/N` tag (non-detection CRS infrastructure: blocking evaluation 949110/949111, score correlation 980170, admin rules like 901340). What remains is the set of genuine attack-detection rules. |
| `matched_rules[].paranoia_level` | The rule's CRS paranoia tier from its `paranoia-level/N` tag (1-4). `0` means the rule has no `paranoia-level` tag, i.e. it is not gated to a tier and is active at all paranoia levels. Lets the caller reason about tiers from a single sweep at high PL instead of probing each level. |
| `anomaly_score.inbound` | Final `tx.blocking_inbound_anomaly_score`, captured via a synthetic phase-5 rule (id `900100`, omitted from `matched_rules`). Reflects the configured paranoia level - probe at the level you want to reason about. |
| `anomaly_score.threshold` | Configured `tx.inbound_anomaly_score_threshold` (CRS default 5). The level at which the 949 blocking rules fire. |
| `anomaly_score.to_block` | Points still needed to reach the threshold (`threshold - inbound`), clamped to `0` once already blocked. A small non-zero value flags a near-miss: "covered if one more rule scored", which is directly actionable for partial-coverage and handoff decisions. |
| `blocked` | `true` if a CRS blocking-evaluation rule fired (949110 / 949111) or the transaction was interrupted. |
| `interruption` | The disruptive action, if any. The engine runs in `DetectionOnly`, so this is normally `null` and `blocked` is derived from the 949 rules. |

### Batch / sweep output

Batch and sweep mode return a `results` array instead of the flat fields.
`status`, `parse_ok` and `error` describe the shared WAF build (one classification
for the whole run); each element carries the per-request outcome.

```json
{
  "status": "ok",
  "parse_ok": true,
  "results": [
    {
      "index": 0,
      "paranoia": 1,
      "matched_rules": [],
      "anomaly_score": { "inbound": 0, "threshold": 5, "to_block": 5 },
      "blocked": false,
      "interruption": null
    },
    {
      "index": 0,
      "paranoia": 2,
      "matched_rules": [{ "id": 942100, "...": "..." }],
      "anomaly_score": { "inbound": 42, "threshold": 5, "to_block": 0 },
      "blocked": true,
      "interruption": null
    }
  ],
  "error": null
}
```

| Field | Meaning |
|-------|---------|
| `results[].index` | Position of the source request in the input `requests` list (`0` for a lone `request`). In sweep mode the same index repeats once per paranoia level. |
| `results[].paranoia` | The paranoia level this result was probed at. Constant in batch mode; `1..4` in sweep mode. Read `blocked` alongside it for the block decision per tier. |

The per-result `matched_rules`, `anomaly_score`, `blocked` and `interruption`
fields have the same meaning as in single mode.

### status / parse_ok matrix

| Situation | status | parse_ok |
|-----------|--------|----------|
| Normal probe | `ok` | `true` |
| Candidate rule has bad syntax (base CRS compiles) | `ok` | `false` |
| Bad `--crs` path, broken ruleset, bad input JSON | `error` | `false` |

## Examples

Benign request (not blocked):

```bash
echo '{"request":{"method":"GET","uri":"/api/users?page=1&limit=50"}}' \
  | ./probe-engine --crs ./coreruleset
# -> blocked:false, anomaly_score.inbound:0
```

Candidate parse-check (author):

```bash
echo '{"request":{"method":"GET","uri":"/p?x=EvilCorp"}}' \
  | ./probe-engine --crs ./coreruleset \
      --candidate-rule-file ./my-candidate.conf
# valid rule   -> parse_ok:true,  candidate id appears in matched_rules
# invalid rule -> parse_ok:false, error names the offending directive
```

Differential before/after (fix): run twice against two ruleset dirs and diff
the `matched_rules` / `blocked` / `anomaly_score` of each result.

```bash
REQ='{"request":{"method":"GET","uri":"/p?q=PAYLOAD"}}'
echo "$REQ" | ./probe-engine --crs ./coreruleset          > before.json
echo "$REQ" | ./probe-engine --crs ./coreruleset-patched  > after.json
# or with --input / --output flags:
./probe-engine --crs ./coreruleset         --input req.json --output before.json
./probe-engine --crs ./coreruleset-patched --input req.json --output after.json
```

## Notes for skill integration

- `variables[].value` is the **post-transform** value - what the operator
  actually evaluated after the rule's transform pipeline (e.g. `urlDecodeUni`,
  `lowercase`). This is the operator's-eye view and is usually what you want
  when checking whether a transform pipeline normalized a payload correctly; it
  is not the raw request input. Coraza does not expose the pre-transform value
  on a matched datum, so this is by design, not a workaround.
- A `candidate_rule` is loaded after the CRS ruleset, i.e. after the 949
  blocking evaluation. Its match is observable in `matched_rules`, but any
  anomaly score it sets is not counted by 949 in the same run. To confirm a new
  rule fires, check `matched_rules`; to measure its scoring impact, place it in
  its target CRS file and probe via `--crs` against the patched fork.
- `matched_rules` contains detection rules only; the aggregate score
  correlation rule (980170) is intentionally excluded. Per-tier distribution is
  recoverable from each rule's `paranoia_level`, and the total is in
  `anomaly_score.inbound`.
- **Chain near-miss introspection (review E4) — investigated, not exposed.**
  `variables[].chain_level` already reports how deep a *matched* chain rule went.
  The valuable case, though, is a chain that fires link 1 but fails a later link
  (a near-miss): Coraza never adds such a rule to `tx.MatchedRules()`, and the
  public API (`types.RuleMetadata` / `MatchData`) exposes neither the chain
  length nor the post-transform value of a *non-matching* rule. So an
  "explain mode" that reports per-rule matched/not-matched with values for
  caller-supplied candidate IDs is not feasible without trace-level debug-log
  parsing or an engine fork. Left out deliberately; this is the one residual the
  skill still resolves from the index (see `skill-review-stage1.md` E4). The
  `to_block` distance covers the score-based near-miss case it can answer.
- The skills currently allow only `Bash(python *)`. To call this binary they
  must widen `allowed-tools` to permit `probe-engine` (action B3).
- A `slashFS` wrapper normalizes Windows backslash paths to forward slashes
  because Coraza's SecLang parser joins include paths with `filepath.Join`,
  which `io/fs` otherwise rejects.
