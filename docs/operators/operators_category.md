# Operators — Category Reference

Operators define *when* ModSecurity triggers a match. See `reference-operators.md` for full documentation.

All operators are prefixed with `@`. Prefix any operator with `!` to negate its result:

```apache
SecRule REQUEST_LINE "!@beginsWith GET" ...   # matches when NOT starting with GET
```

---

## String Operators

Match against string content. Macro expansion is performed on parameters before comparison (except `@pm` / `@pmf`).

| Name | Description | `capture` |
|---|---|:---:|
| `@rx PATTERN` | PCRE regex match. **Default operator** — used when no `@` operator is specified. Case-sensitive by default; use `(?i)` for case-insensitive | Yes |
| `@rxGlobal PATTERN` | Global regex — continues matching after first match to collect all captures. More expensive than `@rx`; use only when multiple captures are needed | Yes |
| `@pm word1 word2 ...` | Case-insensitive multi-string match (Aho-Corasick algorithm). Very fast for large keyword lists. Does **not** support macro expansion | Yes |
| `@pmf FILE` / `@pmFromFile FILE` | Same as `@pm` but reads phrases from a file (one per line). Supports relative paths and HTTPS URLs | — |
| `@beginsWith STR` | Returns true if input starts with STR | — |
| `@endsWith STR` | Returns true if input ends with STR | — |
| `@contains STR` | Returns true if STR appears anywhere in input | — |
| `@containsWord STR` | Returns true if STR appears as a **whole word** (with word boundaries) in input. Avoids matching partial words | — |
| `@streq STR` | Exact string equality | — |
| `@strmatch STR` | Returns true if STR appears anywhere in input. Comparable to `@contains` in current implementation | — |
| `@within HAYSTACK` | Returns true if the input (needle) is found anywhere **within** the parameter (haystack). Use artificial delimiters to avoid partial matches | — |

---

## Attack Detection Operators (libinjection)

High-performance attack detection powered by the libinjection library. No regex needed.

| Name | Description | `capture` |
|---|---|:---:|
| `@detectSQLi` | Detects SQL injection payloads using libinjection's tokenizer-based approach | Yes |
| `@detectXSS` | Detects XSS injection payloads using libinjection | Yes |

---

## Numerical Operators

Compare numeric values. Non-numeric inputs are treated as `0`. Macro expansion supported.

| Name | Description |
|---|---|
| `@eq N` | True if input equals N |
| `@ne N` | True if input does not equal N |
| `@gt N` | True if input is greater than N |
| `@ge N` | True if input is greater than or equal to N |
| `@lt N` | True if input is less than N |
| `@le N` | True if input is less than or equal to N |

> **Tip:** Use `&COLLECTION` to count members before comparing, e.g., `&REQUEST_HEADERS "@gt 20"`.

---

## Validation Operators

Detect structural or encoding violations in input. Match on **failure** (invalid input).

| Name | Description |
|---|---|
| `@validateByteRange RANGES` | Matches if input contains bytes **outside** the specified ranges (e.g., `32-126`). Useful to detect NUL bytes or binary content |
| `@validateUrlEncoding` | Matches if URL-encoded characters in input are invalid. Use against raw input (`REQUEST_URI_RAW`), not already-decoded variables |
| `@validateUtf8Encoding` | Matches if input is not valid UTF-8. Detects truncated sequences, invalid characters, and overlong encodings |
| `@validateDTD /path/to/file.dtd` | Validates XML DOM tree against a DTD. Requires `ctl:requestBodyProcessor=XML` and `SecXmlExternalEntity On`. Matches on validation failure |
| `@validateSchema /path/to/file.xsd` | Validates XML DOM tree against an XML Schema. Matches on validation failure |

---

## Network / IP Operators

Match against IP addresses and network reputation sources.

| Name | Description | `capture` |
|---|---|:---:|
| `@ipMatch ADDR[,ADDR...]` | Fast IPv4/IPv6 match. Supports individual addresses and CIDR notation. Multiple values comma-separated | — |
| `@ipMatchFromFile FILE` / `@ipMatchF FILE` | Same as `@ipMatch` but reads addresses from a file. Supports HTTPS URLs | — |
| `@rbl HOSTNAME` | Real-time Block List (DNS) lookup. Matches if the IP is listed in the specified RBL (e.g., `sbl-xbl.spamhaus.org`) | Yes |
| `@geoLookup` | GeoIP lookup of input IP. On success, populates the `GEO` collection. Use with `nolog,pass` then inspect `GEO` fields separately | — |

---

## Data Verification Operators (PII / Sensitive Data)

Detect specific sensitive data patterns. Use regex pre-filter + algorithm validation to reduce false positives.

| Name | Description | `capture` |
|---|---|:---:|
| `@verifyCC REGEX` | Detects credit card numbers — applies regex first, then Luhn algorithm validation | Yes |
| `@verifyCPF REGEX` | Detects Brazilian CPF (social security) numbers | Yes |
| `@verifySSN REGEX` | Detects US Social Security Numbers — validates format and checks against known invalid patterns | Yes |

---

## Miscellaneous Operators

| Name | Description |
|---|---|
| `@unconditionalMatch` | Always returns true. Unlike `SecAction`, still sets `MATCHED_VAR`. Useful at the start of a chain |
| `@noMatch` | Always returns false. Forces a rule to never match |
| `@inspectFile SCRIPT.lua` | Executes an external Lua script per variable value. Designed for file inspection (`FILES_TMPNAMES`). Returns match if script returns non-null |
| `@fuzzyHash FILE THRESHOLD` | Fuzzy hash (ssdeep / CTPH) comparison against known hash file. Matches inputs with homologies to known bad content |

---

## Not Supported in v3

| Name | Notes |
|---|---|
| `@gsbLookup` | Google Safe Browsing lookup — not available in ModSecurity v3 |
| `@rsub` | Regex-based string substitution — not available in ModSecurity v3 |
| `@validateHash` | Not available in ModSecurity v3 |

---

## Operator Negation

Any operator can be negated with `!`:

```apache
# Triggers if request method is NOT GET, POST, or HEAD
SecRule REQUEST_METHOD "!@within GET,POST,HEAD" "id:1000,..."

# Triggers if URI does NOT begin with /api/
SecRule REQUEST_URI "!@beginsWith /api/" "id:1001,..."
```
