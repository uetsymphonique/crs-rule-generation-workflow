# Transformation Functions — Category Reference

Transformation functions normalize input data before operator matching. See `reference-transforms.md` for full documentation.

> **Always start with `t:none`** to clear any inherited transforms, then apply decodes in the correct order.

---

## URL / Percent Encoding

| Name | Description |
|---|---|
| `urlDecodeUni` | URL-decodes input; handles Microsoft `%uHHHH` encoding and full-width ASCII. **Preferred over `urlDecode`** |
| `urlDecode` | URL-decodes input. Does not handle `%u` encoding. Avoid using on already-decoded variables |
| `urlEncode` | Encodes input using URL encoding |
| `utf8toUnicode` | Converts UTF-8 sequences to `%uHHHH` Unicode format; reduces FP/FN for non-ASCII input |

---

## HTML / Web Encoding

| Name | Description |
|---|---|
| `htmlEntityDecode` | Decodes HTML entities: `&#xHH;`, `&#DDD;`, `&quot;`, `&lt;`, `&gt;`, `&nbsp;` |
| `jsDecode` | Decodes JavaScript escape sequences including `\uHHHH` |
| `cssDecode` | Decodes CSS 2.x escape sequences (e.g., `ja\vascript` → `javascript`) |

---

## Base64 Encoding

| Name | Description |
|---|---|
| `base64Decode` | Decodes a strict Base64-encoded string |
| `base64DecodeExt` | Decodes Base64, forgiving version — ignores invalid characters |
| `base64Encode` | Encodes input using Base64 |

---

## Hex Encoding

| Name | Description |
|---|---|
| `hexDecode` | Decodes a hex-encoded string (inverse of `hexEncode`) |
| `hexEncode` | Encodes each byte as two hex characters (e.g., `xyz` → `78797a`) |
| `sqlHexDecode` | Decodes SQL hex notation (e.g., `0x414243` → `ABC`) |

---

## Case Normalization

| Name | Description |
|---|---|
| `lowercase` | Converts all characters to lowercase |
| `uppercase` | Converts all characters to uppercase (v3.x+) |

---

## Whitespace Normalization

| Name | Description |
|---|---|
| `compressWhitespace` | Converts all whitespace characters to spaces and collapses consecutive spaces into one |
| `removeWhitespace` | Removes all whitespace characters from input |
| `trimLeft` | Removes whitespace from the left side of input |
| `trimRight` | Removes whitespace from the right side of input |
| `trim` | Removes whitespace from both sides of input |

---

## Null Byte Handling

| Name | Description |
|---|---|
| `removeNulls` | Removes all NUL (`\0`) bytes from input |
| `replaceNulls` | Replaces NUL bytes with space characters (ASCII 0x20) |

---

## Comment Removal

| Name | Description |
|---|---|
| `replaceComments` | Replaces `/* ... */` C-style comments with a single space |
| `removeCommentsChar` | Removes comment-starting sequences: `/*`, `*/`, `--`, `#` |
| `removeComments` | Removes full comment blocks (`/* */`, `--`, `#`). **Deprecated — unreliable, avoid** |

---

## Path Normalization

| Name | Description |
|---|---|
| `normalizePath` | Removes multiple slashes, `.` self-references, and `..` back-references from paths |
| `normalizePathWin` | Same as `normalizePath`, but first converts `\` to `/` (Windows paths) |
| `normalisePath` | Alias for `normalizePath` — kept for backward compatibility, **do not use** |
| `normalisePathWin` | Alias for `normalizePathWin` — kept for backward compatibility, **do not use** |

---

## Shell Command Normalization

| Name | Description |
|---|---|
| `cmdLine` | Normalizes shell command evasion: removes `\`, `"`, `'`, `^`; collapses spaces; converts commas/semicolons to spaces; lowercases |
| `escapeSeqDecode` | Decodes ANSI C escape sequences: `\n`, `\t`, `\xHH`, `\0OOO`, etc. |

---

## Hashing

| Name | Description |
|---|---|
| `md5` | Computes MD5 hash of input (raw binary). Combine with `t:hexEncode` for text output |
| `sha1` | Computes SHA1 hash of input (raw binary). Combine with `t:hexEncode` for text output |

---

## Parity

| Name | Description |
|---|---|
| `parityEven7bit` | Calculates even parity of 7-bit data, setting the 8th bit accordingly |
| `parityOdd7bit` | Calculates odd parity of 7-bit data, setting the 8th bit accordingly |
| `parityZero7bit` | Sets the 8th bit to zero, allowing even/odd parity data to be inspected as ASCII7 |

---

## Utility

| Name | Description |
|---|---|
| `none` | Clears all inherited transformation functions. Always use at the start of a transform chain |
| `length` | Replaces input with its byte length as a decimal string (e.g., `ABCDE` → `5`) |

---

## Reference Example: Counter-Evasion Transform Order

The reference emphasizes that transformations are applied in the order they are listed. One documented example is:

```apache
SecRule ARGS "@rx attack" "phase:2,id:1,t:none,t:htmlEntityDecode,t:lowercase,t:removeNulls,t:removeWhitespace"
```

Use `t:none` first when you want to clear inherited transforms, then add only the transforms the rule actually needs.
