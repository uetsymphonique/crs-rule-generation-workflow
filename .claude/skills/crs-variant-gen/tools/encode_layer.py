#!/usr/bin/env python3
"""encode_layer.py — compute transport-layer encodings for variant crafting.

Used when an encoding-layer is present in the injection slot (e.g. Base64-wrapped
Basic-auth, hex-encoded body, URL-encoded-twice URI). Avoids hand-computing or
writing ad-hoc helper scripts; avoids denied `python -c` / PowerShell calls.

Usage:
    python .claude/skills/crs-variant-gen/tools/encode_layer.py encode <scheme> <text>
    python .claude/skills/crs-variant-gen/tools/encode_layer.py decode <scheme> <value>
    python .claude/skills/crs-variant-gen/tools/encode_layer.py roundtrip <scheme> <text>

<text> supports C-style escape sequences in the argument:  \\r \\n \\t \\xHH
This lets the caller express CRLF payloads as a single shell argument, e.g.:
    encode_layer.py encode base64 'user:\\r\\nSet-Cookie: x=1'

Schemes:
    base64        RFC 4648 standard (used in Basic-auth, generic wrappers)
    base64url     URL-safe variant (no padding, used in JWT, some OAuth flows)
    hex           lowercase hex, no separator (\\xHH per byte)
    url           percent-encoding (encode: all non-unreserved; decode: %XX)
    url-full      percent-encode ALL bytes (aggressive, no unreserved passthrough)
    html          HTML named/numeric entity encoding (encode only; decode strips &…;)
    jwt-decode    inspect JWT header+payload without signature validation (decode only)

roundtrip: encode then decode, prints both — use to verify a variant value is
correct before putting it in variants.json.
"""

import base64
import sys
import urllib.parse
import re


# --- escape-sequence pre-processor ----------------------------------------

_ESC = re.compile(r'\\([rnt\\]|x[0-9a-fA-F]{2})')

def _expand_escapes(s: str) -> bytes:
    """Convert a string with \\r \\n \\t \\xHH into raw bytes."""
    def _sub(m):
        c = m.group(1)
        if c == 'r':   return '\r'
        if c == 'n':   return '\n'
        if c == 't':   return '\t'
        if c == '\\':  return '\\'
        return chr(int(c[1:], 16))
    return _ESC.sub(_sub, s).encode('utf-8', errors='surrogateescape')


def _safe_repr(b: bytes) -> str:
    """Print bytes with non-printable bytes shown as \\xHH."""
    parts = []
    for byte in b:
        ch = chr(byte)
        if ch == '\r':   parts.append('\\r')
        elif ch == '\n': parts.append('\\n')
        elif ch == '\t': parts.append('\\t')
        elif ch == '\\': parts.append('\\\\')
        elif 0x20 <= byte <= 0x7e: parts.append(ch)
        else: parts.append(f'\\x{byte:02x}')
    return ''.join(parts)


# --- scheme implementations -----------------------------------------------

def _encode_base64(raw: bytes, urlsafe=False) -> str:
    fn = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return fn(raw).decode('ascii')


def _decode_base64(value: str, urlsafe=False) -> bytes:
    # add padding if stripped
    pad = (-len(value)) % 4
    padded = value + '=' * pad
    fn = base64.urlsafe_b64decode if urlsafe else base64.b64decode
    return fn(padded)


def _encode_hex(raw: bytes) -> str:
    return raw.hex()


def _decode_hex(value: str) -> bytes:
    return bytes.fromhex(value.replace(' ', ''))


def _encode_url(raw: bytes, full=False) -> str:
    if full:
        return ''.join(f'%{b:02X}' for b in raw)
    return urllib.parse.quote(raw, safe='')


def _decode_url(value: str) -> bytes:
    return urllib.parse.unquote_to_bytes(value)


_HTML_MAP = {
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;',
    '/': '&#x2F;',
}

def _encode_html(raw: bytes) -> str:
    text = raw.decode('utf-8', errors='replace')
    return ''.join(_HTML_MAP.get(c, c) for c in text)


def _decode_html(value: str) -> bytes:
    import html
    return html.unescape(value).encode('utf-8')


def _decode_jwt(value: str) -> str:
    import json
    parts = value.split('.')
    if len(parts) < 2:
        return f"[not a JWT — expected at least 2 dot-separated parts, got {len(parts)}]"
    out = []
    for label, seg in zip(('header', 'payload'), parts[:2]):
        try:
            raw = _decode_base64(seg, urlsafe=True)
            parsed = json.loads(raw)
            out.append(f"{label}: {json.dumps(parsed, indent=2, ensure_ascii=False)}")
        except Exception as e:
            out.append(f"{label}: [decode error: {e}]")
    out.append(f"signature: {parts[2] if len(parts) > 2 else '(missing)'}")
    return '\n'.join(out)


# --- dispatch --------------------------------------------------------------

def encode(scheme: str, raw: bytes) -> str:
    if scheme == 'base64':       return _encode_base64(raw, urlsafe=False)
    if scheme == 'base64url':    return _encode_base64(raw, urlsafe=True)
    if scheme == 'hex':          return _encode_hex(raw)
    if scheme == 'url':          return _encode_url(raw, full=False)
    if scheme == 'url-full':     return _encode_url(raw, full=True)
    if scheme == 'html':         return _encode_html(raw)
    if scheme == 'jwt-decode':   sys.exit("jwt-decode is decode-only; use: decode jwt-decode <token>")
    sys.exit(f"unknown scheme: {scheme!r}  (choices: base64 base64url hex url url-full html jwt-decode)")


def decode(scheme: str, value: str) -> bytes | str:
    if scheme == 'base64':     return _decode_base64(value, urlsafe=False)
    if scheme == 'base64url':  return _decode_base64(value, urlsafe=True)
    if scheme == 'hex':        return _decode_hex(value)
    if scheme == 'url':        return _decode_url(value)
    if scheme == 'url-full':   return _decode_url(value)
    if scheme == 'html':       return _decode_html(value)
    if scheme == 'jwt-decode': return _decode_jwt(value)   # returns str, not bytes
    sys.exit(f"unknown scheme: {scheme!r}")


def main():
    args = sys.argv[1:]
    if len(args) < 3 or args[0] not in ('encode', 'decode', 'roundtrip'):
        print(__doc__)
        sys.exit(1)

    op, scheme, text = args[0], args[1], args[2]

    if op == 'encode':
        raw = _expand_escapes(text)
        result = encode(scheme, raw)
        print(result)

    elif op == 'decode':
        if scheme == 'jwt-decode':
            print(decode(scheme, text))
        else:
            raw = decode(scheme, text)   # bytes
            print(_safe_repr(raw))

    elif op == 'roundtrip':
        raw = _expand_escapes(text)
        encoded = encode(scheme, raw)
        decoded = decode(scheme, encoded)
        print(f"input  : {_safe_repr(raw)}")
        print(f"encoded: {encoded}")
        if isinstance(decoded, bytes):
            print(f"decoded: {_safe_repr(decoded)}")
            ok = decoded == raw
            print(f"match  : {'OK' if ok else 'MISMATCH'}")
        else:
            print(f"decoded:\n{decoded}")


if __name__ == '__main__':
    main()
