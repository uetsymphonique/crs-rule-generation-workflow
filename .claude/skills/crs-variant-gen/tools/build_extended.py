#!/usr/bin/env python3
"""build_extended.py — assemble Stage-1 PoC + model-crafted variants into one
batch-ready request set for Lane-4 Verify.

Usage:
    python .claude/skills/crs-variant-gen/tools/build_extended.py \
        <probe-input.json> <variants.json> <extended-requests.json> [--keep-variants]   (from repo root)

variants.json is pure staging: this script is its ONLY reader, and
extended-requests.json is a strict superset of it (every variant's request →
requests[], label → labels[], evades_rule+rationale → meta[], plus the PoC +
paranoia). So after extended-requests.json is SAFELY written, build_extended
deletes variants.json. The delete is gated on the successful write (an envelope
validation abort leaves variants.json in place to fix) and `--keep-variants`
retains it. probe-input.json (the immutable PoC source / clone base) is NEVER
touched — re-running this script regenerates extended-requests.json from scratch.

The MODEL writes variants.json (full request per variant, mirroring the
probe-input shape it already produced in Stage 1 — so the JSON-body escaping is
handled by the model, not by fragile find-replace). This script is thin: it only
(1) validates each variant request kept the SAME envelope as the PoC EXCEPT at the
declared injection slot and (2) bundles PoC + variants into extended-requests.json
(probe-engine batch shape + an index-aligned label/meta sidecar).

Envelope + slot fidelity (gates `shape-fidelity` + `injection-slot-fidelity`):
variants.json declares ONE `injection_slot` as a ModSec request-variable string
(the real vector from Stage-1 `classification.injection_point`) — e.g.
`REQUEST_HEADERS:Authorization`, `ARGS_GET:user`, `REQUEST_COOKIES:PHPSESSID`,
`REQUEST_BODY`. The variable is the pipeline-shared slot identity (Stage-1 scope
and the crs-rule-author rule scope all speak ModSec); resolve_slot() maps its
family to the coarse PHYSICAL slot (header / cookie / uri / body) the raw-request
differ can isolate. Each variant may change ONLY that slot; EVERYTHING else
(method, all other headers/cookies, the non-slot uri/body) must equal the base
PoC, and the slot value MUST differ from the PoC (else it is a no-op variant).
The slot must exist (non-empty) in the base PoC — you can only vary where the PoC
already injects. This deliberately rejects the failure where a variant freezes the
real vector (e.g. a base64 Authorization header) and bolts a payload onto a
non-vector slot (the uri): that moves the injection to a DIFFERENT vector, which is
a different vuln, not a variant. A drifted method / dropped header / changed
non-slot part aborts — it would probe a different endpoint and make verify
meaningless.

variants.json (model-authored):
    { "injection_slot": "REQUEST_HEADERS:Authorization",
      "variants": [
        { "label": "variant:lf-only", "evades_rule": null,
          "rationale": "base64-decoded credential uses lone LF as the session-file line delimiter",
          "request": { "method": "...", "uri": "...", "headers": {...}, "body": "..." } }
      ] }

extended-requests.json (output — batch-ready, requests[0] is the PoC):
    { "paranoia": 2,
      "requests": [ {<poc>}, {<variant>}, ... ],
      "labels":   [ "poc", "variant:exec", ... ],
      "meta": [ {label, evades_rule, rationale}, ... ] }
"""
import json
import os
import sys


def norm_headers(h):
    return {str(k).lower(): v for k, v in (h or {}).items()}


def parse_cookies(cookie_hdr):
    """Split a Cookie header value into an ordered list of (name, raw_pair)."""
    pairs = []
    for part in str(cookie_hdr or "").split(";"):
        seg = part.strip()
        if not seg:
            continue
        name = seg.split("=", 1)[0].strip()
        pairs.append((name, seg))
    return pairs


# ModSec request-variable families → physical slot the raw-request differ can isolate.
# (Per comibined-docs/modsec-docs/variables/variables_category.md.) The variable is the
# canonical, pipeline-shared slot identity (Stage-1 scope + crs-rule-author rule scope all
# speak ModSec); the differ only needs the coarse physical location to freeze the envelope.
_HEADER_VARS = {"REQUEST_HEADERS", "REQUEST_HEADERS_NAMES"}
_COOKIE_VARS = {"REQUEST_COOKIES", "REQUEST_COOKIES_NAMES"}
_URI_VARS = {"ARGS_GET", "ARGS_GET_NAMES", "QUERY_STRING",
             "REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_FILENAME", "REQUEST_BASENAME", "PATH_INFO"}
# ARGS_POST + raw/parsed body + multipart file-upload + XML body all live physically in `body`;
# the differ freezes everything-but-body (it does not sub-isolate one arg/part — that is the
# body processor's / rule author's job).
_BODY_VARS = {"ARGS_POST", "ARGS_POST_NAMES", "REQUEST_BODY", "XML",
              "FILES", "FILES_NAMES", "MULTIPART_FILENAME", "MULTIPART_NAME", "MULTIPART_PART_HEADERS"}
# Auth-derived vars are parsed out of the Authorization header — physically isolate that header.
_AUTH_VARS = {"REMOTE_USER", "AUTH_TYPE"}
# Vars that span the whole request line/envelope or are the frozen method — never a clean slot.
_NONSLOT_VARS = {"REQUEST_LINE", "REQUEST_PROTOCOL", "REQUEST_METHOD", "FULL_REQUEST", "FULL_REQUEST_LENGTH"}


def resolve_slot(var):
    """Map a ModSec request-variable expression (e.g. 'REQUEST_HEADERS:Authorization')
    to (physical_location, name, error). name is the header/cookie key the differ isolates
    (None for uri/body — the differ freezes the whole uri/body, which is the coarse but
    physically correct slot; per-arg granularity is the rule author's job, not the differ's)."""
    if not isinstance(var, str) or not var.strip():
        return None, None, ("injection_slot must be a ModSec request variable string, e.g. "
                            "'REQUEST_HEADERS:Authorization' / 'ARGS_GET:user' / 'REQUEST_BODY'")
    base, sep, key = var.strip().partition(":")
    base = base.strip().upper()
    key = key.strip()
    if base in _HEADER_VARS:
        if not key:
            return None, None, f"{var!r}: name the header, e.g. REQUEST_HEADERS:Authorization"
        return "header", key.lower(), None
    if base in _COOKIE_VARS:
        if not key:
            return None, None, f"{var!r}: name the cookie, e.g. REQUEST_COOKIES:PHPSESSID"
        return "cookie", key, None  # cookie names are case-sensitive
    if base in _AUTH_VARS:
        return "header", "authorization", None  # parsed from the Authorization header
    if base in _URI_VARS:
        return "uri", None, None
    if base in _BODY_VARS:
        return "body", None, None
    if base in ("ARGS", "ARGS_NAMES"):
        return None, None, (f"{var!r}: ARGS spans GET+POST — disambiguate to ARGS_GET (uri) "
                            f"or ARGS_POST (body) so the differ knows the physical slot")
    if base in _NONSLOT_VARS:
        return None, None, (f"{var!r}: spans the whole request line/envelope (or is the frozen method) — "
                            f"not a single injectable slot. Pick the concrete sub-vector "
                            f"(REQUEST_URI / REQUEST_HEADERS:<name> / REQUEST_BODY ...)")
    return None, None, (f"{var!r}: unsupported injection variable — use a request-content var: "
                        f"REQUEST_HEADERS:/REQUEST_COOKIES: / ARGS_GET / ARGS_POST / REQUEST_BODY / "
                        f"REQUEST_URI family / REMOTE_USER / FILES / XML")


def split_slot(req, loc, name):
    """Return (slot_value, residual) for a request: slot_value is the injected slot's
    content; residual is a canonical, hashable view of EVERYTHING ELSE. Two requests
    are envelope-identical iff their residuals are equal. slot_value is None when the
    declared slot is absent."""
    method = str(req.get("method", "")).upper()
    headers = norm_headers(req.get("headers"))
    uri = req.get("uri")
    body = req.get("body", "")
    if loc == "uri":
        return uri, (method, tuple(sorted(headers.items())), body)
    if loc == "body":
        return body, (method, tuple(sorted(headers.items())), uri)
    if loc == "header":
        slot_val = headers.get(name)
        rest = tuple(sorted((k, v) for k, v in headers.items() if k != name))
        return slot_val, (method, rest, uri, body)
    # cookie: isolate the named cookie inside the Cookie header
    cookies = parse_cookies(headers.get("cookie"))
    slot_val = next((raw for n, raw in cookies if n == name), None)
    rest_cookies = tuple(raw for n, raw in cookies if n != name)
    rest_headers = tuple(sorted((k, v) for k, v in headers.items() if k != "cookie"))
    return slot_val, (method, rest_headers, rest_cookies, uri, body)


def validate_envelope(base, req, label, loc, name):
    """Return list of error strings (empty = ok). The variant may differ from the
    base PoC ONLY at the declared injection slot; the slot value must change."""
    errs = []
    base_val, base_residual = split_slot(base, loc, name)
    var_val, var_residual = split_slot(req, loc, name)
    if var_val is None:
        errs.append(f"{label}: injection slot ({loc}{':' + name if name else ''}) absent from variant request")
        return errs
    if var_residual != base_residual:
        errs.append(f"{label}: changed something OUTSIDE the injection slot "
                    f"({loc}{':' + name if name else ''}) — method/other-headers/other-cookies/non-slot uri-body "
                    f"must equal the base PoC")
    if var_val == base_val:
        errs.append(f"{label}: identical to PoC at the injection slot "
                    f"({loc}{':' + name if name else ''}) — no payload variation")
    return errs


def main():
    argv = sys.argv[1:]
    keep_variants = "--keep-variants" in argv
    pos = [a for a in argv if not a.startswith("--")]
    if len(pos) != 3:
        sys.exit("usage: build_extended.py <probe-input.json> <variants.json> <extended-requests.json> [--keep-variants]")
    probe_input_path, variants_path, out_path = pos

    with open(probe_input_path, encoding="utf-8") as f:
        probe_input = json.load(f)
    with open(variants_path, encoding="utf-8") as f:
        variants_doc = json.load(f)

    reqs = probe_input.get("requests")
    if not reqs:
        sys.exit("probe-input.json has no requests[]")
    base = reqs[0]
    paranoia = probe_input.get("paranoia", 2)
    variants = variants_doc.get("variants") or []

    slot_var = variants_doc.get("injection_slot")
    loc, name, slot_err = resolve_slot(slot_var)
    if slot_err:
        sys.exit("injection_slot invalid (declare the Stage-1 vector as a ModSec variable; "
                 "fix variants.json, do not loosen):\n  - " + slot_err)
    # you can only vary where the PoC injects: the slot must exist (non-empty) in the base PoC.
    base_val, _ = split_slot(base, loc, name)
    if not base_val:
        sys.exit(f"injection_slot {slot_var!r} ({loc}{':' + name if name else ''}) is absent/empty in the "
                 f"base PoC — the declared slot is not the real vector. Re-derive it from "
                 f"classification.injection_point.")

    errors = []
    out_requests = [base]
    out_labels = ["poc"]
    out_meta = [{"label": "poc", "evades_rule": None, "rationale": "base PoC from Stage 1 probe-input"}]

    for i, v in enumerate(variants):
        label = v.get("label") or f"variant:{i}"
        req = v.get("request")
        if not isinstance(req, dict):
            errors.append(f"{label}: missing/invalid request object")
            continue
        errors.extend(validate_envelope(base, req, label, loc, name))
        out_requests.append(req)
        out_labels.append(label)
        out_meta.append({
            "label": label,
            "evades_rule": v.get("evades_rule"),
            "rationale": v.get("rationale"),
        })

    if errors:
        sys.exit("envelope validation failed (fix variants.json, do not loosen):\n  - " + "\n  - ".join(errors))

    out = {
        "paranoia": paranoia,
        "injection_slot": slot_var,
        "requests": out_requests,
        "labels": out_labels,
        "meta": out_meta,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    # staging cleanup: extended-requests.json (superset) is written, so variants.json
    # is now dead. delete it (gated on the successful write + the envelope validation
    # above passing). never clobber the output; never crash the pipeline on a failed
    # unlink. probe-input.json (the clone base) is never touched.
    cleaned = ""
    if not keep_variants and os.path.abspath(variants_path) != os.path.abspath(out_path):
        try:
            os.remove(variants_path)
            cleaned = f" (removed {variants_path})"
        except OSError as e:
            cleaned = f" (kept {variants_path}: {e})"

    print(f"{out_path} — poc + {len(variants)} variant(s), paranoia={paranoia}{cleaned}")


if __name__ == "__main__":
    main()
