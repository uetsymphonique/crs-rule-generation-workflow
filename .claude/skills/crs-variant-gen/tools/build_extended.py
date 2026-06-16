#!/usr/bin/env python3
"""build_extended.py — assemble Stage-1 PoC + model-crafted variants into one
batch-ready request set for Lane-4 Verify.

Usage:
    python .claude/skills/crs-variant-gen/tools/build_extended.py \
        <probe-input.json> <variants.json> <extended-requests.json>   (from repo root)

The MODEL writes variants.json (full request per variant, mirroring the
probe-input shape it already produced in Stage 1 — so the JSON-body escaping is
handled by the model, not by fragile find-replace). This script is thin: it only
(1) validates each variant request kept the SAME envelope as the PoC and
(2) bundles PoC + variants into extended-requests.json (probe-engine batch shape
+ an index-aligned label/meta sidecar).

Envelope fidelity (gate `shape-fidelity`): a variant may only change the payload
slot. method + headers must equal the base PoC (header keys compared
case-insensitively); exactly one of uri/body must differ (something must change,
or it is not a variant). A drifted method / dropped header / changed path aborts
— that would probe a different endpoint and make the verify verdict meaningless.

variants.json (model-authored):
    { "variants": [
        { "label": "variant:exec", "evades_rule": 932240,
          "rationale": "932240 anchors shell-path token around /etc/passwd; pure exec() falls outside",
          "request": { "method": "...", "uri": "...", "headers": {...}, "body": "..." } }
    ] }

extended-requests.json (output — batch-ready, requests[0] is the PoC):
    { "paranoia": 2,
      "requests": [ {<poc>}, {<variant>}, ... ],
      "labels":   [ "poc", "variant:exec", ... ],
      "meta": [ {label, evades_rule, rationale}, ... ] }
"""
import json
import sys


def norm_headers(h):
    return {str(k).lower(): v for k, v in (h or {}).items()}


def validate_envelope(base, req, label):
    """Return list of error strings (empty = ok)."""
    errs = []
    if str(req.get("method", "")).upper() != str(base.get("method", "")).upper():
        errs.append(f"{label}: method changed ({req.get('method')!r} != base {base.get('method')!r})")
    if norm_headers(req.get("headers")) != norm_headers(base.get("headers")):
        errs.append(f"{label}: headers differ from base PoC (envelope must stay identical)")
    same_uri = req.get("uri") == base.get("uri")
    same_body = req.get("body", "") == base.get("body", "")
    if same_uri and same_body:
        errs.append(f"{label}: identical to PoC — no payload variation (uri and body both unchanged)")
    return errs


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: build_extended.py <probe-input.json> <variants.json> <extended-requests.json>")

    with open(sys.argv[1], encoding="utf-8") as f:
        probe_input = json.load(f)
    with open(sys.argv[2], encoding="utf-8") as f:
        variants_doc = json.load(f)

    reqs = probe_input.get("requests")
    if not reqs:
        sys.exit("probe-input.json has no requests[]")
    base = reqs[0]
    paranoia = probe_input.get("paranoia", 2)
    variants = variants_doc.get("variants") or []

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
        errors.extend(validate_envelope(base, req, label))
        out_requests.append(req)
        out_labels.append(label)
        out_meta.append({
            "label": label,
            "evades_rule": v.get("evades_rule"),
            "rationale": v.get("rationale"),
        })

    if errors:
        sys.exit("envelope validation failed (fix variants.json, do not loosen):\n  - " + "\n  - ".join(errors))

    out = {"paranoia": paranoia, "requests": out_requests, "labels": out_labels, "meta": out_meta}
    with open(sys.argv[3], "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    print(f"{sys.argv[3]} — poc + {len(variants)} variant(s), paranoia={paranoia}")


if __name__ == "__main__":
    main()
