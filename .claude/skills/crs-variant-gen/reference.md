# crs-variant-gen — Reference

Load on-demand (CRAFT-VARIANTS cần CRAFT-PLAYBOOK; EMIT cần SCHEMA). SKILL.md giữ phần mandatory.

---

## CRAFT-PLAYBOOK — regex-aware "fall-outside" theo class

Nguyên tắc chung: đọc **construct cụ thể** target rule neo vào (từ `pattern_excerpt`/`trigger_explanation` focused, hoặc regex `.conf` aggressive), rồi craft exploit **cùng class** dùng đường khác mà pattern đó không phủ. Variant phải vẫn là exploit thật (gate `class-valid`), không phải chuỗi né regex vô nghĩa.

| Class | Target thường neo vào | Hướng craft rơi ngoài (ví dụ) |
|---|---|---|
| rce / cmdi (shell) | shell-path token (`/etc/passwd`, `/bin/sh`), separator (`;`,`|`,`` ` ``), unix keyword list | đổi command không dùng path tuyệt đối; dùng IFS/biến env; encode khác; **chuyển sang code-eval** nếu endpoint là interpreter |
| code-injection (Python/Node/Ruby) | `__import__`, `subprocess`, `eval`/`exec` literal, dunder cụ thể | dùng construct tương đương khác: `exec()`/`eval()`/`compile(...,'exec')`, `getattr(__builtins__,...)`, `().__class__.__base__.__subclasses__()`, `os.popen` vs `subprocess.run` |
| sqli | từ khóa SQL cụ thể (`union select`, comment `--`/`#`), hàm tên cụ thể | đổi keyword casing/whitespace bất thường (đã bị t:lowercase chặn → đổi construct: subquery, stacked, hàm khác) |
| xss | tag/handler cụ thể (`<script`, `onerror=`) | dùng event handler / tag khác; encoding context khác (attribute vs JS context) |
| ssti | delimiter cụ thể (`{{`, `${`), object access | engine khác (Jinja vs Freemarker vs Velocity); truy cập object qua đường khác |
| lfi / traversal | `../` literal, `/etc/` prefix | encoding traversal (`..%2f`, `....//`), absolute path khác, null-byte/wrapper |

Ghi nhớ: **t:lowercase + t:urlDecodeUni là baseline** rule CRS thường áp → biến thể chỉ đổi case/url-encode thường KHÔNG thoát (đã normalize). Phải đổi **construct/cấu trúc**, không chỉ encoding bề mặt. Đây là khác biệt giữa variant đủ chất lượng và fuzz vô ích.

Mỗi variant ghi `rationale` nêu rõ: target id nào, nó neo construct gì, variant đi đường nào để rơi ngoài. Reviewer + New-rule Generator đọc cái này để hiểu breadth cần phủ.

---

## SCHEMA

### `out/<id>/variant-context.json` (parse_targets.py → model đọc)

| Field | Vai trò |
|---|---|
| `classification.families` / `injection_point` / `protocol` | xác định attack-class + injection slot |
| `payload_samples` | base PoC + đối chiếu để định vị slot trong probe-input |
| `paranoia` | carry thẳng cho Lane-4 Verify (không dùng ở variant-gen) |
| `mode` | `focused` / `aggressive` — nguồn target |
| `targets` | focused: `{id,msg,operator,transforms,pattern_excerpt,matched_at,trigger_explanation}` (pattern inline) · aggressive: `{id,msg,tags,paranoia_level,matched_var}` (id-only, đọc pattern sau) |

Schema đầy đủ + derive: docstring `tools/parse_targets.py`.

### `out/<id>/variants.json` (MODEL viết — judgment)

```json
{
  "variants": [
    {
      "label": "variant:exec",
      "evades_rule": 932240,
      "rationale": "932240 neo shell-path token quanh cat /etc/passwd; exec() thuần Python không có '/path' nằm ngoài @rx",
      "request": {
        "method": "POST",
        "uri": "/api/v1/validate/code",
        "headers": { "Content-Type": "application/json", "Authorization": "Bearer ...placeholder" },
        "body": "{\"code\":\"exec(__import__('os').popen('id').read())\"}"
      }
    }
  ]
}
```

Quy tắc populate:
- `label` unique, prefix `variant:` (PoC do script gán `poc`).
- `request` clone **đúng envelope** PoC (method+headers y hệt), chỉ payload tại slot khác; **escape đúng** (body JSON 2 lớp như `probe-input.json`).
- `evades_rule` = id target variant nhắm né (1 id chính); `rationale` cite construct.
- Passthrough (targets rỗng): `{"variants": []}`.

### `out/<id>/extended-requests.json` (build_extended.py → Lane-4 Verify)

```json
{
  "paranoia": 2,
  "requests": [ {<poc>}, {<variant>}, ... ],
  "labels": [ "poc", "variant:exec", ... ],
  "meta": [
    { "label": "poc", "evades_rule": null, "rationale": "base PoC from Stage 1 probe-input" },
    { "label": "variant:exec", "evades_rule": 932240, "rationale": "..." }
  ]
}
```

`requests[0]` luôn là PoC; `labels`/`meta` index-aligned với `requests`. Verify đọc batch này, map kết quả engine về label qua index.

---

## Anti-Patterns — refute trước

### "Đổi case / url-encode payload là ra variant"
Sai. Rule CRS baseline áp `t:lowercase,t:urlDecodeUni` → biến thể bề mặt bị normalize về cũ, vẫn bị bắt y nguyên. Phải đổi **construct/cấu trúc** mới rơi ngoài pattern thật.

### "Dùng candidate_rules làm target cho gọn"
Sai. `candidate_rules` là output RETRIEVE (rule liên quan để Stage 2 *tham chiếu thiết kế*), KHÔNG phải rule đang phủ payload. Target là `root_cause_rules` (focused) / `matched_rules` (aggressive) — rule engine thực sự fire trên payload (gate `target-source`).

### "Probe thử variant xem có lọt rule cũ không"
Sai và vi phạm `no-probe`. Variant là design fodder; craft hụt (vẫn bị bắt) cũng OK. Việc engine chấm là độc quyền Lane-4 Verify. Variant-gen không có engine trong allowed-tools.

### "Đọc new.json xem rule mới đang viết gì để né cho khớp"
Sai và phá `isolation`. Variant-gen chạy TRƯỚC New-rule Generator chính để KHÔNG thấy regex candidate → không neo vào nó. Đọc new.json = tái tạo blind-spot #2.

### "Read full file .conf để xem hết rule class cho chắc"
Sai và phình context. aggressive chỉ `Read` block target (`offset/limit`) cho `@rx`, cap ≤8, qua index. Không cày `.ra`, không grep regex body.

### "Craft thật nhiều variant cho breadth tối đa"
Sai. Mục tiêu là *vài biến thể đủ chất lượng*, không phải bypass-fuzzer. ≤6 variant, ≥2 kỹ thuật — chất lượng + đa dạng construct hơn số lượng.

---

## Red Flags — STOP nếu đang nghĩ:

| Nếu nghĩ... | Thực tế là... |
|---|---|
| "URL-encode/đổi case là đủ thành variant" | Bị t:urlDecodeUni/t:lowercase normalize → không rơi ngoài; phải đổi construct |
| "candidate_rules là rule cần né" | Đó là rule tham chiếu thiết kế; target là root_cause/matched (gate target-source) |
| "Probe variant cho chắc nó lọt" | no-probe — guarantee ở Lane-4; variant chỉ là design fodder |
| "Xem new.json để craft cho ăn khớp rule mới" | Phá isolation — variant-gen cố tình mù với regex candidate |
| "targets rỗng thì tự bịa vài variant" | Không có target regex (focused+not-covered) → passthrough; muốn variant thì --aggressive |
| "Đổi method/path cho ra request khác" | Phá envelope → probe sai endpoint; chỉ đổi payload slot (gate shape-fidelity) |
| "Craft chuỗi né regex là xong" | Variant phải là exploit hợp lệ cùng class (gate class-valid), không thì Verify vô nghĩa |

---

## Operational note
- **Escaping body JSON**: model tự viết full `request` với escape đúng (đã làm ở Stage 1 khi viết `probe-input.json`) — KHÔNG để script find-replace payload thô (re-escape 2 lớp fragile). `build_extended.py` chỉ validate envelope + bundle.
- **paranoia passthrough**: variant-gen không probe nên không dùng `paranoia`; nó chỉ chảy `verdict.probe.paranoia` → `extended-requests.json` để Lane-4 Verify probe đúng PL (mặc định 2, đồng bộ Stage 1).
- **Multi-vector template**: `build_extended.py` lấy `probe-input.requests[0]` làm PoC base. Template đa vector (nhiều exploit request) → variant-gen nhắm vector đầu; vector khác xử lý ở lần chạy riêng nếu cần.
