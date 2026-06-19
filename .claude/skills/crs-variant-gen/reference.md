# crs-variant-gen — Reference

Load on-demand (CRAFT-VARIANTS cần CRAFT-PLAYBOOK; EMIT cần SCHEMA). SKILL.md giữ phần mandatory.

---

## CRAFT-PLAYBOOK — regex-aware "fall-outside" + technique-spread (PaTT-backed)

Nguyên tắc chung: craft exploit **cùng class** với PoC nhưng dùng **construct/technique khác** mà pattern target không phủ (root-cause-only/all-triggered-rules: rơi ngoài vùng pattern target đọc từ `pattern_excerpt`/regex `.conf`; class-only: spread nhiều technique theo family). Variant phải vẫn là exploit thật (gate `class-valid`), không phải chuỗi né regex vô nghĩa. **Catalog technique = `comibined-docs/patt-category.md`** (index prose `.md` của PayloadsAllTheThings — README + sibling, KHÔNG raw payload) — KHÔNG hard-code danh sách technique ở đây.

### Retrieve technique — GỌN, theo thứ tự, dừng sớm

1. **Tra index 1 lần**: Read `comibined-docs/patt-category.md`, tìm dòng map của `classification.families` token → lấy `folder` + danh sách `anchor` + `size` + (nếu cần encoding-layer) `bypass anchor`. Đây là Read **duy nhất** vào index.
2. **Chọn tối thiểu**: 1 folder chính (multi-family → chỉ family dominant/đầu tiên; chỉ mở folder thứ 2 khi template thực sự lai class). Chọn **≤2–3 anchor** đúng nhu cầu craft — đủ để có ≥2 technique distinct, KHÔNG hơn.
3. **Lấy section theo `size`** (áp cho mọi `.md`, cấm Read whole file lớn). Mặc định mở `README.md`; chỉ mở **sibling `.md`** (engine SQL/SSTI theo backend, bypass-doc XSS — xem mục Sibling trong `patt-category.md`) khi template chỉ rõ engine hoặc cần bypass riêng:
   - `.md` ≤ ~250 dòng → Read whole **1 lần**.
   - `.md` ≥ ~400 dòng (XXE 688, XSS README 609, `MySQL Injection.md` 775, `XSS Filter Bypass.md` 578, …) → **KHÔNG** Read whole. `Grep -n '^#{2,3} '` lấy line của anchor đã chọn → Read **offset/limit** đúng 1–2 section đó.
4. **Encoding-layer** (chỉ khi Bước 0 ở CRAFT-VARIANTS xác định payload bị bọc transport-encoding **và** có gap CRS không decode lớp đó): thêm section `bypass anchor` của class + (nếu cần) `Encoding Transformations/README.md` (`Unicode`/`Base64`). Bỏ qua nếu không có gap.
5. **STOP**. Đủ ≥2 technique distinct thì dừng — KHÔNG quét thêm folder/file "cho chắc" (tổng ≤2 file `.md`). Cấm tuyệt đối: `Files/`, `Intruder/`, `Images/`, `*.txt` — payload thô gắn slot mặc định của tác giả, ngoài scope variant-gen.

Mỗi technique lấy từ PaTT phải được **re-home vào `injection_slot` thật** + giữ class-valid; KHÔNG bê payload verbatim (PaTT gắn slot mặc định của tác giả, thường là URI — không phải slot của template này).

### Ghi nhớ — construct, không phải encoding bề mặt

**t:lowercase + t:urlDecodeUni là baseline** rule CRS thường áp → biến thể chỉ đổi case/url-encode bề mặt KHÔNG thoát (đã normalize về cũ). Phải đổi **construct/cấu trúc** (technique khác từ PaTT methodology). Ngoại lệ — encoding-**layer**: khi payload bị bọc lớp transport-encoding mà **không CRS rule nào decode lớp đó** (the gap), biến đổi *trong/qua lớp đó* (delimiter `\r\n`↔`\n`↔`\r`, base64 chuẩn↔base64url↔padding, đổi bộ field) MỚI là trục breadth thật. Phân biệt: surface re-encode (bị normalize, vô ích) vs layer-variation tại gap (có ích) — xem `patt-category.md` mục Encoding-layer.

Mỗi variant ghi `rationale` nêu rõ: (root-cause-only/all-triggered-rules) target id nào + neo construct gì + variant đi đường nào để rơi ngoài; (class-only) technique gì từ PaTT + vì sao là vector hợp lệ chưa được phủ. Reviewer + New-rule Generator đọc cái này để hiểu breadth cần phủ.

---

## SCHEMA

### `out/<id>/variant-context.json` (parse_targets.py → model đọc)

| Field | Vai trò |
|---|---|
| `classification.families` / `injection_point` / `protocol` | xác định attack-class + injection slot |
| `classification.injection_slot` | **slot vector chuẩn từ Stage 1** (ModSec request-variable, vd `REQUEST_HEADERS:Authorization`). Khi có → copy **verbatim** vào `variants.json` top-level `injection_slot`, KHÔNG tự đoán lại từ prose. Vắng (artifact cũ) → tự suy từ `injection_point` + probe-input |
| `payload_samples` | base PoC + đối chiếu để định vị slot trong probe-input |
| `paranoia` | carry thẳng cho Lane-4 Verify (không dùng ở variant-gen) |
| `mode` | `class-only` / `root-cause-only` / `all-triggered-rules` — nguồn target. class-only (default hoặc fallback) = không neo rule; root-cause-only/all-triggered-rules fallback về class-only khi thiếu field (no root cause / nothing fired) |
| `targets` | class-only: `[]` (craft từ family/payload_samples, không có rule) · root-cause-only: `{id,msg,operator,transforms,pattern_excerpt,matched_at,trigger_explanation}` (pattern inline) · all-triggered-rules: `{id,msg,tags,paranoia_level,matched_var}` (id-only, đọc pattern sau) |

Schema đầy đủ + derive: docstring `tools/parse_targets.py`.

### `out/<id>/variants.json` (MODEL viết — judgment)

```json
{
  "injection_slot": "REQUEST_BODY",
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
- **`injection_slot` (top-level, BẮT BUỘC)** — slot vector thật, khai bằng **ModSec request-variable string** (đồng bộ vocabulary với Stage-1 scope + crs-rule-author rule scope). **Ưu tiên copy verbatim `classification.injection_slot` từ variant-context** (Stage 1 cấp); chỉ tự suy từ `classification.injection_point` khi context không có (artifact cũ). `build_extended.py::resolve_slot` map family của var → vị trí vật lý thô để đóng băng phần ngoài slot và bắt slot phải đổi (gate `injection-slot-fidelity`):

  | ModSec var khai | Vị trí vật lý (differ đóng băng phần còn lại) |
  |---|---|
  | `REQUEST_HEADERS:Name` | header `Name` |
  | `REMOTE_USER` / `AUTH_TYPE` | header `Authorization` (var parse ra từ đó) |
  | `REQUEST_COOKIES:Name` | cookie `Name` (trong header Cookie) |
  | `ARGS_GET[:n]` / `QUERY_STRING` / `REQUEST_URI` / `REQUEST_FILENAME` / `REQUEST_BASENAME` / `PATH_INFO` | toàn bộ `uri` |
  | `ARGS_POST[:n]` / `REQUEST_BODY` / `XML` / `FILES` / `MULTIPART_FILENAME` / `MULTIPART_NAME` / `MULTIPART_PART_HEADERS` | toàn bộ `body` |
  | `ARGS` / `ARGS_NAMES` | **lỗi** — disambiguate ARGS_GET (uri) / ARGS_POST (body) |
  | `REQUEST_LINE` / `REQUEST_PROTOCOL` / `REQUEST_METHOD` / `FULL_REQUEST` | **lỗi** — span cả envelope hoặc là method đã freeze, không phải slot đơn |

  Differ chỉ cô lập ở mức vật lý thô (không parse arg trong body, không sub-isolate một part multipart — đó là việc body-processor / rule author); `:n` cho rule author biết arg cụ thể, differ vẫn đóng băng cả uri/body. Var khác ngoài bảng → reject (bắt khai lại đúng request-content var). Ví dụ: CVE base64 Basic-auth → `REQUEST_HEADERS:Authorization` (hoặc `REMOTE_USER`); CRLF query → `ARGS_GET:user` (hoặc `REQUEST_URI`); JSON body field → `REQUEST_BODY`; session cookie → `REQUEST_COOKIES:PHPSESSID`; upload filename → `MULTIPART_FILENAME`.
- `label` unique, prefix `variant:` (PoC do script gán `poc`).
- `request` clone **đúng envelope** PoC, chỉ đổi payload **tại `injection_slot`** (mọi thứ ngoài slot — method, header/cookie khác, uri/body không-phải-slot — y hệt PoC); **escape đúng** (body JSON 2 lớp như `probe-input.json`).
- `evades_rule` = id target variant nhắm né (1 id chính); `rationale` cite construct. **class-only**: `evades_rule = null`, `rationale` cite technique thay vì rule.
- **Luôn có ≥1 variant** — KHÔNG passthrough rỗng ở skill này. (PoC-only là việc của crs-retrieve-analyze khi `gen-variants=off`.)
- **Pure staging — auto-xoá**: `build_extended.py` là consumer duy nhất; `extended-requests.json` là superset (request→requests[], label→labels[], evades_rule+rationale→meta[]). Sau khi `extended-requests.json` ghi xong, script xoá `variants.json` (gated-on-success; abort do envelope drift thì giữ lại). `--keep-variants` để giữ khi debug.

### `out/<id>/extended-requests.json` (build_extended.py → Lane-4 Verify)

```json
{
  "paranoia": 2,
  "injection_slot": "REQUEST_BODY",
  "requests": [ {<poc>}, {<variant>}, ... ],
  "labels": [ "poc", "variant:exec", ... ],
  "meta": [
    { "label": "poc", "evades_rule": null, "rationale": "base PoC from Stage 1 probe-input" },
    { "label": "variant:exec", "evades_rule": 932240, "rationale": "..." }
  ]
}
```

`requests[0]` luôn là PoC; `labels`/`meta` index-aligned với `requests`. `injection_slot` carry từ `variants.json` (provenance: vector mọi request biến đổi). Verify đọc batch này, map kết quả engine về label qua index.

---

## Anti-Patterns — refute trước

### "Đổi case / url-encode payload là ra variant"
Sai. Rule CRS baseline áp `t:lowercase,t:urlDecodeUni` → biến thể bề mặt bị normalize về cũ, vẫn bị bắt y nguyên. Phải đổi **construct/cấu trúc** mới rơi ngoài pattern thật.

### "Dùng candidate_rules làm target cho gọn"
Sai. `candidate_rules` là output RETRIEVE (rule liên quan để Stage 2 *tham chiếu thiết kế*), KHÔNG phải rule đang phủ payload. Target là `root_cause_rules` (root-cause-only) / `matched_rules` (all-triggered-rules) — rule engine thực sự fire trên payload (gate `target-source`); class-only không neo rule.

### "Probe thử variant xem có lọt rule cũ không"
Sai và vi phạm `no-probe`. Variant là design fodder; craft hụt (vẫn bị bắt) cũng OK. Việc engine chấm là độc quyền Lane-4 Verify. Variant-gen không có engine trong allowed-tools.

### "Đọc new.json xem rule mới đang viết gì để né cho khớp"
Sai và phá `isolation`. Variant-gen chạy TRƯỚC New-rule Generator chính để KHÔNG thấy regex candidate → không neo vào nó. Đọc new.json = tái tạo blind-spot #2.

### "Read full file .conf để xem hết rule class cho chắc"
Sai và phình context. all-triggered-rules chỉ `Read` block target (`offset/limit`) cho `@rx`, cap ≤8, qua index. Không cày `.ra`, không grep regex body.

### "Bê payload `.txt` trong PaTT Files/Intruder vào variant cho nhanh"
Sai. Catalog technique là **prose `.md`** (README + sibling) — KHÔNG raw payload. `Files/`·`Intruder/`·`*.txt` là payload thô gắn slot mặc định của tác giả (CRLF list toàn prefix `/...` = URI) — bê verbatim sẽ dời slot (phá `injection-slot-fidelity`) và thường chỉ là surface-encoding (bị normalize). Lấy **technique** từ `.md` methodology, tự dựng payload re-home vào `injection_slot` thật.

### "Read full README/`.md` PaTT / quét nhiều file cho đủ breadth"
Sai và phình context. Theo ##CRAFT-PLAYBOOK retrieve: tra `patt-category.md` 1 lần → 1 folder chính, mặc định README, chỉ mở sibling `.md` khi cần engine/bypass; `.md` lớn (≥~400 dòng) Grep anchor rồi Read offset/limit, KHÔNG Read whole; đủ ≥2 technique distinct thì STOP (tổng ≤2 file `.md`). Không mở folder thứ 2 trừ khi template lai class thật.

### "Tự tính base64/hex tay hoặc dùng `python -c` / PowerShell / ide để encode"
Sai và error-prone. `python -c`, PowerShell, `mcp__ide__executeCode` đều **bị chặn** trong allowed-tools — agent sẽ flail nhiều turn rồi vẫn phải tự tính tay (dễ sai: `cXJv` ≠ `c3Jv`, `qro` ≠ `sro`). Script sanctioned `encode_layer.py` đã có trong allowed-tools và xử lý escape `\r\n` tự động. Luôn dùng:
```bash
python .claude/skills/crs-variant-gen/tools/encode_layer.py roundtrip base64 'payload\r\n...'
```
Trước khi copy giá trị encoded vào `variants.json`. Xem Operational note.

### "Craft thật nhiều variant cho breadth tối đa"
Sai. Mục tiêu là *vài biến thể đủ chất lượng*, không phải bypass-fuzzer. ≤6 variant, ≥2 kỹ thuật — chất lượng + đa dạng construct hơn số lượng.

### "Vector thật là một header, nhưng đổi header phiền — nhồi payload vào uri cho qua validation"
Sai và phá `injection-slot-fidelity`. Slot vector thật suy từ `classification.injection_point` — có thể là header (`Authorization`), cookie, uri, hay body. Đóng băng vector thật rồi inject sang slot khác = chuyển sang **vuln khác**, variant vô nghĩa (Verify chấm sai). Khai đúng `injection_slot` và biến đổi **trong slot đó**; nếu payload bị bọc encoding-layer (base64/hex/nested-url/JWT) thì biến đổi trong/qua lớp đó (delimiter `\r\n`↔`\n`↔`\r`, base64 chuẩn↔base64url↔padding/whitespace, đổi bộ field chèn). Đây đúng là lỗi CVE-2026-41940.

---

## Red Flags — STOP nếu đang nghĩ:

| Nếu nghĩ... | Thực tế là... |
|---|---|
| "URL-encode/đổi case là đủ thành variant" | Bị t:urlDecodeUni/t:lowercase normalize → không rơi ngoài; phải đổi construct |
| "candidate_rules là rule cần né" | Đó là rule tham chiếu thiết kế; target là root_cause/matched (gate target-source) |
| "Probe variant cho chắc nó lọt" | no-probe — guarantee ở Lane-4; variant chỉ là design fodder |
| "Xem new.json để craft cho ăn khớp rule mới" | Phá isolation — variant-gen cố tình mù với regex candidate |
| "targets rỗng thì tự bịa vài variant" | targets rỗng ⇒ luôn `mode=class-only` → VẪN craft từ family (technique-spread, evades_rule=null). KHÔNG passthrough ở skill này (PoC-only = `gen-variants=off`, do crs-retrieve-analyze xử lý) |
| "Đổi method/path cho ra request khác" | Phá envelope → probe sai endpoint; chỉ đổi payload slot (gate shape-fidelity) |
| "Vector là header nhưng nhồi payload vào uri cho qua check" | Phá injection-slot-fidelity — dời sang vuln khác; khai đúng `injection_slot`, biến đổi TRONG slot (kể cả lớp encoding base64/hex/JWT) |
| "Copy payload `.txt` PaTT cho nhanh" | Catalog là prose `.md` (`patt-category.md`); `Files/.txt` là payload thô gắn slot tác giả → bê verbatim phá injection-slot-fidelity. Lấy technique, tự re-home |
| "Read full `.md` PaTT cho chắc" | 1 folder, mặc định README + sibling khi cần; `.md` lớn Grep+offset/limit, không Read whole; đủ ≥2 technique distinct thì STOP (≤2 file) |
| "Craft chuỗi né regex là xong" | Variant phải là exploit hợp lệ cùng class (gate class-valid), không thì Verify vô nghĩa |
| "Cần encode base64/hex cho variant, dùng `python -c` / PowerShell cho nhanh" | Cả hai bị chặn → flail nhiều turn → tự tính tay → sai im lặng (build_extended.py không decode). Dùng `encode_layer.py roundtrip` — sanctioned, escape `\r\n` tự động, in `match: OK` để verify |

---

## Operational note
- **Escaping body JSON**: model tự viết full `request` với escape đúng (đã làm ở Stage 1 khi viết `probe-input.json`) — KHÔNG để script find-replace payload thô (re-escape 2 lớp fragile). `build_extended.py` chỉ validate envelope + bundle.
- **paranoia passthrough**: variant-gen không probe nên không tự sinh `paranoia`. `build_extended.py` đọc `paranoia` từ `probe-input.json` (Stage 1 ghi) → `extended-requests.json` để Lane-4 Verify probe đúng PL (mặc định 2, đồng bộ Stage 1). `variant-context.json` cũng carry một `paranoia` (lấy từ probe result trong `probe.json`) cho model biết PL, nhưng không dùng để craft.
- **Multi-vector template**: `build_extended.py` lấy `probe-input.requests[0]` làm PoC base. Template đa vector (nhiều exploit request) → variant-gen nhắm vector đầu; vector khác xử lý ở lần chạy riêng nếu cần.
- **Encoding-layer computation — `encode_layer.py`**: khi Bước 0 xác định encoding-layer, MỌI tính toán encode/decode/verify đều qua script sanctioned (trong allowed-tools; `python -c` bị chặn). Interface:
  ```bash
  python .claude/skills/crs-variant-gen/tools/encode_layer.py encode <scheme> '<text với \r\n escapes>'
  python .claude/skills/crs-variant-gen/tools/encode_layer.py decode <scheme> '<value>'
  python .claude/skills/crs-variant-gen/tools/encode_layer.py roundtrip <scheme> '<text>'   # verify match OK trước khi ghi variants.json
  ```
  Schemes: `base64`, `base64url`, `hex`, `url`, `url-full`, `html`, `jwt-decode` (decode-only). `\r \n \t \xHH` trong argument được expand tự động — không cần shell quoting phức tạp. Luôn chạy `roundtrip` để xác nhận `match: OK` trước khi copy giá trị encoded vào `variants.json`.
