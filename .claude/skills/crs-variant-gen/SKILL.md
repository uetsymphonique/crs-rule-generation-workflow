---
name: crs-variant-gen
description: Stage 2 (Lane 2) của pipeline CRS rule-generation. Sinh một nhúm request biến thể CÙNG attack-class với PoC để New-rule Generator (crs-rule-author) thiết kế rule có breadth ngay từ vòng đầu và Lane-4 Verify có đủ request để engine chấm. Đọc variant-handoff.json + probe.json, chọn target theo --gen-variants (class-only = default, craft từ family/template không neo rule / root-cause-only = neo root_cause_rules / all-triggered-rules = neo matched_rules; KHÔNG dùng candidate_rules). root-cause-only & all-triggered-rules auto fallback class-only khi thiếu field (no root cause / nothing fired). Clone shape probe-input, craft regex-aware. KHÔNG probe, KHÔNG đọc rule candidate mới, KHÔNG author rule. Write-only → out/<id>/extended-requests.json.
model: claude-sonnet-4-6
effort: medium
allowed-tools:
  - Read
  - Grep
  - Glob
  - Write
  - Edit
  - Bash(python *)
---

# CRS Variant Generator (Lane 2)

Thực thi stage **variant synthesis**: `Ingest → Select-Targets → Craft-Variants → Emit`.
Input: `variant-handoff.json` + `probe.json` (luôn có khi skill này chạy) → distill qua `parse_targets.py` (mode theo `--gen-variants`) → `out/<template_id>/variant-context.json` (model đọc file này) + `out/<template_id>/probe-input.json` (shape request gốc để clone).
Output: đúng **một** artifact `out/<template_id>/extended-requests.json` (PoC + variants, batch-ready cho Verify).

Mục tiêu (proposal §4): cho New-rule Generator vài biến thể **đủ chất lượng** — KHÔNG phải bypass-fuzzer. Chạy **một pass**, **không probe**. Variant là **design fodder heuristic**: có thể craft hụt (thực ra vẫn bị rule cũ bắt) cũng không sao — guarantee duy nhất nằm ở Lane-4 Verify.

> **WRITE-ONLY mặc định.** Deliverable duy nhất là `extended-requests.json`. KHÔNG phát variant/reasoning ra conversation trừ khi user yêu cầu tường minh. Khi hoàn tất, in **đúng một dòng**: `out/<id>/extended-requests.json — <mode>: <n> variant(s)`.

In scope: craft request biến thể cùng class, clone shape PoC.
Out of scope: probe engine, author/patch rule (→ `crs-rule-author`/`crs-rule-fix`), đọc rule candidate mới, invoke skill khác.

Companion file (load on-demand): `reference.md` → ##CRAFT-PLAYBOOK (regex-aware crafting + retrieve technique từ `comibined-docs/patt-category.md`, prose `.md` README+sibling, no raw payload), ##SCHEMA (variants.json / extended-requests.json), Anti-Patterns + Red Flags.

---

## Output artifacts (`out/<id>/`)

| File | Vai trò | Lifecycle |
|------|---------|-----------|
| `extended-requests.json` | **Deliverable** — PoC + variants, batch-ready cho Lane-4 Verify (`verify_rule.py` đọc file này). | Giữ lại (handoff sang Verify). |
| `variant-context.json` | Input distill từ `parse_targets.py` (model đọc thay cho variant-handoff.json/probe.json). | Giữ lại (trace/debug/re-run). |
| `probe-input.json` | Input từ Stage 1 — envelope/clone base cho mọi variant. | Giữ lại (do Stage 1 sở hữu; KHÔNG đụng). |
| `variants.json` | **Pure staging** — judgment model viết; `build_extended.py` là consumer duy nhất, `extended-requests.json` là superset. | **Auto-xoá** sau khi `extended-requests.json` ghi xong (gated-on-success). `--keep-variants` để giữ. |

---

## State machine

| State | Action | Transition (guard → next) |
|-------|--------|---------------------------|
| INGEST | distill input (`parse_targets.py`); Read variant-context + probe-input | probe-input.json thiếu → HALT (báo lý do) · mode=class-only (targets==[]) → CRAFT-VARIANTS (bỏ qua SELECT-TARGETS) · mode=root-cause-only/all-triggered-rules → SELECT-TARGETS |
| SELECT-TARGETS | hiểu vùng pattern mỗi target rule (để craft rơi ngoài) | → CRAFT-VARIANTS |
| CRAFT-VARIANTS | craft variant cùng class (rơi ngoài target HOẶC technique-spread theo family) | → EMIT |
| EMIT | Write variants.json; `build_extended.py` bundle | → STOP |

Tuần tự nghiêm ngặt. Không skip stage. **Variant-gen luôn craft** — không có nhánh passthrough (PoC-only là việc của crs-retrieve-analyze khi `gen-variants=off`, không spawn skill này). class-only bỏ qua SELECT-TARGETS (không có rule để neo) nhưng VẪN craft từ family/mechanism.

> **`mode` do script `parse_targets.py` quyết** (từ `--gen-variants`):
> - `mode=class-only` (default, hoặc fallback) → `targets == []`: craft breadth từ `classification.families` + `payload_samples` + cơ chế template, KHÔNG neo rule nào. Dùng khi muốn brainstorm bypass thẳng từ template, hoặc khi CRS gần như không bắt được class này (blind-spot thật).
> - `mode=root-cause-only` → `targets` = root_cause_rules (pattern inline). Script **fallback class-only** nếu không có root_cause_rules.
> - `mode=all-triggered-rules` → `targets` = matched_rules (id-only, đọc pattern sau). Script **fallback class-only** nếu không rule nào fire.

---

## HARD GATES — vi phạm một gate là invalidate cả stage

<HARD-GATE id="no-probe">
TUYỆT ĐỐI không gọi `probe-engine` (không có trong allowed-tools). Variant là design fodder heuristic, KHÔNG phải claim bypass đã chứng thực. Verification trigger/fire là việc **độc quyền** của Lane-4 Verify (`verify_rule.py`). Không tự "kiểm" variant bằng bất kỳ engine nào ở đây.
</HARD-GATE>

<HARD-GATE id="isolation">
KHÔNG đọc `out/<id>/new.json` (rule candidate — có thể chưa tồn tại, hoặc của lần chạy trước). Variant chỉ được thấy regex **rule CŨ** (target rule trong `variant-context.json`), KHÔNG thấy regex sắp viết. Đây là cơ chế cắt shared-context của blind-spot #2 — variant-gen chạy trước New-rule Generator chính vì lý do này. Đọc new.json = phá isolation.
</HARD-GATE>

<HARD-GATE id="target-source">
Target rule lấy theo **mode** (`variant-context.json.mode`), KHÔNG bao giờ từ `candidate_rules`:
- **class-only** (default, hoặc fallback) → `targets == []`: craft từ `classification.families` + `payload_samples` + cơ chế template (enumerate technique trong cùng class), KHÔNG neo rule. **KHÔNG passthrough — vẫn craft.**
- **root-cause-only** → `targets` = root-cause rules, pattern_excerpt đã inline trong context.
- **all-triggered-rules** → `targets` = matched_rules (id-only), pattern đọc từ `.conf` qua index.
`targets == []` ⇒ luôn là `mode=class-only` ⇒ VẪN craft (gate `class-valid` áp dụng với "fall-outside-target" thay bằng "spread khắp các technique của family"). KHÔNG có ca craft passthrough chỉ PoC ở skill này.
</HARD-GATE>

<HARD-GATE id="bounded-read">
Đọc pattern **chỉ** của target rule, bounded:
- root-cause-only → pattern_excerpt có sẵn trong context, **KHÔNG đọc file**.
- all-triggered-rules → mỗi id: `Grep ^<id>\t` trên `.claude/skills/crs-retrieve-analyze/index/<fileid>.tsv` lấy `file`/`line`/`operator`; chỉ `Read coreruleset/rules/<file>` (`offset=line-1, limit=40`) khi `operator`=`@rx`. Cap **≤8 rule**, ưu tiên rule có tag `attack-*` (bỏ qua protocol 920/921 — evade chúng vô nghĩa cho detection).
KHÔNG full-`Read` `.conf`, KHÔNG cày corpus `.ra`, KHÔNG `Grep id:<id>` trên `.conf` (kéo regex body ~12KB/dòng).
</HARD-GATE>

<HARD-GATE id="class-valid">
Mỗi variant PHẢI là exploit **hợp lệ cùng attack-class** với template (xét theo `classification.families` + cơ chế vuln từ template/payload). KHÔNG craft chuỗi rác/ngẫu nhiên chỉ để "khác PoC". Variant vô nghĩa làm Verify pass/fail sai → thiết kế rule lệch. Đa dạng kỹ thuật: **≤6 variant** và **≥2 kỹ thuật khác nhau**.
- **root-cause-only / all-triggered-rules**: tiêu chí "khác" = **rơi ngoài** vùng pattern target (mỗi variant ghi `evades_rule`).
- **class-only**: KHÔNG có target để rơi ngoài → tiêu chí "khác" = **enumerate technique trong cùng family** (vd RCE: `os.system` vs `subprocess` vs `eval/exec` vs `__import__` vs reverse-shell vs file-write), spread đủ rộng để rule mới phải phủ breadth thật. `evades_rule = null`, `rationale` cite technique + vì sao nó là vector hợp lệ chưa được CRS phủ.
</HARD-GATE>

<HARD-GATE id="injection-slot-fidelity">
Variant PHẢI inject ở **đúng slot vector thật** mà PoC dùng — suy từ `classification.injection_point` (Stage 1). Slot có thể là **một header** (vd `Authorization`), query/uri, body, hoặc **một cookie có tên** — KHÔNG mặc định là uri/body.

Khai `injection_slot` (top-level) trong `variants.json` bằng **ModSec request-variable string** (đồng bộ vocabulary với Stage-1 scope + crs-rule-author rule scope) — vd `REQUEST_HEADERS:Authorization`, `ARGS_GET:user`, `REQUEST_COOKIES:PHPSESSID`, `REQUEST_BODY`. `build_extended.py::resolve_slot` map family của var → vị trí vật lý thô (header/cookie/uri/body) để đóng băng envelope (bảng map ở `reference.md ##SCHEMA`). Mọi variant chỉ đổi payload **tại slot này**; toàn bộ phần còn lại (method, header/cookie khác, uri/body không-phải-slot) **y hệt PoC**, và giá trị tại slot **phải khác PoC**.

**Dời payload sang slot khác = vi phạm.** Đóng băng vector thật (vd header `Authorization` base64) rồi nhồi payload vào slot vô can (vd `uri`) là chuyển sang **vector khác = vuln khác**, KHÔNG phải variant — đó là một template/probe mới (việc của Stage 1). Đây chính là lỗi đã xảy ra ở CVE-2026-41940. `build_extended.py` chặn cứng: phần ngoài slot khác PoC → abort; slot không đổi → abort; slot khai không tồn tại trong PoC → abort. Sửa `variants.json` (khai đúng slot, biến đổi trong slot), KHÔNG nới validation.
</HARD-GATE>

<HARD-GATE id="shape-fidelity">
Mỗi variant clone **đúng envelope** PoC từ `probe-input.json`: chỉ slot đã khai ở `injection-slot-fidelity` được đổi, mọi thứ khác giữ nguyên (method KHÔNG bao giờ đổi; không drop/thêm header; không đổi path nếu path không phải slot). Model tự viết full request với escaping đúng (JSON body 2 lớp như Stage 1). `build_extended.py` validate envelope slot-driven — drift → script abort. Sửa variant, KHÔNG nới validation.
</HARD-GATE>

<HARD-GATE id="terminal">
Sau khi `extended-requests.json` write → HALT. Không probe, không author rule, không invoke `crs-rule-author`/`crs-rule-fix`/skill khác.
</HARD-GATE>

> Anti-Patterns + Red Flags đầy đủ ở `reference.md`. Tham chiếu khi định shortcut.

---

## INGEST

1. **Distill input bằng script** — KHÔNG `Read` cả `variant-handoff.json` hay `probe.json`. `--gen-variants` là arg của skill (default `class-only` nếu không truyền):
   ```bash
   python .claude/skills/crs-variant-gen/tools/parse_targets.py \
     out/<id>/variant-handoff.json out/<id>/probe.json \
     out/<id>/variant-context.json [--gen-variants=class-only|root-cause-only|all-triggered-rules]
   ```
   Contract đầu vào (đủ để skill chạy độc lập): hai file `variant-handoff.json` + `probe.json` ở `out/<id>/` đúng schema Stage 1, cộng arg `--gen-variants`. Caller cung cấp đủ chừng đó là chạy được — không phụ thuộc cách invoke (gọi tay sau Stage 1, hay được driver nào đó spawn đều như nhau).

   **Read `out/<id>/variant-context.json`**. Field: `classification` (families/injection_point/protocol — xác định class + slot), `payload_samples` (base PoC), `paranoia` (carry cho Verify), `mode`, `targets`, `scope_gate_decision`. Lưu ý: `mode` script trả về có thể đã **fallback class-only** (nếu yêu cầu root-cause-only/all-triggered-rules nhưng thiếu field) — luôn theo `mode` thực tế trong file, không theo arg.

   **Scope-gate guard (chạy ngay sau Read, trước mọi xử lý):** nếu `scope_gate_decision` ∈ {`virtual-patch-only`, `out-of-scope-structural`} → **HALT**, in một dòng: `out/<id> — variant-gen skipped: <decision> (no content signature to mutate)`. Đây là cùng guard mà crs-retrieve-analyze áp dụng trước khi spawn bg agent — khi chạy standalone, skill tự gate thay vì để caller biết. `scope_gate_decision == null` (covered) hoặc `in-scope` → tiếp tục bình thường.
2. **Read `out/<id>/probe-input.json`** — shape request gốc (method/uri/headers/body). Đây là envelope mọi variant phải clone. **Xác định `injection_slot`** (ModSec request-variable, gate `injection-slot-fidelity`) — thứ DUY NHẤT variant được đổi, KHÔNG mặc định uri/body:
   - **Stage 1 đã cấp `classification.injection_slot` trong variant-context** → dùng nó làm chuẩn, copy **verbatim** vào `variants.json`. KHÔNG tự đoán lại từ prose (Stage 1 đã đối chiếu matched_var, đáng tin hơn).
   - **Vắng** (artifact cũ) → tự suy: đọc `classification.injection_point` + tìm `payload_samples[].value` nằm ở đâu trong request gốc → map sang var (`REQUEST_HEADERS:<tên>` / `ARGS_GET[:<n>]` / `REQUEST_BODY` hoặc `ARGS_POST[:<n>]` / `REQUEST_COOKIES:<tên>`).
   Ghi nhận luôn **encoding-layer** nếu payload bị bọc (base64 Basic-auth, hex, nested url, JWT segment) để craft biến đổi trong/qua lớp đó.
3. *(tùy chọn, light)* Nếu cơ chế vuln chưa rõ từ context, **Read** Nuclei template `.yaml` (`template_path`) để hiểu class exploit đủ craft variant hợp lệ — KHÔNG để probe.
4. Guard theo `mode`:
   - `mode=class-only` (`targets==[]`, default hoặc fallback) → bỏ qua SELECT-TARGETS (không có rule để neo), sang thẳng CRAFT-VARIANTS theo nhánh class-only. **Bắt buộc Read template `.yaml`** (`template_path`) để nắm cơ chế exploit đủ enumerate technique.
   - `mode=root-cause-only` / `all-triggered-rules` (`targets` non-empty) → SELECT-TARGETS bình thường.
   - `probe-input.json` thiếu → HALT.

## SELECT-TARGETS

> Bỏ qua bước này khi `mode=class-only` (không có target rule). Sang CRAFT-VARIANTS.

Hiểu **vùng pattern** mỗi target rule neo vào (để craft rơi ngoài):
- **root-cause-only**: `targets[].pattern_excerpt` + `trigger_explanation` đã có sẵn → đọc thẳng, KHÔNG mở file. (vd 932240: `trigger_explanation` chỉ rõ neo shell-token quanh `cat /etc/passwd`.)
- **all-triggered-rules**: với mỗi target (ưu tiên `attack-*`, cap ≤8, bỏ 920/921), `Grep ^<id>\t` index lấy `file`/`line`/`operator`; `@rx` → `Read` block (`offset=line-1, limit=40`) lấy regex; `@pmFromFile` → ghi tên data file (suy keyword class), `@detectSQLi`/`@detectXSS` → engine name. Gate `bounded-read`.

Với mỗi target, tóm tắt 1 dòng: rule này bắt **construct nào** → khoảng trống nào của class nằm **ngoài** nó. Đây là input thiết kế variant.

## CRAFT-VARIANTS

> **Bước 0 — LOCK slot + encoding-layer (làm TRƯỚC mọi craft, cả hai nhánh).** Chốt tường minh, một lần, trước khi enumerate:
> 1. **`injection_slot`** — ModSec var đã xác định ở INGEST (ưu tiên `classification.injection_slot` từ Stage 1). MỌI variant chỉ biến đổi tại slot này (gate `injection-slot-fidelity`) — KHÔNG dời sang slot khác để "cho khác PoC".
> 2. **Encoding-layer** — payload tại slot có bị bọc lớp transport-encoding không (base64 Basic-auth, hex, nested url-encode, JWT segment)? Nếu CÓ → trục biến thể chính là **trong/qua lớp đó** (đổi delimiter trong nội dung đã decode, đổi cách encode wrapper, đổi field chèn), KHÔNG phải đổi encoding bề mặt ngoài slot. Xem ##CRAFT-PLAYBOOK (nguyên tắc encoding-layer).
> 3. **Tính/verify giá trị encoding-layer bằng `encode_layer.py`** — KHÔNG tự tính tay, KHÔNG `python -c`, KHÔNG viết script tạm tùy ý. Dùng script sanctioned:
>    ```bash
>    python .claude/skills/crs-variant-gen/tools/encode_layer.py encode base64 'payload\r\nHeader: val'
>    python .claude/skills/crs-variant-gen/tools/encode_layer.py roundtrip base64 'payload\r\n...'
>    python .claude/skills/crs-variant-gen/tools/encode_layer.py decode jwt-decode '<token>'
>    ```
>    `roundtrip` in `match: OK/MISMATCH` — luôn dùng để verify trước khi ghi giá trị vào `variants.json`. Escape sequences `\r \n \t \xHH` được expand tự động trong argument. Schemes: `base64`, `base64url`, `hex`, `url`, `url-full`, `html`, `jwt-decode`.
>
> Mỗi variant ở dưới PHẢI cite **biến đổi ở đâu**: trong slot (+ trong/qua layer nào nếu có). Variant không nằm trong slot đã lock = vi phạm, `build_extended.py` abort.

**root-cause-only / all-triggered-rules** — suy luận **regex-aware** (##CRAFT-PLAYBOOK):
1. Cùng `classification.families`, cùng cơ chế vuln, nhưng dùng construct **rơi ngoài** vùng pattern target (vd target neo `/etc/passwd` shell-path → craft `exec("...")`/`eval(...)`/`compile(...,'exec')` thuần Python không có shell-path) — **vẫn trong slot đã lock**.
2. Mỗi variant clone envelope PoC, đặt payload vào **đúng `injection_slot`** (+ biến đổi trong/qua encoding-layer nếu có), **escape đúng** (body JSON 2 lớp như `probe-input.json`).
3. Gate `class-valid`: ≤6 variant, ≥2 kỹ thuật khác nhau; mỗi variant ghi `evades_rule` (id target nó nhắm né) + `rationale` (vì sao rơi ngoài pattern + biến đổi ở đâu trong slot/layer).
4. **KHÔNG** test lại bằng engine (gate `no-probe`).

**class-only** — không có target rule, suy luận **technique-spread** (##CRAFT-PLAYBOOK → retrieve catalog technique từ `comibined-docs/patt-category.md`):
1. Từ `classification.families` + cơ chế template, **enumerate** các technique riêng biệt của class đó (theo procedure retrieve gọn ở ##CRAFT-PLAYBOOK: tra `patt-category.md` → 1 folder + ≤2–3 anchor README; mở rộng theo cơ chế cụ thể của template) — tất cả **trong slot đã lock** (+ trục encoding-layer nếu payload bị bọc).
2. Mỗi variant = **một technique khác nhau**, vẫn là exploit hợp lệ, đặt payload vào **đúng `injection_slot`** + clone envelope PoC + escape đúng. Mục tiêu: trải đủ rộng để rule mới buộc phải phủ breadth, không chỉ khớp PoC.
3. Gate `class-valid`: ≤6 variant, ≥2 (ưu tiên nhiều hơn) technique distinct; `evades_rule = null`; `rationale` cite technique + vì sao là vector hợp lệ chưa được CRS phủ + biến đổi ở đâu trong slot/layer.
4. **KHÔNG** test lại bằng engine (gate `no-probe`).

## EMIT — terminal (WRITE-ONLY)

1. **Write `out/<id>/variants.json`** (judgment model viết) theo ##SCHEMA: top-level `injection_slot` = ModSec request-variable string (slot vector thật, gate `injection-slot-fidelity`) + `variants[]` = `{label, evades_rule, rationale, request{method,uri,headers,body}}`. Mọi variant đổi payload **chỉ tại `injection_slot`**. Luôn có ≥1 variant — KHÔNG để rỗng. `mode=class-only` → `evades_rule: null`; `mode=root-cause-only`/`all-triggered-rules` → `evades_rule` = id target nhắm né.
2. **Assemble** (script lo cơ học: validate envelope + bundle PoC + variants):
   ```bash
   python .claude/skills/crs-variant-gen/tools/build_extended.py \
     out/<id>/probe-input.json out/<id>/variants.json out/<id>/extended-requests.json
   ```
   - Script abort (envelope drift) → đọc message, sửa `variants.json`, chạy lại. KHÔNG nới validation.
   - `variants.json` là **pure staging** (chỉ script này đọc; `extended-requests.json` là superset). Sau khi `extended-requests.json` ghi xong, script **auto-xoá `variants.json`** (gated-on-success: abort do envelope drift thì giữ lại để sửa). Thêm `--keep-variants` để giữ khi cần debug. `probe-input.json` (clone base) KHÔNG bao giờ bị đụng.
3. In **đúng một dòng** `out/<id>/extended-requests.json — <mode>: <n> variant(s)`. HALT.

Exception: chỉ present nội dung artifact khi user request tường minh.

---

## Checklist (tạo task, complete theo thứ tự)

1. **INGEST** — chạy `parse_targets.py` (`--gen-variants`) → Read `variant-context.json` + `probe-input.json`; **scope-gate guard**: `scope_gate_decision` ∈ {`virtual-patch-only`, `out-of-scope-structural`} → HALT; định vị injection slot; guard theo `mode` thực tế (class-only → bắt buộc Read template, sang CRAFT; root-cause-only/all-triggered-rules → SELECT-TARGETS).
2. **SELECT-TARGETS** *(bỏ qua nếu class-only)* — root-cause-only: đọc `pattern_excerpt`/`trigger_explanation` inline; all-triggered-rules: index lookup + Read block `@rx` (cap ≤8, ưu tiên attack-*); tóm tắt vùng pattern mỗi rule.
3. **CRAFT-VARIANTS** — **Bước 0: LOCK `injection_slot` + encoding-layer** (chốt trước khi craft; mọi variant chỉ biến đổi trong slot + trong/qua layer). Rồi: root-cause-only/all-triggered-rules: regex-aware rơi ngoài pattern (ghi `evades_rule`); class-only: technique-spread theo family (`evades_rule: null`). ≤6 variant, ≥2 kỹ thuật; clone envelope + escape; rationale cite biến đổi ở đâu trong slot/layer.
4. **EMIT** — Write `variants.json`; chạy `build_extended.py`; in dòng confirmation; HALT.

## Failure handling
1. `mode=class-only` (default, hoặc fallback từ root-cause-only/all-triggered-rules khi thiếu field) → KHÔNG passthrough; craft technique-spread từ family (`evades_rule: null`), bắt buộc Read template trước. Khi là fallback (CRS không có rule để neo) → blind-spot thật, variant càng quan trọng để rule mới có breadth. (PoC-only passthrough KHÔNG ở skill này — đó là `gen-variants=off` xử lý bởi crs-retrieve-analyze, không spawn skill.)
2. `probe-input.json` thiếu/hỏng → HALT, in một dòng báo lý do (Stage 1 chưa chạy hoặc artifact lỗi).
3. all-triggered-rules: index TSV missing/stale → `python .claude/skills/crs-retrieve-analyze/tools/build_rule_index.py` rồi proceed; rule id absent khỏi index → bỏ target đó, không fabricate file/line.
4. `build_extended.py` abort (envelope drift) → sửa variant cho khớp envelope PoC, chạy lại; KHÔNG sửa script để bỏ qua check.
