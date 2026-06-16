---
name: crs-variant-gen
description: Stage 2 pre-step (Lane 2) của pipeline CRS rule-generation. Sinh một nhúm request biến thể CÙNG attack-class với PoC nhưng rơi NGOÀI vùng regex của các rule đang phủ payload, để New-rule Generator (crs-rule-author) thiết kế rule có breadth ngay từ vòng đầu và Lane-4 Verify có đủ request để engine chấm. Đọc verdict.json (focused = root_cause_rules / aggressive = matched_rules; KHÔNG dùng candidate_rules), clone shape probe-input, craft regex-aware. KHÔNG probe, KHÔNG đọc rule candidate mới, KHÔNG author rule. Write-only → out/<id>/extended-requests.json.
model: claude-sonnet-4-6
effort: high
allowed-tools:
  - Read
  - Grep
  - Glob
  - Write
  - Bash(python *)
---

# CRS Variant Generator (Lane 2)

Thực thi stage **variant synthesis**: `Ingest → Select-Targets → Craft-Variants → Emit`.
Input: `out/<template_id>/verdict.json` (Stage 1) → distill qua `parse_targets.py` → `out/<template_id>/variant-context.json` (model đọc file này, KHÔNG đọc verdict.json) + `out/<template_id>/probe-input.json` (shape request gốc để clone).
Output: đúng **một** artifact `out/<template_id>/extended-requests.json` (PoC + variants, batch-ready cho Verify).

Mục tiêu (proposal §4): cho New-rule Generator vài biến thể **đủ chất lượng** — KHÔNG phải bypass-fuzzer. Chạy **một pass**, **không probe**. Variant là **design fodder heuristic**: có thể craft hụt (thực ra vẫn bị rule cũ bắt) cũng không sao — guarantee duy nhất nằm ở Lane-4 Verify.

> **WRITE-ONLY mặc định.** Deliverable duy nhất là `extended-requests.json`. KHÔNG phát variant/reasoning ra conversation trừ khi user yêu cầu tường minh. Khi hoàn tất, in **đúng một dòng**: `out/<id>/extended-requests.json — <mode>: <n> variant(s)`.

In scope: craft request biến thể cùng class, clone shape PoC.
Out of scope: probe engine, author/patch rule (→ `crs-rule-author`/`crs-rule-fix`), đọc rule candidate mới, invoke skill khác.

Companion file (load on-demand): `reference.md` → ##CRAFT-PLAYBOOK (regex-aware crafting per class), ##SCHEMA (variants.json / extended-requests.json), Anti-Patterns + Red Flags.

---

## State machine

```
INGEST ──► SELECT-TARGETS ──► CRAFT-VARIANTS ──► EMIT ──► STOP
   │            │
   │            └─ targets == [] (focused & no root_cause) ─► EMIT passthrough (chỉ PoC) ─► STOP
   └─ probe-input.json thiếu ─► HALT (báo lý do)
```
Tuần tự nghiêm ngặt. Không skip stage.

---

## HARD GATES — vi phạm một gate là invalidate cả stage

<HARD-GATE id="no-probe">
TUYỆT ĐỐI không gọi `probe-engine` (không có trong allowed-tools). Variant là design fodder heuristic, KHÔNG phải claim bypass đã chứng thực. Verification trigger/fire là việc **độc quyền** của Lane-4 Verify (`verify_rule.py`). Không tự "kiểm" variant bằng bất kỳ engine nào ở đây.
</HARD-GATE>

<HARD-GATE id="isolation">
KHÔNG đọc `out/<id>/new.json` (rule candidate — có thể chưa tồn tại, hoặc của lần chạy trước). Variant chỉ được thấy regex **rule CŨ** (target rule trong verdict), KHÔNG thấy regex sắp viết. Đây là cơ chế cắt shared-context của blind-spot #2 — variant-gen chạy trước New-rule Generator chính vì lý do này. Đọc new.json = phá isolation.
</HARD-GATE>

<HARD-GATE id="target-source">
Target rule lấy theo **mode** (`variant-context.json.mode`), KHÔNG bao giờ từ `candidate_rules`:
- **focused** (default) → `targets` = root-cause rules, pattern_excerpt đã inline trong context.
- **aggressive** (`--aggressive`) → `targets` = matched_rules (id-only), pattern đọc từ `.conf` qua index.
`targets == []` (focused + not-covered) → KHÔNG craft variant, EMIT passthrough chỉ PoC.
</HARD-GATE>

<HARD-GATE id="bounded-read">
Đọc pattern **chỉ** của target rule, bounded:
- focused → pattern_excerpt có sẵn trong context, **KHÔNG đọc file**.
- aggressive → mỗi id: `Grep ^<id>\t` trên `.claude/skills/crs-retrieve-analyze/index/<fileid>.tsv` lấy `file`/`line`/`operator`; chỉ `Read coreruleset/rules/<file>` (`offset=line-1, limit=40`) khi `operator`=`@rx`. Cap **≤8 rule**, ưu tiên rule có tag `attack-*` (bỏ qua protocol 920/921 — evade chúng vô nghĩa cho detection).
KHÔNG full-`Read` `.conf`, KHÔNG cày corpus `.ra`, KHÔNG `Grep id:<id>` trên `.conf` (kéo regex body ~12KB/dòng).
</HARD-GATE>

<HARD-GATE id="class-valid">
Mỗi variant PHẢI là exploit **hợp lệ cùng attack-class** với template (xét theo `classification.families` + cơ chế vuln từ template/payload), chỉ khác ở chỗ **rơi ngoài** vùng pattern target. KHÔNG craft chuỗi rác/ngẫu nhiên chỉ để "khác PoC". Variant vô nghĩa làm Verify pass/fail sai → thiết kế rule lệch. Đa dạng kỹ thuật: khi có target, **≤6 variant** và **≥2 kỹ thuật né khác nhau**.
</HARD-GATE>

<HARD-GATE id="shape-fidelity">
Mỗi variant clone **đúng envelope** PoC từ `probe-input.json`: `method` + `headers` giữ nguyên; chỉ đổi payload tại injection slot (`body` hoặc `uri`). Model tự viết full request với escaping đúng (JSON body 2 lớp như Stage 1). `build_extended.py` validate envelope — drift (đổi method/path, drop header) → script abort. Sửa variant, KHÔNG nới validation.
</HARD-GATE>

<HARD-GATE id="terminal">
Sau khi `extended-requests.json` write → HALT. Không probe, không author rule, không invoke `crs-rule-author`/`crs-rule-fix`/skill khác.
</HARD-GATE>

> Anti-Patterns + Red Flags đầy đủ ở `reference.md`. Tham chiếu khi định shortcut.

---

## INGEST

1. **Distill verdict bằng script** — KHÔNG `Read` cả `verdict.json`. Mode mặc định focused; thêm `--aggressive` khi user/orchestrator yêu cầu breadth:
   ```bash
   python .claude/skills/crs-variant-gen/tools/parse_targets.py \
     out/<id>/verdict.json out/<id>/variant-context.json [--aggressive]
   ```
   **Read `out/<id>/variant-context.json`**. Field: `classification` (families/injection_point/protocol — xác định class + slot), `payload_samples` (base PoC), `paranoia` (carry cho Verify), `mode`, `targets`.
2. **Read `out/<id>/probe-input.json`** — shape request gốc (method/uri/headers/body). Đây là envelope mọi variant phải clone. Định vị injection slot bằng `classification.injection_point` + đối chiếu `payload_samples[].value` trong body/uri.
3. *(tùy chọn, light)* Nếu cơ chế vuln chưa rõ từ context, **Read** Nuclei template `.yaml` (`template_path`) để hiểu class exploit đủ craft variant hợp lệ — KHÔNG để probe.
4. Guard: `targets == []` (focused + not-covered) → bỏ qua CRAFT, sang EMIT passthrough. `probe-input.json` thiếu → HALT.

## SELECT-TARGETS

Hiểu **vùng pattern** mỗi target rule neo vào (để craft rơi ngoài):
- **focused**: `targets[].pattern_excerpt` + `trigger_explanation` đã có sẵn → đọc thẳng, KHÔNG mở file. (vd 932240: `trigger_explanation` chỉ rõ neo shell-token quanh `cat /etc/passwd`.)
- **aggressive**: với mỗi target (ưu tiên `attack-*`, cap ≤8, bỏ 920/921), `Grep ^<id>\t` index lấy `file`/`line`/`operator`; `@rx` → `Read` block (`offset=line-1, limit=40`) lấy regex; `@pmFromFile` → ghi tên data file (suy keyword class), `@detectSQLi`/`@detectXSS` → engine name. Gate `bounded-read`.

Với mỗi target, tóm tắt 1 dòng: rule này bắt **construct nào** → khoảng trống nào của class nằm **ngoài** nó. Đây là input thiết kế variant.

## CRAFT-VARIANTS

Suy luận **regex-aware** (##CRAFT-PLAYBOOK):
1. Cùng `classification.families`, cùng cơ chế vuln, nhưng dùng construct **rơi ngoài** vùng pattern target (vd target neo `/etc/passwd` shell-path → craft `exec("...")`/`eval(...)`/`compile(...,'exec')` thuần Python không có shell-path).
2. Mỗi variant clone envelope PoC, đặt payload vào injection slot, **escape đúng** (body JSON 2 lớp như `probe-input.json`).
3. Gate `class-valid`: ≤6 variant, ≥2 kỹ thuật khác nhau; mỗi variant ghi `evades_rule` (id target nó nhắm né) + `rationale` (vì sao rơi ngoài pattern).
4. **KHÔNG** test lại bằng engine (gate `no-probe`).

## EMIT — terminal (WRITE-ONLY)

1. **Write `out/<id>/variants.json`** (judgment model viết) theo ##SCHEMA: `variants[]` = `{label, evades_rule, rationale, request{method,uri,headers,body}}`. Passthrough (targets rỗng) → `{"variants": []}`.
2. **Assemble** (script lo cơ học: validate envelope + bundle PoC + variants):
   ```bash
   python .claude/skills/crs-variant-gen/tools/build_extended.py \
     out/<id>/probe-input.json out/<id>/variants.json out/<id>/extended-requests.json
   ```
   - Script abort (envelope drift) → đọc message, sửa `variants.json`, chạy lại. KHÔNG nới validation.
3. In **đúng một dòng** `out/<id>/extended-requests.json — <mode>: <n> variant(s)`. HALT.

Exception: chỉ present nội dung artifact khi user request tường minh.

---

## Checklist (tạo task, complete theo thứ tự)

1. **INGEST** — chạy `parse_targets.py` (mode-gated) → Read `variant-context.json` + `probe-input.json`; định vị injection slot; (tùy chọn) Read template; guard `targets==[]`.
2. **SELECT-TARGETS** — focused: đọc `pattern_excerpt`/`trigger_explanation` inline; aggressive: index lookup + Read block `@rx` (cap ≤8, ưu tiên attack-*); tóm tắt vùng pattern mỗi rule.
3. **CRAFT-VARIANTS** — regex-aware, cùng class rơi ngoài pattern; ≤6 variant, ≥2 kỹ thuật; clone envelope + escape; ghi evades_rule + rationale.
4. **EMIT** — Write `variants.json`; chạy `build_extended.py`; in dòng confirmation; HALT.

## Failure handling
1. `targets == []` (focused + not-covered) → EMIT passthrough (`variants: []` → extended-requests chỉ có PoC); in dòng confirmation với `n=0`. Muốn variant → rerun `--aggressive`.
2. `probe-input.json` thiếu/hỏng → HALT, in một dòng báo lý do (Stage 1 chưa chạy hoặc artifact lỗi).
3. aggressive: index TSV missing/stale → `python .claude/skills/crs-retrieve-analyze/tools/build_rule_index.py` rồi proceed; rule id absent khỏi index → bỏ target đó, không fabricate file/line.
4. `build_extended.py` abort (envelope drift) → sửa variant cho khớp envelope PoC, chạy lại; KHÔNG sửa script để bỏ qua check.
