---
name: crs-rule-author
description: Stage 3 primary của pipeline CRS rule-generation. Nhận verdict (not-covered hoặc covered+force-candidates) + Nuclei template + extended-requests (PoC + biến thể từ crs-variant-gen Stage 2), synthesize MỘT CRS SecRule mới từ zero với RAG từ comibined-docs. Thiết kế variable scope, operator, transform pipeline, phase, anomaly scoring; chọn rule ID không conflict; bắt attack class bao phủ cả PoC lẫn extended variants. HALT nếu scope_gate ∈ {out-of-scope-structural, virtual-patch-only} hoặc covered+candidate_rules rỗng. Verify bằng engine (verify_rule.py) trước khi emit — max 3 vòng. Write-only → out/<id>/new.json. KHÔNG commit vào coreruleset.
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

# CRS Rule Author (Action B — primary)

Thực thi stage **rule synthesis**: `Ingest → Design → Synthesize → Verify → Emit`.
Input: `out/<template_id>/verdict.json` (Stage 1) → distill qua `parse_verdict.py` → `out/<template_id>/author-context.json` (model đọc file này, KHÔNG đọc verdict.json) + Nuclei template `.yaml` gốc + `out/<template_id>/extended-requests.json` (Lane 2, từ crs-variant-gen — PoC + biến thể, là design target). Chạy khi **not-covered**, hoặc **covered+force-candidates** (complementary mode — lấp gap class/PL chưa phủ).
Output: đúng **một** artifact `out/<template_id>/new.json` (recommendation type `new`) sau khi Verify engine pass.

> **WRITE-ONLY mặc định.** Deliverable duy nhất là recommendation artifact. KHÔNG phát SecRule / reasoning / metadata ra conversation trừ khi user yêu cầu tường minh. Toàn bộ thiết kế serialize vào artifact. Khi hoàn tất, in **đúng một dòng**: `out/<id>/new.json — new rule: <rule_id> @ <target_file>`.

In scope: thiết kế detection logic + metadata cho rule MỚI, recommend (không commit).
Out of scope: sửa rule có sẵn (→ `crs-rule-fix`), edit/ghi file trong `coreruleset/`, invoke skill khác.

Companion file (load on-demand đúng stage cần):
- `reference.md` → ##RAG-MAP (Design), ##ID-RANGES + ##SKELETON + ##SCHEMA (Synthesize/Emit), Anti-Patterns + Red Flags.

---

## State machine

| State | Action | Transition (guard → next) |
|-------|--------|---------------------------|
| INGEST | đọc verdict/candidate input | scope_gate ∈ {out-of-scope-structural, virtual-patch-only} → STOP · covered & candidate_rules == [] → STOP · ngược lại → DESIGN |
| DESIGN | thiết kế detection logic (set/tăng `iter`) | → SYNTHESIZE |
| SYNTHESIZE | viết rule + check metadata gate | metadata fail (no-deny/metadata-tiered/transforms-mandatory/id-placeholder) → SYNTHESIZE (fix tại chỗ, không thoát) · ok → VERIFY |
| VERIFY | probe rule, đọc triggered | all triggered → EMIT · parse_ok=false → SYNTHESIZE (fix syntax, `iter` không tăng) · any triggered=false & iter<3 → DESIGN (iter++) · any triggered=false & iter=3 → EMIT (residual gap) |
| EMIT | xuất rule (pass hoặc residual gap) | → STOP |

Tuần tự nghiêm ngặt. Không skip stage. **Iteration counter**: khởi tạo `iter=1` tại VERIFY lần đầu; mỗi lần VERIFY fail loop về DESIGN tăng `iter`. EMIT chỉ xảy ra sau VERIFY — hoặc pass (all triggered), hoặc terminal (iter=3). Metadata fail phát hiện cuối SYNTHESIZE → fix trong SYNTHESIZE, không thoát sang VERIFY.

---

## HARD GATES — vi phạm một gate là invalidate cả stage

<HARD-GATE id="input-guard">
Sau khi chạy `parse_verdict.py`, đọc `coverage` + `scope_gate.decision` trong `author-context.json` (KHÔNG tự đọc verdict.json để phán).

**Bước 0 — scope_gate (chạy TRƯỚC mọi branch coverage):** nếu `scope_gate.decision` ∈ {`out-of-scope-structural`, `virtual-patch-only`} → **HALT ngay**, KHÔNG synthesize. Rule-author chỉ làm **generic CRS rule**; hai class này ngoài năng lực đó:
- `out-of-scope-structural` → in: `out/<id> — no rule synthesizable: <decision> (structural WAF blind spot — no content signature exists)`. Author bất kỳ rule nào ở đây = `@rx` khít literal PoC → FP magnet (vi phạm anti-pattern).
- `virtual-patch-only` → in: `out/<id> — no rule synthesizable: virtual-patch-only (needs deployment-specific path+missing-header rule, outside generic CRS scope — author manually per scope_gate.rationale)`. Rule khả thi nhưng app-specific (endpoint-cứng + điều kiện vắng header), không hợp ID range CRS, không phải đóng góp upstream → để content team tự viết theo `scope_gate.rationale`.

`scope_gate.decision == in-scope` (hoặc `scope_gate` null = covered/legacy) → tiếp các branch coverage dưới đây.

- `not-covered` → chạy bình thường (greenfield / gap-fill).
- `covered` **và** `candidate_rules` non-empty (= verdict chạy force-candidates) → **complementary mode**: rule mới phải lấp phần `already_covered_by` CHƯA phủ (vd gap PL1 khi `pl_gap.pl1_blocks=false`, hoặc class khác như Python code-injection vs shell-only), TUYỆT ĐỐI không nhân bản rule đã cover.
- `covered` **và** `candidate_rules` rỗng → terminal, HALT ngay (CRS đã cover, không có related rule để bổ sung).
</HARD-GATE>

<HARD-GATE id="no-deny">
Detection rule dùng `block` + anomaly scoring `setvar`: `setvar:'tx.inbound_anomaly_score_plN=+%{tx.<severity>_anomaly_score}'` (N = paranoia level; severity map → score variable theo ##SKELETON). TUYỆT ĐỐI không `deny`/`drop`/`redirect`/`status` trong detection rule. `block` delegate cho `SecDefaultAction`.
</HARD-GATE>

<HARD-GATE id="metadata-tiered">
Theo policy detection-first (`comibined-docs/modsec-docs/metadata/required-metadata.md`):
- **Tier 1 (luôn emit):** `id` (đúng range), `phase` (numeric), `block`, `severity`, scoring `setvar`, `tag:'paranoia-level/N'` (chỉ khi PL>1), `capture` (khi logic/logdata ref `%{TX.n}`).
- **Tier 2 (emit):** `msg`, `logdata`.
- **Tier 3 (SKIP trừ khi user yêu cầu release-ready):** `ver`, `rev`, classification tag (`OWASP_CRS`, `attack-*`, `application-*`, `language-*`, `platform-*`, `capec/*`), `maturity`, `accuracy`. Attack family/platform ghi vào prose trace của artifact, không cần encode thành tag.
Thiếu Tier 1 = invalid. (Lưu ý: list "required" trong CLAUDE.md gồm cả ver/maturity/accuracy — đó là cho rule release-ready; recommendation theo tier ở đây.)
</HARD-GATE>

<HARD-GATE id="transforms-mandatory">
String/regex matching PHẢI có transform pipeline chống bypass (baseline `t:none,t:urlDecodeUni,t:lowercase`; bổ sung theo encoding quan sát ở `payload_samples` + `classification.injection_point`). Author-context KHÔNG cấp transform list sẵn — tự suy transform từ encoding của payload. Operator chuyên dụng (`@detectSQLi`, `@detectXSS`) có normalize riêng — vẫn cite lý do.
</HARD-GATE>

<HARD-GATE id="id-placeholder">
Rule ID dùng **placeholder** `<fileID>XXX` (vd `934XXX`, fileID lấy từ tên `target_file`) — hoặc `9XXXXX` nếu chưa rõ file. KHÔNG resolve exact ID, KHÔNG Grep `coreruleset/` tìm id trống: deliverable là recommendation, allocation chính xác để version sau. Chỉ cần đúng file prefix (zero-cost từ filename).
</HARD-GATE>


<HARD-GATE id="rag-grounded">
Mọi lựa chọn operator / variable / transform PHẢI justify được bằng `comibined-docs/` (cite path/section inline trong `design_rationale` của artifact — KHÔNG có array `rag_citations` riêng). Không invent cú pháp ModSecurity từ trí nhớ — verify bằng RAG.
</HARD-GATE>

<HARD-GATE id="no-manual-dump">
KHÔNG full-`Read` 4 catalog lớn `reference-*.md` (operators/variables/transforms/actions, ~108KB) hay `nuclei-template-format.md`. Theo tiered retrieval (##RAG-MAP): menu lấy ở `*_category.md` (nhỏ, đọc đúng dimension đang quyết); edge-case của một entry → `Grep` đúng tên đó trong `reference-*.md` với `-A` vài dòng. Nuốt cả manual vào context là vi phạm.
</HARD-GATE>

<HARD-GATE id="terminal">
Sau khi artifact write → HALT. Không commit vào `coreruleset/`, không author thêm rule, không invoke `crs-rule-fix` hay skill khác.
</HARD-GATE>

> Anti-Patterns + Red Flags đầy đủ ở `reference.md`. Tham chiếu khi định shortcut.

---

## INGEST

1. **Parse verdict bằng script** — KHÔNG `Read` cả `verdict.json` (nhiều noise: raw `matched_rules` + full tag arrays + protocol/SQLi FP collateral). Script project về whitelist + tính sẵn tín hiệu probe:
   ```bash
   python .claude/skills/crs-rule-author/tools/parse_verdict.py \
     out/<id>/verdict.json out/<id>/author-context.json
   ```
   **Read `out/<id>/author-context.json`** (đã gọn). Guard gate `input-guard`: **trước hết** check `scope_gate.decision` (out-of-scope-structural / virtual-patch-only → HALT), rồi mới tới `coverage` + `candidate_rules`.
   **Read `out/<id>/extended-requests.json`** nếu tồn tại (output của crs-variant-gen). Đọc `labels[]` + `meta[]` để biết tên và rationale mỗi variant — đây là **design target**: rule phải bao phủ mọi request trong này. **Không tồn tại (variant lane off/skip) → KHÔNG block:** `verify_rule.py` tự fallback verify PoC-only từ `probe-input.json` (Stage 1 luôn ghi). Khi không có variant, gánh nặng class-coverage dồn hết vào **design reasoning** (generalize PoC → attack class, anti-pattern "match literal PoC"), vì engine chỉ verify được PoC — thiết kế precise theo class, đừng chỉ khít PoC.
2. Đọc các field trong context:
   - `classification` — `families`, `injection_point`, `severity`, `protocol`, `cwe_hint`, `confidence` (carry vào artifact `confidence`).
   - `payload_samples` — base PoC (poc; dùng để hình dung attack class khi thiết kế).
   - `scope_signal` — **`engine_confirmed_var`** = scope do engine **xác nhận** (ưu tiên hơn `injection_point` prose). Rỗng ⇒ không rule nào fire → fallback `injection_point`. `off_class_on_var` + `note`: nhiều rule off-class cùng nổ ⇒ payload nhiễu heuristic → thiết kế **precise**, không bắt chước các rule rộng.
   - `pl_gap` — `pl1_blocks`/`pl2_blocks` định vị PL cho rule mới (`pl1_blocks=false` ⇒ rule PL1 có giá trị thật: block ở deployment mặc định). Đây là tín hiệu *định vị*, KHÔNG phải tín hiệu thiết kế detection.
   - `candidate_rules` (đã rank) + `target_file_hint` — few-shot idiom.
   - `already_covered_by` (chỉ khi covered+force-candidates) — rule CRS đang cover + **cơ chế** (`operator`/`pattern_excerpt`/`trigger_explanation`): vừa là few-shot giàu nhất, vừa là danh sách **tránh nhân bản** — rule mới nhắm phần chưa phủ.
3. **Read** Nuclei template `.yaml` gốc cho full fidelity (request layout, mọi matcher, header/method/path, **Content-Type**) — context chỉ mang sample. Operational signal (vd body cần Content-Type đúng để kích body processor) tự suy từ template.
4. **Chốt `target_file`**: dùng `target_file_hint` (= file candidate rank cao nhất); **override** bằng `classification.families` + bảng class→file (##ID-RANGES) nếu class thật khác hint (vd Python code-injection → `934` thay vì shell-only `932`). `candidate_rules` rỗng → classify thẳng từ family. Chốt **phase** từ scope: query/args/body → `phase:2`, header/cookie → `phase:1` (hoặc 2 nếu cần body), response → `phase:4`.

## DESIGN

Thiết kế detection logic theo tiered retrieval (##RAG-MAP, gate `no-manual-dump`). Common path dùng Tier 0 (baked ##SKELETON); chỉ mở category file khi lựa chọn chưa chắc; drill-down Grep khi cần edge-case. Mỗi quyết định cite nguồn inline trong `design_rationale`.

**Few-shot (index-TSV-first — mượn strategy `no-conf-read` của Stage 1):** với rule rank cao nhất trong `candidate_rules`, lấy idiom **từ index TSV trước**: `Grep ^<id>\t` (`output_mode:content`) trên `.claude/skills/crs-retrieve-analyze/index/<fileid>.tsv` (fileid = 3 số đầu `id`) → 1 row ~200 char chứa **trọn skeleton**: `variables` (scope), `transforms`, `phase`, `pl`, `severity`, `chain` — đủ mượn cấu trúc, **0 regex noise**. CHỈ `Read coreruleset/rules/<file>` (`offset=line-1, limit=40`; `line` lấy từ `candidate_rules`/index) khi **thật cần** xem regex pattern thật hoặc thứ tự action string. **KHÔNG** `Grep id:<id>` trên `.conf` — kéo cả dòng SecRule chứa regex ~12KB/dòng (machine-generated), phí token, đúng cái Stage 1 cấm. Mượn **cấu trúc**, KHÔNG copy nguyên (candidate đã *trượt root-cause* nên detection chưa đủ). Khi có `already_covered_by` (complementary mode), `pattern_excerpt`/`trigger_explanation` ở đó là few-shot **giàu nhất** (cơ chế rule thật đang bắt) — đồng thời là ranh giới *tránh nhân bản*: nhắm phần class/PL chưa phủ. `candidate_rules` rỗng → greenfield thuần từ ##SKELETON.

> Index là artifact dùng chung (Stage 1 build). Missing/stale → regenerate `python .claude/skills/crs-retrieve-analyze/tools/build_rule_index.py`, hoặc fallback `Read` block `.conf` bằng `candidate_rules[].line` đã có sẵn.
1. **Variable scope + phase** — payload nằm ở đâu? Chọn scope + đọc luôn phase ở `variables_category.md` (có cột Phase). Body JSON/XML → check `REQBODY_PROCESSOR` + ##Request Body Handling (`directives_category.md`); processor không chắc active → thêm scope `REQUEST_BODY`.
2. **Operator** — `@rx` / `@pm`·`@pmFromFile` / `@detectSQLi`·`@detectXSS`. Menu: `operators_category.md`.
3. **Transform pipeline** — baseline `t:none,t:urlDecodeUni,t:lowercase`; bổ sung theo encoding payload (quan sát `payload_samples` + injection_point). Menu: `transforms_category.md` (chú ý thứ tự, `t:none` mở đầu).
4. **Chain** (nếu cần giảm FP) — vd chain endpoint-specific (`REQUEST_FILENAME`) trước token match. **Chain ⇒ PL≥2** (PL1 chỉ atomic, không chain — rule-authoring-standards); dùng chain thì bump PL + score var `_pl2`. Action order: `setvar` sau `severity`, `chain` **cuối** string. Chỉ khi chain mới Read section liên quan của `chaining-secrules.md`.
5. **Paranoia level** — chọn theo bảng PL ở ##SKELETON: pattern unambiguous + no-FP → PL1; chain → ≥PL2; lookaround/macro → ≥PL3. Token rộng/FP cao → PL cao hơn, không ép PL1. Anomaly score theo severity (baked).

## SYNTHESIZE

Build SecRule theo ##SKELETON (reference.md):
1. Gán rule ID placeholder `<fileID>XXX` (gate `id-placeholder`) — không resolve exact.
2. Điền metadata theo tier (gate `metadata-tiered`): Tier 1 + Tier 2 luôn; Tier 3 chỉ khi release-ready.
3. Action block: `block` + `setvar` anomaly (gate `no-deny`).
4. Nếu cần regex mới: viết pattern bắt class, ghi kèm bản `.ra` source đề xuất (CRS convention: regex sống ở `regex-assembly/`).
5. **Metadata checklist trước khi thoát SYNTHESIZE** (fail → fix tại chỗ, không thoát):
   - `no-deny`: không có `deny`/`drop`/`redirect`/`status`.
   - `metadata-tiered`: Tier 1 đủ (`id`, `phase` numeric, `block`, `severity`, `setvar` anomaly); `msg` + `logdata` (Tier 2).
   - `transforms-mandatory`: có `t:none` mở đầu + ít nhất `t:urlDecodeUni,t:lowercase` (hoặc lý do rõ ràng nếu dùng operator chuyên dụng).
   - `id-placeholder`: id là `<fileID>XXX` hoặc `9XXXXX`, không phải số thực.

## VERIFY — engine là trọng tài

Gate thật thay cho self-assertion. Đóng fail-open #1 (parse syntax) và blind-spot #2 (variant coverage).

```bash
python .claude/skills/crs-rule-author/tools/verify_rule.py \
  out/<id>/new.json out/<id>/extended-requests.json out/<id>/verify-report.json
```

**Read `out/<id>/verify-report.json`** (nhỏ, model chỉ đọc cái này — không đọc probe-raw):
```json
{"parse_ok": true, "paranoia": 2, "rule_id_placeholder": "934XXX",
 "requests": [
   {"label": "poc",          "triggered": true,  "matched_value": "__import__("},
   {"label": "variant:exec", "triggered": false}
 ]}
```

**Gate (engine phán, không phải LLM):**
- `parse_ok: false` → rule không compile → **không EMIT**, loop về SYNTHESIZE (fix syntax; iteration không tăng).
- Bất kỳ `triggered: false` **và** `iter < 3` → rule chưa bao đủ → loop về **DESIGN** (tăng iter, mở rộng pattern/scope bao variant lọt; ghi label nào lọt + `meta[].rationale` của nó vào context thiết kế).
- Bất kỳ `triggered: false` **và** `iter = 3` → **terminal**: EMIT với `triggered: false` labels ghi vào `design_rationale` (residual gap) + hạ `confidence` xuống `medium` hoặc `low`.
- Mọi `triggered: true` → **pass** → sang EMIT.

> **Engine constraint** (proposal §6 + probe-engine README): `--candidate-rule-file` load sau rule 949 → trigger hiện trong `matched_rules` nhưng anomaly score KHÔNG được 949 đếm trong cùng run. VERIFY chỉ xác nhận **trigger/fire**, KHÔNG xác nhận scoring/block. Claim scoring (vd "shift score 3→8, crosses threshold") ghi vào `design_rationale` dạng "chưa engine-verified" — không loại bỏ, chỉ đánh dấu. Verify full CRS (không harness một-rule) đảm bảo fidelity transform pipeline (JSON body processor, phase resolution).

> **PoC-only mode** (verify-report chỉ có label `poc`, không variant — variant lane off/skip): VERIFY chỉ chứng minh rule bắt **PoC**, KHÔNG chứng minh nó generalize sang bypass cùng class (blind-spot #2 KHÔNG được engine đóng ở run này). Khi đó: (a) bắt buộc generalize theo class ở DESIGN — KHÔNG viết `@rx` khít literal PoC (anti-pattern "match literal PoC"); (b) ghi rõ trong `design_rationale` rằng class-breadth là "chưa engine-verified" (giống Tier-B của scoring); (c) **KHÔNG** `confidence: high` chỉ vì PoC pass — cap `medium` trừ khi class hẹp/unambiguous tới mức một construct là toàn bộ class. ALL PASS (1/1) ở mode này KHÔNG đồng nghĩa rule đủ rộng.

## EMIT — terminal (WRITE-ONLY)

Serialize `out/<id>/new.json` theo ##SCHEMA. Toàn bộ rule + rationale + RAG citation nằm **trong artifact**.
- `class_coverage` PHẢI phản ánh kết quả VERIFY: với mỗi request trong extended-requests, ghi `{"payload": "<label>", "matched": <triggered>, "why": "..."}`. Nếu iter=3 terminal: `matched: false` entries giữ nguyên + ghi vào `design_rationale` (residual gap) + `confidence` hạ xuống `medium`/`low`.
- Sau khi write: in **đúng một dòng** `out/<id>/new.json — new rule: <rule_id> @ <target_file>`. Không gì khác. HALT.

Exception: chỉ present nội dung artifact khi user request tường minh (vd "show the rule", "explain design").
Không exit nào khác được phép (commit coreruleset, tạo thêm rule, invoke skill).

---

## Checklist (tạo task, complete theo thứ tự)

1. **INGEST** — chạy `parse_verdict.py` → Read `author-context.json` (KHÔNG đọc verdict.json); guard `input-guard`: check `scope_gate.decision` trước (out-of-scope-structural/virtual-patch-only → HALT), rồi `coverage`+`candidate_rules`; đọc classification / payload_samples / scope_signal / pl_gap / candidate_rules / already_covered_by; Read `extended-requests.json` nếu có (labels + meta = design target); Read Nuclei template; chốt target_file (từ `target_file_hint`, override theo family) + phase (từ scope).
2. **DESIGN** — (few-shot từ candidate_rules / already_covered_by) variable scope (ưu tiên `engine_confirmed_var`) / operator / transform / chain / PL (định vị từ `pl_gap`); khi có extended-requests: rule phải thiết kế để bao phủ mọi variant label, ghi từng label vào context design. Mỗi quyết định cite RAG.
3. **SYNTHESIZE** — id placeholder `<fileID>XXX`; metadata Tier 1+2; action block `block`+anomaly; (nếu cần) regex + `.ra` source; metadata checklist (no-deny / metadata-tiered / transforms-mandatory / id-placeholder) cuối SYNTHESIZE — fail thì fix tại chỗ.
4. **VERIFY** — chạy `verify_rule.py new.json extended-requests.json verify-report.json`; Read `verify-report.json`; engine gate: `parse_ok=false` → fix syntax trong SYNTHESIZE (loop, iter không tăng); `triggered=false` & iter<3 → DESIGN loop (tăng iter); iter=3 terminal → sang EMIT; all triggered → sang EMIT.
5. **EMIT** — serialize `out/<id>/new.json` (class_coverage phản ánh verify-report: triggered entries + residual gap nếu terminal); in dòng confirmation; HALT.

## Failure handling
0. `scope_gate.decision` ∈ {`out-of-scope-structural`, `virtual-patch-only`} → HALT trước mọi xử lý, in một dòng `no rule synthesizable` (xem gate `input-guard` bước 0); không synthesize. Đây KHÔNG phải lỗi — là terminal hợp lệ của pipeline cho lớp vuln ngoài tầm content-inspection.
1. `coverage == "covered"` **và** `candidate_rules == []` (CRS đã cover, không related rule) hoặc thiếu `classification` → HALT, in một dòng báo lý do; không tạo rule. (covered + candidate_rules non-empty → complementary mode, vẫn chạy.)
2. Không xác định được variable scope (template sparse) → chọn scope rộng hợp lý + ghi `confidence: low` trong artifact, proceed.
3. Không chắc fileID (`candidate_rules` rỗng và family mơ hồ) → `target_file` = `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf`, id `934XXX` (hoặc `9XXXXX`); không cố resolve.
4. Không tìm thấy RAG support cho một operator/transform định dùng → đổi sang cái có doc, không invent.
5. `extended-requests.json` không tồn tại (variant lane off/skip) → `verify_rule.py` **tự fallback** verify PoC-only từ `probe-input.json` (Stage 1 luôn ghi), KHÔNG block. Chỉ exit lỗi khi **cả** `extended-requests.json` lẫn `probe-input.json` đều thiếu → khi đó báo user chạy Stage 1 trước. KHÔNG bỏ qua VERIFY.
6. VERIFY `parse_ok: false` (syntax error) → đọc `error` field từ probe-engine output nếu có; fix syntax ở SYNTHESIZE; không tăng iter; chạy lại VERIFY.
7. VERIFY `triggered: false` sau iter=3 → EMIT với residual gap rõ ràng trong `design_rationale` (liệt kê label lọt + `meta[].rationale` từ extended-requests) + `confidence: low`; KHÔNG drop âm thầm, KHÔNG loop tiếp.
