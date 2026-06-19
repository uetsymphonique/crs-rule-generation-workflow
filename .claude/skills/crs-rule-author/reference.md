# crs-rule-author — Reference

Load on-demand (DESIGN cần RAG-MAP; SYNTHESIZE/EMIT cần ID-RANGES + SKELETON + SCHEMA). SKILL.md giữ phần mandatory.

---

## RAG-MAP — tiered retrieval protocol (gate `no-manual-dump`)

Quy tắc: **không bao giờ full-`Read` `reference-*.md`** (4 catalog lớn ~108KB) hay `nuclei-template-format.md`. Lấy menu ở `*_category.md` (nhỏ, đã distilled), drill-down bằng Grep một entry. Token: điển hình 1–2 category file thay vì cả manual.

### Tier 0 — baked (zero Read)
SKELETON + ID-RANGES (file này) đã chứa: anomaly setvar, severity→score, metadata tier, ID range, paranoia, regex best-practice, action set cố định (`block`/`setvar`/`capture`/`chain`/`t`/`ctl`). Đây là nguồn mặc định cho common path — không cần mở doc nào.

### Tier 1 — menu (`*_category.md`, chỉ đọc file của dimension đang quyết)
| Quyết định | Category file (size) | Ghi chú |
|---|---|---|
| operator | `modsec-docs/operators/operators_category.md` (6.3KB) | có cột `capture` |
| variable scope **+ phase** | `modsec-docs/variables/variables_category.md` (9.8KB) | **có cột Phase** → lấy luôn phase ở đây |
| transform | `modsec-docs/transforms/transforms_category.md` (5KB) | ghi chú thứ tự + "preferred over X" |
| action / ctl / marker | `modsec-docs/actions/actions_category.md` (8.5KB) | |
| body processor (JSON/XML/multipart) | `modsec-docs/directives/directives_category.md` (5.4KB) | Request Body Handling; xem `REQBODY_PROCESSOR` trong variables_category |

### Tier 2 — drill-down (Grep MỘT entry, `-A N`, KHÔNG full-Read)
Chỉ khi edge-case của một entry quyết định verdict (vd `@rx` có hỗ trợ capture group nào, transform decode đúng encoding nào):
`Grep` đúng tên entry trong `reference-*.md` tương ứng (`operators/`, `variables/`, `transforms/`, `actions/`) với `-A` vài dòng.

### CRS-policy guides (prose; phần lớn đã baked — Read theo section khi cần)
| Cần | Doc | Trạng thái |
|---|---|---|
| anomaly scoring / PL | `CRS-contents/2-.../anomaly-scoring-and-paranoia-levels.md` (4.9KB) | baked ở SKELETON |
| authoring standards (action order, PL constraints, ID scheme, formatting) | `CRS-contents/6-.../rule-authoring-standards.md` (≈5KB) | baked (action order + PL table ở SKELETON); Read khi cần formatting/sibling detail |
| metadata tier | `modsec-docs/metadata/required-metadata.md` (5.1KB) | baked (gate `metadata-tiered`) |
| SecRule syntax | `CRS-contents/3-.../secrule-syntax-and-metadata.md` (6.5KB) | baked ở SKELETON |
| regex convention | `CRS-contents/6-.../regex-conventions.md` (8.3KB) | Read khi viết regex phức tạp |
| chaining | `CRS-contents/6-.../chaining-secrules.md` (22.9KB) | **chỉ khi chain**; Read section liên quan |
| v3-unsupported actions | `modsec-docs/actions/not-supported-actions.md` | check khi định dùng action/`ctl:` lạ (vd `proxy`, `append`, `sanitise*`, `ctl:requestBodyLimit` — v2-only, KHÔNG dùng) |
| Nuclei format | `nuclei-docs/nuclei-template-format.md` (26KB) | **Grep field lạ**, KHÔNG full-Read (đã có `.yaml` thật) |
| Few-shot idiom (structure) | index TSV `crs-retrieve-analyze/index/<fileid>.tsv` | `Grep ^<id>\t` → variables/transforms/phase/pl/severity/chain (1 row, 0 regex). **KHÔNG** grep regex body `.conf` |
| Few-shot regex/action thật (chỉ khi cần) | `coreruleset/rules/<file>` | `Read offset=line-1, limit=40` (line từ index/candidate_rules) — KHÔNG Read full, KHÔNG `Grep id:<id>` |

---

## ID-RANGES — rule ID là placeholder (gate `id-placeholder`)

Deliverable là recommendation → **không resolve exact ID** (allocation chính xác để version sau, khỏi tốn token Grep ruleset).

- Dùng placeholder `<fileID>XXX` (vd `934XXX`), trong đó `fileID` = 3 chữ số trong tên `target_file` (`REQUEST-934-...` → `934`). Zero-cost, không cần đọc file.
- fileID không rõ → `9XXXXX`.
- Context (cho version sau): CRS range **900000–949999 inbound**, **950000–999999 outbound**; mỗi file cấp 1000 ID, detection rule cách nhau 10 (`9[fileID]100`, `...110`…). Allocation thực sẽ là "ID rule cuối trong file + 10" — KHÔNG làm ở stage này.

### class → target_file (fallback khi `candidate_rules` rỗng)
Ưu tiên lấy `target_file` từ `candidate_rules[].file` (rule rank cao nhất cùng class). Chỉ map từ `classification.families`/`cwe_hint` khi `candidate_rules` rỗng:

| family / class | target_file | fileID |
|---|---|---|
| sqli | `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` | 942 |
| xss | `REQUEST-941-APPLICATION-ATTACK-XSS.conf` | 941 |
| rce / cmdi (OS command) | `REQUEST-932-APPLICATION-ATTACK-RCE.conf` | 932 |
| lfi / path-traversal | `REQUEST-930-APPLICATION-ATTACK-LFI.conf` | 930 |
| rfi | `REQUEST-931-APPLICATION-ATTACK-RFI.conf` | 931 |
| php injection | `REQUEST-933-APPLICATION-ATTACK-PHP.conf` | 933 |
| java / deserialization / OGNL·SpEL / Log4Shell | `REQUEST-944-APPLICATION-ATTACK-JAVA.conf` | 944 |
| ssrf / ssti / node·ruby·perl code-injection / prototype-pollution / **generic·unknown** | `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf` | 934 |
| session-fixation | `REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf` | 943 |
| protocol violation / CRLF·smuggling·HPP | `REQUEST-920-PROTOCOL-ENFORCEMENT.conf` / `REQUEST-921-PROTOCOL-ATTACK.conf` | 920 / 921 |

Không xác định class → `934` (GENERIC), `confidence: low`.

---

## SKELETON — SecRule template (detection-first)

Cấu trúc: `SecRule VARIABLES "OPERATOR" "TRANSFORMS,ACTIONS"`.

```apache
SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx <pattern bắt class>" \
    "id:9XXXXX,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:lowercase,\
    msg:'<mô tả rule detect cái gì>',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}',\
    severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

### Quy tắc bắt buộc
- **`t:none` mở đầu** transform list (clear transform kế thừa từ `SecDefaultAction`), rồi mới tới các transform cụ thể.
- **`block`, không `deny`/`status`** (gate `no-deny`).
- **`phase` numeric** (`phase:2` request body/args, `phase:1` header, `phase:4` response body). Không `phase:request`.
- **`capture`** chỉ khi `logdata`/logic ref `%{TX.0}`.
- **`tag:'paranoia-level/N'`** chỉ khi PL>1.
- PL>1 dùng `tx.inbound_anomaly_score_pl2/3/4` tương ứng.

### severity → score variable
| severity | score var | default | dùng khi |
|---|---|---|---|
| `CRITICAL` | `%{tx.critical_anomaly_score}` | 5 | payload tấn công xác định, rõ ràng |
| `ERROR` | `%{tx.error_anomaly_score}` | 4 | rất khả năng tấn công, FP nhẹ |
| `WARNING` | `%{tx.warning_anomaly_score}` | 3 | pattern khả nghi, FP vừa |
| `NOTICE` | `%{tx.notice_anomaly_score}` | 2 | vi phạm policy / anomaly nhỏ |

### Chọn paranoia level (rule-authoring-standards)
| Điều kiện | PL tối thiểu |
|---|---|
| Pattern cụ thể, unambiguous, **không FP** | PL1 (atomic, **không chain**) |
| Cần chain | PL2 |
| Dùng lookaround / macro expansion | PL3 |
| Validate-everything theo RFC/allowlist | PL4 |
PL1 là hard "no false positive" — token rộng/mơ hồ phải lên PL cao hơn, không ép vào PL1.

### Chain (giảm FP) — vd gate endpoint trước token match
**Chain là construct PL≥2** (rule-authoring-standards: PL1 chỉ atomic check, không chain). Dùng chain → bump PL lên ≥2 và score var `_pl2/3/4` tương ứng.
```apache
SecRule REQUEST_FILENAME "@rx /api/v1/validate/code$" \
    "id:9XXXXX,phase:2,block,t:none,t:lowercase,\
    msg:'...',tag:'paranoia-level/2',severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}',chain"
    SecRule ARGS:code "@rx <python-injection-tokens>" "t:none,t:urlDecodeUni"
```
Action disruptive + scoring `setvar` đặt ở rule **đầu** chain; rule con chỉ mang variable/operator/transform.
**Action order (CRS canonical):** `setvar` sau `severity`, **`chain` luôn ở cuối** action string (rule-authoring-standards). Không viết `chain,setvar:...`.

### Regex best-practice (CRS)
- Tránh `^`/`$` neo cứng (dễ thêm ký tự bypass) trừ khi cố ý (vd endpoint match).
- Case-insensitive qua `t:lowercase`, không qua `(?i)`.
- Hạn chế `.`; ưu tiên `*` hơn `+`; `t:urlDecodeUni` thay `t:urlDecode`.
- Regex mới nên có bản `.ra` source đề xuất (CRS giữ regex ở `regex-assembly/`).

---

## INPUT — `out/<template_id>/author-context.json` (model đọc file này, KHÔNG đọc verdict.json)

`parse_verdict.py` project `verdict.json` → context distilled (bỏ raw `matched_rules` + full tags + protocol/SQLi FP noise) + tính sẵn tín hiệu probe. Field model tiêu thụ:

| Field | Vai trò |
|---|---|
| `scope_gate.decision` | `in-scope` / `virtual-patch-only` / `out-of-scope-structural` (null khi covered) — **check trước `coverage`** ở `input-guard`: hai cái sau → HALT (rule-author chỉ làm generic CRS; virtual-patch là app-specific để content team tự viết theo `scope_gate.rationale`) |
| `coverage` | `not-covered` / `covered` — quyết gate `input-guard` (cùng `candidate_rules`); chỉ xét khi `scope_gate.decision` = `in-scope`/null |
| `classification` | families / injection_point / severity / protocol / cwe_hint / confidence → target_file + phase + severity (+ `confidence` vào artifact) |
| `payload_samples` | material VALIDATE class-coverage (tự sinh bypass variant) |
| `scope_signal.engine_confirmed_var` | scope **engine xác nhận** (ưu tiên hơn injection_point prose); rỗng ⇒ fallback prose |
| `scope_signal.off_class_on_var` + `note` | đếm rule off-class cùng nổ → payload nhiễu ⇒ thiết kế precise |
| `pl_gap.pl1_blocks`/`pl2_blocks` | định vị PL (pl1_blocks=false ⇒ rule PL1 có giá trị); KHÔNG phải tín hiệu detection |
| `candidate_rules` + `target_file_hint` | few-shot idiom đã rank; hint target_file (override theo family nếu class khác) |
| `already_covered_by` | chỉ khi covered+force-candidates — rule đang cover + cơ chế (operator/transforms/pattern_excerpt/matched_at/trigger_explanation): few-shot giàu nhất + ranh giới tránh nhân bản |

Schema đầy đủ + cách derive: docstring `tools/parse_verdict.py`.

---

## SCHEMA — Artifact `out/<template_id>/new.json`

```json
{
  "template_id": "CVE-2026-0770",
  "designed_at": "<YYYY-MM-DD>",
  "type": "new",
  "source_verdict": "out/CVE-2026-0770/verdict.json",
  "target_file": "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
  "rule": {
    "id": "934XXX",
    "id_note": "placeholder — allocate exact ID ở version sau (range 934xxx)",
    "phase": 2,
    "variables": "ARGS|ARGS_NAMES|REQUEST_BODY|XML:/*",
    "operator": "@rx",
    "pattern": "<regex bắt class>",
    "transforms": ["none", "urlDecodeUni", "lowercase"],
    "severity": "CRITICAL",
    "paranoia_level": 1,
    "anomaly_setvar": "tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}",
    "chain": null,
    "secrule_text": "<full SecRule block, copy-paste được>",
    "ra_source": "<nội dung regex-assembly đề xuất, hoặc null nếu không phải @rx mới>"
  },
  "design_rationale": {
    "scope": "<vì sao chọn variable này — cite RAG>",
    "operator": "<vì sao operator này>",
    "transforms": "<từng transform chặn vector nào>",
    "phase": "<vì sao phase này>",
    "chain": "<vì sao chain / không chain>",
    "paranoia_severity": "<vì sao PL + severity này>"
  },
  "class_coverage": [
    {"payload": "poc", "matched": true, "why": "..."},
    {"payload": "variant:exec", "matched": true, "why": "..."}
  ],
  "few_shot_from": [932160],
  "confidence": "high",
  "notes": "<OPTIONAL — chỉ khi có operational signal thật sự quan trọng, vd Content-Type=application/json → cần REQUEST_BODY scope; nếu không có gì đáng note thì bỏ hẳn field này>"
}
```

### Quy tắc populate (tất cả vào ARTIFACT, không ra conversation)
- `class_coverage` PHẢI có một entry cho **mỗi** request trong `extended-requests.json` (keyed theo `label`: `poc` + từng `variant:*` từ crs-variant-gen); `matched` = `triggered` trong `verify-report.json` (**engine phán, không self-assert**). Pass khi mọi `matched: true`. `triggered: false` khi `iter<3` → loop về DESIGN (xem state machine SKILL.md), KHÔNG emit. `iter=3` terminal → giữ nguyên entries `matched: false` làm residual gap + ghi label lọt (kèm `meta[].rationale`) vào `design_rationale` + hạ `confidence` (medium/low).
- `design_rationale` mang justification mỗi quyết định (scope/operator/transform/phase/chain/PL) **kèm cite RAG inline** (path/section trong `comibined-docs/`). Đây là nơi grounding sống — KHÔNG có array `rag_citations` riêng (citation viết thẳng trong prose từng field).
- `few_shot_from` = list `id` candidate_rules đã mượn làm idiom (rỗng `[]` nếu greenfield thuần — `candidate_rules` rỗng). Traceability: reviewer biết rule mới phỏng theo idiom nào.
- `confidence` = mức tin cậy thiết kế (`high`/`medium`/`low`); `low` khi scope/class phải đoán (template sparse hoặc family mơ hồ → fallback 934). **PoC-only verify** (không variant — class-breadth chưa engine-verified) → cap `medium` trừ khi class hẹp tới mức một construct phủ trọn (xem SKILL.md ##VERIFY PoC-only mode).
- `secrule_text` là rule hoàn chỉnh, đúng line-continuation, copy-paste vào `.conf` được. **Dùng `"\n".join(lines)` để tạo actual newline** — `\\\n` trong Python string literal không đi qua JSON round-trip đáng tin cậy và sẽ ra literal `\n` thay vì newline, khiến `parse_ok=False`. Hoặc dùng single-line format (không cần continuation) — valid ModSecurity syntax và dễ hơn.
- Tier 3 metadata (ver/maturity/accuracy/classification tags) **không** emit (gate `metadata-tiered`) — không cần liệt kê field đã bỏ; chỉ thêm khi user yêu cầu release-ready.
- Write-only: sau khi write chỉ in `out/<id>/new.json — new rule: <id> @ <file>`.

---

## Anti-Patterns — refute trước

### "PoC chỉ có một payload, viết regex match đúng nó là xong"
Sai. Bắt theo attack **class**. Regex phải chặn cả bypass variant trong `payload_samples` (vd Python injection: `__import__`, `getattr(__builtins__,...)`, `compile(...,'exec')`, không chỉ literal trong PoC).

### "Thêm `deny,status:403` cho chắc ăn block"
Sai và vi phạm CRS. Detection rule chỉ `block` + cộng anomaly score; quyết định block là của anomaly threshold, không phải rule lẻ.

### "Nhớ cú pháp operator rồi, khỏi đọc doc"
Sai. Mọi operator/transform/variable cite `comibined-docs/` (gate `rag-grounded`). Sai một transform name = rule không normalize → bypass.

### "Read cả reference-operators.md cho chắc"
Sai và phình context (~108KB cho 4 manual). Menu ở `*_category.md` (nhỏ, đã distilled); chỉ Grep MỘT entry trong `reference-*.md` khi cần edge-case (gate `no-manual-dump`).

### "Grep ruleset tìm ID trống rồi gán exact cho chắc"
Sai — tốn token vô ích ở stage recommendation. Dùng placeholder `<fileID>XXX` (gate `id-placeholder`); allocation exact để version sau.

### "Match được payload rồi, gán PL1 luôn"
Sai nếu token rộng/FP cao. Token dễ xuất hiện trong traffic hợp lệ → PL cao hơn hoặc chain với endpoint gate.

### "Dùng `\\\n` trong Python string để làm line-continuation cho `secrule_text`"
Sai và dễ vỡ. `\\\n` (backslash + newline) không đi qua JSON round-trip (`json.dump`/`json.load`) đáng tin cậy — kết quả thực tế là literal `\n` trong conf, khiến `parse_ok=False`. Dùng `"\n".join(lines)` hoặc single-line format thay thế.

### "Grep `id:<id>` trong `.conf` để xem rule few-shot"
Sai và phí token. Dòng `SecRule` chứa regex body machine-generated (~12KB/dòng). Idiom cần (variables/transforms/phase/pl/severity/chain) nằm trọn trong **1 row index TSV** (`Grep ^<id>\t crs-retrieve-analyze/index/<fileid>.tsv`); chỉ `Read` block `.conf` (offset/limit) khi thật cần regex thật. Đây là strategy `no-conf-read` của Stage 1.

---

## Red Flags — STOP nếu đang nghĩ:

| Nếu nghĩ... | Thực tế là... |
|---|---|
| "Regex match literal PoC là đủ" | Đủ cho PoC ≠ đủ cho class; bypass variant sẽ lọt |
| "Dùng deny cho chắc" | Detection rule không bao giờ deny — chỉ block + anomaly |
| "Khỏi cite doc, nhớ cú pháp rồi" | Sai operator/transform name = rule vô hiệu, không ai biết tới VALIDATE |
| "Read full reference-*.md cho chắc" | Phình ~108KB; menu ở *_category.md, drill-down bằng Grep một entry |
| "Phải resolve exact ID không trùng" | Recommendation dùng placeholder `<fileID>XXX`; allocate ở version sau |
| "Body JSON chắc vào ARGS" | Chỉ khi requestBodyProcessor=JSON active; nếu không, cần REQUEST_BODY |
| "PL1 cho mọi rule" | Token FP cao phải lên PL cao hoặc chain endpoint gate |
| "Grep id:<id> trong .conf lấy idiom" | Kéo cả dòng regex ~12KB; idiom (scope/transform/severity/chain) ở index TSV 1 row, regex thật chỉ Read khi cần |
| "scope_gate là virtual-patch-only nhưng cứ viết rule path+missing-header" | App-specific, không hợp ID range CRS, FP cao → ngoài generic CRS; HALT, để content team tự viết theo `rationale` |
| "out-of-scope-structural nhưng vẫn ráng author cái gì đó" | Không content signature nào tồn tại → chỉ ra được `@rx` khít PoC = FP magnet; HALT là đúng |

---

## Operational note
- **JSON/XML body**: payload JSON chỉ vào `ARGS` nếu `requestBodyProcessor=JSON` active (CRS bật theo Content-Type). Không chắc → thêm scope `REQUEST_BODY` + ghi lý do vào `design_rationale.scope` (và `notes` nếu là operational signal quan trọng).
- **Recommend, không commit**: skill chỉ ghi `out/<id>/new.json`. KHÔNG tạo/sửa file trong `coreruleset/`. `ra_source` là đề xuất nội dung, integrator tự đặt vào `regex-assembly/` + re-assemble.
