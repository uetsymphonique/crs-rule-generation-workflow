# crs-retrieve-analyze — Reference

Load file này **on-demand** (CRAFT cần ##CATALOG + ##CLASS-TAG; PROBE cần ##PROBE; EMIT cần ##SCHEMA). SKILL.md giữ phần mandatory; phần dài đặt ở đây để giảm context overhead mỗi lần invoke.

---

## CATALOG — CRS rule file (tra cứu khi RETRIEVE, không gate probe)

Khi RETRIEVE cần tra rule cùng class, chọn file theo **semantic** từ signal của template (`tags`, `info.name`, `info.description`, `http.matchers`, `severity`). Không map cứng CWE — CWE chỉ là hint phụ. Đây chỉ là **bảng tra** để model tự quyết lookup file nào ở bước RETRIEVE/handoff (nhánh not-covered); **không** phải field lưu trong artifact, và **không** gate probe — probe luôn bắn qua toàn ruleset nên rule fire từ file ngoài danh sách vẫn hiện ra.

| File | ID | Coverage |
|---|---|---|
| `REQUEST-911-METHOD-ENFORCEMENT.conf` | 911 | HTTP method bị cấm / abuse |
| `REQUEST-913-SCANNER-DETECTION.conf` | 913 | Scanner / automated tool / bot (User-Agent, header) |
| `REQUEST-920-PROTOCOL-ENFORCEMENT.conf` | 920 | HTTP protocol violation, malformed header, encoding bất thường |
| `REQUEST-921-PROTOCOL-ATTACK.conf` | 921 | Request smuggling, response splitting, CRLF injection, HTTP parameter pollution |
| `REQUEST-922-MULTIPART-ATTACK.conf` | 922 | Attack qua multipart/form-data |
| `REQUEST-930-APPLICATION-ATTACK-LFI.conf` | 930 | Local file inclusion, path traversal (`../`, `/etc/passwd`) |
| `REQUEST-931-APPLICATION-ATTACK-RFI.conf` | 931 | Remote file inclusion (URL trong include parameter) |
| `REQUEST-932-APPLICATION-ATTACK-RCE.conf` | 932 | OS command injection, shell command/builtin |
| `REQUEST-933-APPLICATION-ATTACK-PHP.conf` | 933 | PHP injection, PHP function/wrapper/variable |
| `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf` | 934 | SSRF, SSTI, server-side code injection (Node/Ruby/Perl/PHP…), prototype pollution |
| `REQUEST-941-APPLICATION-ATTACK-XSS.conf` | 941 | Cross-site scripting |
| `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` | 942 | SQL injection |
| `REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf` | 943 | Session fixation |
| `REQUEST-944-APPLICATION-ATTACK-JAVA.conf` | 944 | Java injection, deserialization, OGNL/SpEL, Log4Shell |
| `RESPONSE-950..956-*.conf` | 95x | Data leakage / backend error / web shell trong **response** |

**No clear match** → `934` + `confidence: low`. **Multi-vector** → nhiều file.

Data file payload (chỉ Grep khi handoff phụ thuộc nội dung — `output_mode:content`, grep **đúng token payload** cần đối chiếu, KHÔNG enumerate/Read cả file): `unix-shell.data`(932), `ssrf.data`(934), `lfi-os-files.data`(930), `php-function-names-*.data`(933), `web-shells-*.data`(955).

---

## CLASS-TAG — map vuln-class template → CRS `attack-*` tag (gate root-cause part 1)

Một matched rule được tính **root-cause** chỉ khi `tags` của nó chứa tag dưới đây ứng với class của template (part 1) **VÀ** rule bắt đúng exploit (part 2 — xét **tình huống thực**: fire trên đúng request thực thi exploit, tại nơi payload đi vào, detection đủ generic; KHÔNG so token cứng). Tag đọc thẳng từ `matched_rules[].tags`. Khi tag mơ hồ, đối chiếu CRS ID-range (= file ID ở ##CATALOG) làm corroboration.

| Vuln-class (từ template) | `attack-*` tag kỳ vọng | ID-range corroborate |
|---|---|---|
| SQL injection | `attack-sqli` | 942 |
| XSS | `attack-xss` | 941 |
| LFI / path traversal | `attack-lfi` | 930 |
| RFI | `attack-rfi` | 931 |
| OS command injection / RCE | `attack-rce` | 932 |
| PHP injection | `attack-injection-php` | 933 |
| SSRF / SSTI / code-injection generic | `attack-injection-generic` (kèm `attack-ssrf` cho SSRF) | 934 |
| Java / deserialization / OGNL / SpEL | `attack-injection-java` | 944 |
| Protocol attack (CRLF, smuggling, HPP) | `attack-protocol` | 920 / 921 |
| Session fixation | `attack-fixation` | 943 |
| Multipart attack | `attack-protocol` | 922 |

- Tag chỉ ở mức `attack-*` là đủ class-match; KHÔNG đòi tag chi tiết hơn.
- Template multi-vector → chấp nhận root-cause nếu rule khớp **bất kỳ** class nào của template tại đúng injection point của vector đó.
- Class không xác định → `934` + `attack-injection-generic`, `confidence: low`.

---

## PROBE — pipeline file-based (craft → probe → parse → read)

Engine nạp `coreruleset/` thật vào Coraza, bắn request qua toàn ruleset, trả matched rules (kèm `tags`/`paranoia_level`/matched `variables`) + anomaly score + block decision. Đây là oracle quyết coverage. **KHÔNG cần đọc `README.md` của tool** — toàn bộ path/command tường minh dưới đây là đủ.

Pipeline (path tương đối **repo root**; bỏ `.exe` trên Linux/macOS):

| Bước | Input → Output | Command |
|---|---|---|
| 1 craft | (model) → `out/<id>/probe-input.json` | dùng **Write** tool, dạng batch dưới đây |
| 2 probe | `probe-input.json` → `probe-raw.json` | `./tools/probe-engine/probe-engine.exe --crs coreruleset < out/<id>/probe-input.json > out/<id>/probe-raw.json` |
| 3 parse | `probe-raw.json` → `probe.json` | `python .claude/skills/crs-retrieve-analyze/tools/parse_probe.py out/<id>/probe-raw.json out/<id>/probe.json` |
| 4 read | `probe.json` → (model) | **Read** `out/<id>/probe.json` — KHÔNG đọc `probe-raw.json` |

### probe-input.json (luôn dạng batch `requests[]`, PL2)
```json
{ "requests": [
    { "method": "GET",
      "uri": "/path?param=<POC_URL_ENCODED>",
      "headers": { "Content-Type": "application/json" },
      "body": "<POC_BODY nếu là body vector>" }
  ],
  "paranoia": 2 }
```
- Dùng `requests[]` kể cả khi chỉ 1 request → output luôn là `results[]`, parser xử lý đồng nhất. `index` trong output = vị trí trong mảng.
- Route payload theo location thật của template:
  - query string → `uri` (phải **URL-encode** — space/quote thô trip 920100 "Invalid HTTP Request Line", nhiễu kết quả).
  - body → `body` + `headers."Content-Type"` đúng (`application/json` / xml… kích body processor; thiếu thì payload không vào ARGS).
  - header/cookie → `headers` map.

### probe.json (output bước 3 — cái model đọc)
`parse_probe.py` **đã làm sẵn projection**; file `probe.json` chỉ chứa whitelist dưới đây, đã drop noise. Schema:
```
{ "status", "error",
  "results": [ { "index", "paranoia", "blocked",
                 "anomaly_score": { "inbound","threshold","to_block","score_pl1","score_pl2" },
                 "matched_rules": [ { "id","tags","paranoia_level","msg",
                                      "matched_var":["VARIABLE:KEY"], "variables":[{"variable","key","value"}] } ] } ] }
```
`matched_var[]` do parser derive từ `variables[]` (dạng SecLang engine trả) — dùng để đối chiếu với `injection_point` plain, KHÔNG phải tự viết.
> **KHÔNG có `file`/`line`/`operator` trong probe.json** — Coraza `rule.Line()` không phải dòng .conf thật (đếm trên ruleset đã merge). Source location của rule (fired hay không) lấy từ **index tsv** (cột `file`/`line`/`operator`, lookup theo `id`) ở RETRIEVE.

### Field-consumption contract (parse_probe.py implement đúng whitelist này)

probe-engine emit nhiều field hơn; `parse_probe.py` chỉ giữ các field dưới đây và **drop phần còn lại** — đây là spec của script, model không cần tự project.

**Shared / top-level (giữ):**
| Field | Dùng để |
|---|---|
| `status` | error handling — `"error"` → fallback, nghiêng not-covered |
| `error` | message khi `status:"error"` |

**Per-result `results[]` (giữ):**
| Field | Dùng để |
|---|---|
| `index` | map result ↔ request/vector đã craft (thứ tự trong `requests[]`) |
| `blocked` | fact phụ cho evidence (KHÔNG nâng coverage một mình) |
| `anomaly_score` | xem dưới |
| `matched_rules[]` | adjudicate root-cause; id để cross-ref index khi cần candidate |

**anomaly_score (giữ):** `inbound`, `threshold`, `to_block`, `score_pl1`, `score_pl2`.
→ `score_pl1`/`score_pl2` = score đóng góp theo tier (probe PL2 nên `score_pl3`/`score_pl4` = 0 → **drop**). Cho biết root cause block ở PL1 hay chỉ từ PL2.

**matched_rules[] — adjudicate (giữ cho MỌI rule):** `id`, `tags`, `paranoia_level`, `msg`, `variables[]`, **`matched_var[]`** (parser derive từ `variables[]`, dạng `"VARIABLE:KEY"`).
**variables[] (giữ):** `variable`, `key`, `value`.

**Drop hẳn (không stage nào dùng ở Stage 1):**
`parse_ok` (chỉ cho candidate_rule/author), `interruption` (DetectionOnly → null; `blocked` đã đủ), `matched_rules[].file`/`.line`/`.operator` (Coraza line không phải dòng .conf — lấy từ index tsv theo id), `anomaly_score.detection`, `anomaly_score.score_pl3`, `anomaly_score.score_pl4`, `matched_rules[].phase`, `.severity`, `.raw`, `.data`, `.maturity`, `.accuracy`, `variables[].data`, `variables[].chain_level`.

> `raw` cố tình bỏ: Rule Designer (stage 2) có repo access, tự Read `file:line` khi cần text rule — Stage 1 artifact giữ gọn. Chỉ giữ `raw` nếu sau này tách Stage 2 khỏi repo.

### Adjudicate root-cause (gate `root-cause-evidence`)
Với mỗi `matched_rules[]`, đánh `root_cause:true` ⟺ **cả hai** (xét theo **tình huống thực**, không so token cứng):
1. **Class khớp** — `tags` chứa `attack-<class>` của template (##CLASS-TAG).
2. **Bắt đúng exploit** — rule fire trên chính request thực thi exploit (không phải discover/setup request) tại nơi payload thật sự đi vào, và detection đủ **generic** để trigger bởi pattern exploit (không trùng hợp token vô tình). Đối chiếu `matched_var` (engine trả, dạng SecLang `ARGS:uid`…) với param/location plain đã ghi ở `injection_point` — cùng chỗ thì khớp. KHÔNG cần tự viết injection point dạng SecLang.

- ≥1 rule `root_cause:true` → **covered**. Rule đó cũng tóm vào `root_causes.root_cause_rules` (kèm `reason`).
- 0 rule `root_cause:true` → **not-covered** (dù `blocked:true`). Rule đã fire nhưng off-root-cause giữ nguyên trong `probe.matched_rules` với `root_cause:false` — không tách list riêng (sai class / field phụ / discover request đọc ngay từ `tags`/`matched_var`).
- `status:"error"` → fallback, nghiêng **not-covered**.

---

## Anti-Patterns — refute trước

Ba shortcut nguy hiểm nhất, cần refute đầy đủ (các trigger còn lại xem bảng Red Flags bên dưới — đó là bản scan nhanh, không lặp lý lẽ).

### "PoC bị block rồi → covered"
Block một mình KHÔNG đủ (gate `root-cause-evidence`). Block có thể do rule sai class (template SQLi nhưng chỉ 933 PHP nổ), do cộng dồn 920/921 protocol, hoặc đúng class nhưng matched ở field phụ / trên discover request. `covered` cần ≥1 rule `attack-<class>` khớp tag **và** bắt đúng exploit (đúng request thực thi + đúng param mang payload, detection đủ generic).

### "Tạo bypass variant để test class"
Stage 1 **không** tạo variant nữa (quyết định hiện hành). Probe đúng PoC literal. Robustness/bypass là việc downstream.

### "Classify nhầm file thì sót coverage"
Không — probe bắn qua **toàn ruleset** (gate `probe-first`), rule fire từ file nào cũng hiện, kể cả file không nằm trong danh sách tra ở RETRIEVE. Việc chọn file (##CATALOG) chỉ scope handoff, không ảnh hưởng probe.

---

## Red Flags — bảng scan nhanh, STOP nếu đang reason:

| Nếu nghĩ... | Thực tế là... |
|---|---|
| "PoC blocked → covered" | Block ≠ root-cause. Cần rule `attack-<class>` khớp tag + bắt đúng exploit (đúng request thực thi + đúng param) |
| "Rule nào đó fire → covered" | Phải đúng class **và** đúng chỗ exploit; 933 nổ trên template SQLi, hoặc rule nổ trên discover request = off-root-cause → not-covered |
| "Semantic thấy khớp nên covered" | `covered` cần engine evidence root-cause; semantic chỉ đủ cho candidate handoff |
| "Sweep cho chắc PL" | Một probe PL2 đủ: paranoia_level + score_pl1/pl2 đọc tier |
| "Cần đọc regex để quyết coverage" | Coverage quyết bởi engine oracle, KHÔNG bởi đọc regex. Đọc rule block chỉ được phép ở INSPECT-ROOT-CAUSE (nhánh covered) để giải thích cơ chế đã-xác-nhận — không phải để phán covered/not-covered |
| "Không chắc lắm nhưng thôi covered" | Uncertain / probe error / no root-cause = `not-covered`, luôn |

---

## SCHEMA — hai file: analysis.json (model write) → verdict.json (script assemble)

EMIT tách 2 file để model **không phải chép lại probe transcript**:
- **`out/<id>/analysis.json`** — model write, **chỉ judgment** (classification, payload_samples, root-cause ids + reason, recommendation/candidate_rules).
- **`out/<id>/verdict.json`** — `assemble_verdict.py` sinh ra: inject probe transcript từ `probe.json`, annotate `root_cause` theo id, fill `matched_var`/`msg` từ probe, suy covered/not-covered, in dòng confirmation.

### analysis.json — model write (judgment)
```json
{
  "template_id": "duomicms-sql-injection",
  "template_path": "<đường dẫn file .yaml>",
  "exploit_index": 0,
  "classification": {
    "families": ["sqli"],
    "injection_point": "query param `uid` của exploit request GET /duomiphp/ajax.php?action=addfav",
    "severity": "critical", "protocol": "http", "confidence": "high", "cwe_hint": "CWE-89"
  },
  "payload_samples": [
    { "label": "poc",         "value": "<PoC raw — exact string từ template>" },
    { "label": "poc-decoded", "value": "<PoC URL-decoded nếu encoded>" }
  ],
  "root_cause_rules": [
    { "id": 942100, "reason": "<attack-sqli khớp class + libinjection bắt đúng payload trên uid của exploit request — generic, không trùng hợp>" }
  ],
  "recommendation": {
    "summary": "<1-2 câu: verdict + PL note — vd: covered at PL2, root-cause rules 932200+932240, PL1-only NOT sufficient>",
    "pl_coverage": "<PL tối thiểu để block — 'PL1' | 'PL2' | 'PL3' | 'PL4'>",
    "rule_analysis": [
      {
        "id": 942100,
        "msg": "<msg từ probe>",
        "operator": "@detectSQLi",
        "transforms": ["none"],
        "pattern_excerpt": "<nội dung key: @rx → 300 chars đầu; @pmFromFile → tên data file; @detectSQLi/@detectXSS → tên engine>",
        "matched_at": "<ARGS:uid — từ matched_var probe>",
        "trigger_explanation": "<cơ chế cụ thể: transform nào normalize, subpattern/construct nào triggered, token cụ thể trong payload>"
      }
    ]
  },
  "candidate_rules": [
    { "id": 942190, "file": "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "line": 1234, "operator": "@rx",         "pl": 2, "why": "SQLi cùng class, scope ARGS, PL2 — có thể mở rộng bắt payload template" },
    { "id": 942100, "file": "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "line": 100,  "operator": "@detectSQLi", "pl": 1, "why": "cấu trúc rule SQLi libinjection chuẩn cùng class, PL1, dùng tham chiếu" }
  ],
  "note": null
}
```
- `root_cause_rules` non-empty ⇒ covered → để `recommendation` (structured object với `summary`/`pl_coverage`/`rule_analysis[]`), BỎ `candidate_rules`. Rỗng ⇒ not-covered → để `candidate_rules`, BỎ `recommendation`. `recommendation.rule_analysis[]` được nuôi từ INSPECT-ROOT-CAUSE — mỗi entry có `id`, `msg`, `operator`, `transforms`, `pattern_excerpt`, `matched_at`, `trigger_explanation`.
- **Force-candidates mode (`force_candidates: true`):** covered case giữ **cả** `recommendation` lẫn `candidate_rules` (candidate loại trừ id đã là root-cause; script abort nếu trùng hoặc nếu vẫn ép `[]`). Mặc định (không flag) covered ⇒ `candidate_rules: []`. covered/not-covered không đổi — vẫn suy từ `root_cause_rules`.
- `root_cause_rules[].id` PHẢI là rule đã fire ở exploit request (script verify — abort nếu sai). KHÔNG ghi `matched_var`/`msg` ở đây; script tự lấy từ probe.
- `exploit_index` = vị trí request exploit trong `requests[]` của probe-input (default 0).

### verdict.json — assemble_verdict.py sinh (model KHÔNG tự viết)
Ví dụ ca **covered** (root_cause_rules non-empty → `candidate_rules: []`). Field in **đậm** là phần script tự thêm/điền từ probe, không có trong analysis.json:
```json
{
  "template_id": "duomicms-sql-injection",
  "template_path": "<đường dẫn file .yaml>",
  "classification": { "families": ["sqli"], "injection_point": "query param `uid` ...", "severity": "critical", "protocol": "http", "confidence": "high", "cwe_hint": "CWE-89" },
  "payload_samples": [
    { "label": "poc", "value": "<PoC raw>" }, { "label": "poc-decoded", "value": "<PoC decoded>" }
  ],
  "probe": {
    "paranoia": 2,
    "blocked": true,
    "anomaly_score": { "inbound": 15, "threshold": 5, "to_block": 0, "score_pl1": 15, "score_pl2": 0 },
    "matched_rules": [
      { "id": 942100, "paranoia_level": 1, "tags": ["attack-sqli"],          "matched_var": ["ARGS:uid"], "msg": "SQL Injection Attack Detected via libinjection", "root_cause": true  },
      { "id": 933160, "paranoia_level": 1, "tags": ["attack-injection-php"], "matched_var": ["ARGS:uid"], "msg": "PHP Injection Attack",                          "root_cause": false }
    ]
  },
  "root_causes": {
    "root_cause_rules": [
      { "id": 942100, "matched_var": ["ARGS:uid"], "msg": "SQL Injection Attack Detected via libinjection", "reason": "<attack-sqli khớp class + libinjection bắt đúng payload trên uid — generic, không trùng hợp>" }
    ],
    "recommendation": {
      "summary": "<1-2 câu: verdict + PL + số rule>",
      "pl_coverage": "PL1",
      "rule_analysis": [
        { "id": 942100, "msg": "SQL Injection Attack Detected via libinjection", "operator": "@detectSQLi", "transforms": ["none"], "pattern_excerpt": "libinjection engine", "matched_at": "ARGS:uid", "trigger_explanation": "libinjection tokenizes the payload '...' as SQL structure; no transforms needed (raw value fed directly to libinjection)" }
      ]
    }
  },
  "candidate_rules": []
}
```
- `probe.matched_rules[].root_cause`, `root_causes.root_cause_rules[].matched_var`/`.msg` đều do script điền từ `probe.json` — model chỉ cấp `id` + `reason`.
- Ca **not-covered**: `root_causes: null`, `candidate_rules` = list từ analysis (đã rank theo độ liên quan), `probe.matched_rules[].root_cause` toàn `false`.

### Quy tắc populate (model chỉ write analysis.json; script lo phần còn lại)
**Model write (analysis.json):**
- `classification.injection_point` **luôn** giữ, ghi **plain** (request exploit nào + param/header/body mang payload) — KHÔNG cần dạng SecLang. Gate root-cause cần nó để đối chiếu với `matched_var`; nhánh not-covered cần nó cho Rule Designer (Action B), vì khi KHÔNG rule nào fire thì `matched_var` rỗng → injection_point là record duy nhất về điểm tiêm.
- `root_cause_rules` = list `{id, reason}` model phán root-cause (class khớp + bắt đúng exploit, xét tình huống thực). KHÔNG ghi `matched_var`/`msg` — script lấy từ probe. Non-empty ⇒ covered (kèm `recommendation`); rỗng ⇒ not-covered (kèm `candidate_rules`).
- `candidate_rules` (điền khi not-covered, HOẶC khi `force_candidates:true` kể cả covered) — spec tường minh dưới đây.
- `force_candidates` (optional bool, default false) — true ⇒ giữ `candidate_rules` ở mọi verdict (xem Force-candidates mode).

#### candidate_rules[] — spec field (model write, khi not-covered hoặc `force_candidates`, ≤5 phần tử)
| Field | Type | Required | Nguồn (KHÔNG grep .conf) | Note |
|---|---|---|---|---|
| `id` | int | ✓ | `probe.json` (rule đã fire off-root-cause) **hoặc** index tsv cột `id` | rule CRS gốc |
| `file` | string | ✓ | index tsv cột `file` (lookup theo `id`) | basename `.conf` (vd `REQUEST-942-...SQLI.conf`) |
| `line` | int | ✓ | index tsv cột `line` (lookup theo `id`) | dòng `SecRule` bắt đầu |
| `operator` | string | ✓ | index tsv cột `operator` | vd `@rx`, `@detectSQLi` |
| `pl` | int | ✓ | index tsv cột `pl` (lookup theo `id`) | paranoia level rule (1–4); engine-fired có thể verify qua `probe.matched_rules[].paranoia_level` |
| `why` | string | ✓ | model | bắt buộc cite cơ chế: scope/operator/transform/phase/pl — *tại sao* rule này liên quan tới gap |

- **List đã rank theo độ liên quan** (4 criteria: scope ∩ injection_point, operator+transform, phase, pl tie-break). Order = ưu tiên; Stage 2 — nơi được đọc regex — tự quyết fix (Action A) hay làm few-shot author rule mới (Action B). Stage 1 KHÔNG gán nhãn fix/example vì không được nhìn rule logic để phán đáng tin.
- **Toàn bộ source location + `pl` (`file`/`line`/`operator`/`pl`) đến từ index tsv theo `id`** — engine-fired candidate cũng lookup ở index (KHÔNG dùng `line` của probe vì sai). probe.json chỉ cho biết rule nào *đã fire off-root-cause* (để ưu tiên) và `paranoia_level` (để verify `pl`), không cấp `file`/`line`.
- Script validate: ≤5 phần tử, mỗi entry có `id` + `pl` (1–4) — vi phạm → abort.

**Script lo (assemble_verdict.py → verdict.json):**
- `probe` block: copy `results[exploit_index]` từ `probe.json` (paranoia, blocked, anomaly_score, matched_rules), annotate `matched_rules[].root_cause = id ∈ root_cause_rules`. Off-root-cause rule giữ nguyên với `root_cause:false` — không list `fired_rules` riêng.
- `root_causes`: covered → build từ `root_cause_rules` (script fill `matched_var`/`msg` từ probe + `reason` từ model) + `recommendation`; not-covered → `null`.
- `candidate_rules`: covered → `[]` (trừ khi `force_candidates:true` → copy từ analysis, đã loại id root-cause); not-covered → copy từ analysis.
- **Guardrail:** id trong `root_cause_rules` không fire ở exploit request → abort (model sửa adjudication). probe error/no result mà vẫn covered → abort.
- **Không** field `verdict` — covered/not-covered suy từ length `root_cause_rules`. Score-derived facts đọc thẳng `probe.anomaly_score`, không lưu riêng.
- Script in **đúng một dòng** `out/<id>/verdict.json — <covered|not-covered>`. Chỉ present nội dung khi user request tường minh.

---

## Operational note (đưa vào recommendation khi relevant)

- **JSON/XML body**: payload trong body chỉ vào `ARGS` nếu `Content-Type` kích đúng body processor. Dựng request thiếu Content-Type → payload không vào scope → probe fire sai (false not-covered). Set header đúng từ `http[]`.
- **URL-encode `uri`**: space/quote thô trong query trip 920100 và nhiễu matched_rules. Encode payload trước khi đặt vào `uri`.
- **PL semantics**: root-cause rule là PL1 và `score_pl1 ≥ threshold` → caught & block ở deployment mặc định (PL1). Caught nhưng chỉ block từ PL2 (`score_pl1 < threshold ≤ inbound`) → recommendation nên note "rule cần PL2 mới đủ block".
- **Index có thể stale**: nếu coreruleset submodule vừa update, rebuild `python .claude/skills/crs-retrieve-analyze/tools/build_rule_index.py` trước khi tin số liệu index (chỉ ảnh hưởng RETRIEVE handoff; probe đọc ruleset trực tiếp nên không bị).
