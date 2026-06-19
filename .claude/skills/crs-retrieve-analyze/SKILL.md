---
name: crs-retrieve-analyze
description: Stage 1 của pipeline CRS rule-generation (purple-team oriented). Coverage analysis cho MỘT Nuclei template (.yaml) đối chiếu OWASP CRS bằng engine-as-oracle (probe-engine/Coraza). Dựng request thật từ template, probe PoC tại PL2, đọc matched_rules + anomaly-score, và adjudicate theo tiêu chí ROOT-CAUSE — có ≥1 rule bắt đúng root cause (attack-class tag khớp + bắt đúng exploit, xét tình huống thực) → covered (recommend rule sẵn có); ngược lại → not-covered + dựng candidate_rules (fired-off-root-cause + related rules cùng class, rank theo độ liên quan) cho Rule Designer. covered/not-covered suy từ length root_cause_rules, không có field verdict. Sinh request biến thể cho Stage 2 qua arg gen-variants (default class-only → spawn bg Agent crs-variant-gen; off → tự write PoC-only extended-requests.json) — spawn CHỈ phụ thuộc gen-variants, độc lập coverage/force-candidates. KHÔNG author hay modify rule.
effort: medium
allowed-tools:
  - Read
  - Grep
  - Glob
  - Write
  - Edit
  - Agent
  - Bash(python *)
  - Bash(./tools/probe-engine/probe-engine*)
---

# CRS Retrieve & Analyze

Thực thi stage **retrieve-and-analysis** theo kiến trúc **engine-as-oracle**: `Craft request → probe PL2 → adjudicate ROOT-CAUSE → (nếu gap) retrieve handoff → verdict`.
Input: đúng **một** Nuclei template `.yaml`. Output: đúng **một** artifact `out/<template_id>/verdict.json`.

Bối cảnh: ta đang test một sản phẩm WAF (modsec + rule tự bổ sung) theo lối purple-team, rồi LLM **khuyến nghị cho content team**. Câu hỏi không phải "PL tối thiểu nào chặn được" mà là: **tại PL vận hành thực tế (PL2), có rule nào của CRS bắt đúng *root cause* của template không.**

Coverage **không** phán từ suy luận semantic. `probe-engine` nạp `coreruleset/` thật vào Coraza và trả rule nào fire (kèm `tags`, `paranoia_level`, matched `variables`) + anomaly score + có blocked không. Verdict là **fact thực nghiệm**.

> **WRITE-ONLY mặc định.** Deliverable duy nhất là verdict artifact. KHÔNG phát summary / recommendation / handoff / reasoning ra conversation trừ khi user yêu cầu tường minh. Toàn bộ phân tích serialize vào artifact. Khi hoàn tất, in **đúng một dòng**: `out/<id>/verdict.json — <covered|not-covered>`.

In scope: dựng request, probe PL2, adjudicate root-cause, (nếu not-covered) dựng handoff.
Out of scope: author/patch rule, invoke skill khác — đó là stage Rule Designer phía sau.

Companion file (load on-demand đúng stage cần):
- `reference.md` → ##CATALOG + ##CLASS-TAG (CRAFT/RETRIEVE), ##PROBE + field-consumption contract (PROBE), ##SCHEMA + Anti-Patterns + Red Flags (EMIT).
- `.claude/skills/crs-retrieve-analyze/index/<fileid>.tsv` → **metadata source cho handoff** (một row mỗi detection rule; cột đúng thứ tự: `id, file, line, phase, pl, variables, operator, transforms, chain, severity, tags, msg`; regex body đã strip, `chain`=1 ⇒ rule có chained condition). Dùng để enumerate rule **không** fire ở RETRIEVE. KHÔNG dùng để quyết coverage — đó là việc của probe-engine.

### Output artifacts (mọi file ở `out/<template_id>/`)

| File | Bước | Vai trò | Vòng đời |
|---|---|---|---|
| `verdict.json` | EMIT‑2 | **deliverable duy nhất** (covered/not-covered + transcript) | giữ — Stage 2 đọc |
| `extended-requests.json` | EMIT‑1 *(chỉ `gen-variants=off`)* / bg agent | handoff cho Stage 2 (PoC + variants) | giữ — Stage 2 đọc |
| `variant-handoff.json` | VARIANT-HANDOFF | handoff cho variant-gen (model judgment trước RETRIEVE) | giữ (trace/re-run) |
| `probe.json` | PROBE‑2 | probe đã projection; nhúng trong verdict, variant-gen còn đọc | giữ (trace/re-run) |
| `probe-input.json` | CRAFT | envelope PoC; variant-gen clone | giữ (trace/re-run) |
| `probe-raw.json` | PROBE‑1 | raw engine, **pure staging** | **auto-xoá** sau `probe.json` (`--keep-raw`) |
| `analysis.json` | EMIT‑1 | judgment model, **pure staging** (verdict là superset) | **auto-xoá** sau `verdict.json` (`--keep-analysis`) |

Chỉ 2 file pure-staging bị script tự dọn (gated-on-success). Bộ handoff (`probe.json`/`variant-handoff.json`/`probe-input.json`) **không** xoá vì bg agent variant-gen đọc bất đồng bộ + cần để trace/debug/re-run.

> **`variant-handoff.json` vs `analysis.json` — đừng nhầm là hai phiên bản của một file.** Khác **vai trò** + **vòng đời**, không phải early/late của cùng một thứ:
> - `variant-handoff.json` (stage VARIANT-HANDOFF, trước RETRIEVE) → input async cho bg agent variant-gen. **Giữ** (consumer chạy nền + trace). Mang `rule_analysis[]` **top-level** (chỉ phần variant-gen cần).
> - `analysis.json` (EMIT) → input cho `assemble_verdict.py`. **Pure-staging, auto-xoá** (verdict là superset). Bọc cùng nội dung trong `recommendation: {summary, pl_coverage, rule_analysis[]}` + thêm `candidate_rules`/`note`.
> - Quan hệ: `analysis.json ⊇ variant-handoff.json` ở phần judgment dùng chung (`classification`, `payload_samples`, `root_cause_rules`, `rule_analysis`). **Drift rule:** các field dùng chung PHẢI copy **verbatim** từ `variant-handoff.json` sang `analysis.json` ở EMIT — không viết lại khác đi (lệch ⇒ verdict và variant-context bất đồng, không ai bắt được).

---

## State machine

| State | Action | Transition (guard → next) |
|-------|--------|---------------------------|
| CRAFT | Read template; xác định vuln-class + injection_point + injection_slot (ModSec var); dựng req thật (PoC) | → PROBE |
| PROBE (PL2) | chạy probe-engine; adjudicate root-cause (class khớp + bắt đúng exploit) | ≥1 root-cause → INSPECT-ROOT-CAUSE · 0 root-cause → SCOPE-GATE · probe status=error → FALLBACK |
| INSPECT-ROOT-CAUSE | drill cơ chế từng root-cause rule (đọc block khi `@rx`/`chain`) | → VARIANT-HANDOFF |
| SCOPE-GATE | G0–G4 (mechanism); ghi `scope_gate` trace | `in-scope` → VARIANT-HANDOFF · `virtual-patch-only`/`out-of-scope-structural` → VARIANT-HANDOFF (suppress GEN-VARIANTS spawn) |
| FALLBACK | semantic, nghiêng not-covered (probe lỗi) | → VARIANT-HANDOFF |
| VARIANT-HANDOFF | **luôn write** `variant-handoff.json` (context cho variant-gen) | → GEN-VARIANTS |
| GEN-VARIANTS | `gen-variants≠off` → spawn bg agent variant-gen (chạy nền; CHỈ theo gen-variants, độc lập coverage/force) | Stage 2 chạy → RETRIEVE · Stage 2 idle (covered & không force-candidates) → EMIT |
| RETRIEVE | chọn file CRS (##CATALOG) + rank related rules ≤5 cho handoff | → EMIT |
| EMIT | covered: recommendation · not-covered: handoff; (`gen-variants=off` → write PoC-only `extended-requests.json`) | → STOP |

Tuần tự nghiêm ngặt, không skip stage. **Hai trục quyết định độc lập:**
- **Spawn variant-gen** chỉ theo arg `gen-variants` (`≠off` → spawn; `off` → EMIT write PoC-only). KHÔNG dính coverage/force-candidates.
- **RETRIEVE (candidate_rules)** theo **Stage 2 chạy** = `not-covered` **HOẶC** (`covered` + `force-candidates`) — đây là nơi `force-candidates` có tác dụng (và chỉ ở đây).

`INSPECT-ROOT-CAUSE` **chỉ** ở nhánh covered (nuôi recommendation). `VARIANT-HANDOFF` luôn write ở mọi nhánh. `RETRIEVE` chạy khi Stage 2 chạy — luôn ở not-covered, ở covered chỉ khi `force-candidates`.

> **Mode `force-candidates` (tùy chọn, OFF mặc định):** khi user yêu cầu tường minh (vd "luôn kèm candidate_rules", "force candidates", "--candidates-always"), `RETRIEVE` chạy **thêm** ở nhánh covered (sau `INSPECT-ROOT-CAUSE`) để populate `candidate_rules` song song với `recommendation`. Verdict covered/not-covered **KHÔNG đổi** (vẫn suy từ `root_cause_rules`) — candidate ở đây chỉ là material bổ sung cho Stage 2, **loại trừ** các id đã là root-cause. Bật bằng cách set `force_candidates: true` trong `analysis.json`; mặc định (không có flag) covered ⇒ `candidate_rules: []`.

> **Arg `gen-variants` (default `class-only`):** chọn cách sinh variant cho Stage 2 — enum `off | class-only | root-cause-only | all-triggered-rules`.
> - `class-only` (**default**) → spawn bg Agent crs-variant-gen craft breadth từ template/family (không neo rule).
> - `root-cause-only` → spawn, neo `root_cause_rules` (variant-gen tự fallback class-only nếu không có root cause).
> - `all-triggered-rules` → spawn, neo toàn bộ `matched_rules` (fallback class-only nếu không rule nào fire).
> - `off` → KHÔNG spawn; EMIT tự write PoC-only `extended-requests.json` để Stage 2 không phải chờ.
>
> Spawn quyết **chỉ bởi `gen-variants`** (`≠off` → spawn; `off` → EMIT write PoC-only), **độc lập** với coverage và `force-candidates`. Agent chạy nền song song phần còn lại của main thread (RETRIEVE nếu Stage 2 chạy, hoặc EMIT thẳng). Xem ##GEN-VARIANTS. Đánh đổi: covered + không force-candidates vẫn spawn (gen-variants≠off) dù rule-author sẽ STOP → `extended-requests.json` không ai đọc; chấp nhận để mental model đơn giản. `force-candidates` là arg riêng, **chỉ** chi phối RETRIEVE/`candidate_rules`.

---

## HARD GATES — vi phạm một gate là invalidate cả stage

<HARD-GATE id="probe-first">
Coverage được quyết bởi **engine probe qua TOÀN BỘ ruleset**, không bởi classification. KHÔNG kết luận coverage từ suy luận semantic. Engine thấy mọi file — rule fire từ file không ngờ tới đều phải hiện qua probe, không bị classification che.

Phân biệt 2 việc thường bị gộp nhầm thành "classify":
- **Xác định vuln-class của template** (`classification.families` + `injection_point`) làm **sớm** ở CRAFT/adjudication — adjudication BẮT BUỘC cần nó để so `attack-<class>` (gate `root-cause-evidence` part 1), và `variant-handoff.json`/`analysis.json` luôn cần `classification` kể cả nhánh covered (nơi RETRIEVE không chạy).
- **Chọn file CRS để tra related rule** (theo ##CATALOG) mới là việc **chỉ ở RETRIEVE** để scope handoff (gate `catalog-scope`). Việc chọn file này không gate probe.
</HARD-GATE>

<HARD-GATE id="root-cause-evidence">
Covered (≥1 phần tử `root_cause_rules`) BẮT BUỘC có ≥1 rule thật sự **bắt được root cause của exploit**. Một fired rule tính là root-cause khi THỎA CẢ HAI, xét theo **tình huống thực** (KHÔNG so token cứng):
1. **Class khớp** — `tags` của rule chứa `attack-<class>` ứng với vuln-class của template (##CLASS-TAG). Đối chiếu CRS ID-range (##CATALOG) khi tag mơ hồ.
2. **Bắt đúng exploit** — rule fire trên chính **request thực thi exploit** (không phải discover/setup request đứng trước trong `http[]`) **và** tại nơi payload thật sự đi vào (param/header/body mang PoC, không phải field phụ), **và** detection đủ **generic** để trigger bởi pattern exploit chứ không phải trùng hợp một token vô tình. Đối chiếu: `matched_var` (engine trả, dạng SecLang) có rơi vào đúng param/location mà PoC đặt payload không — cùng chỗ thì khớp.

`blocked:true` **một mình KHÔNG đủ**: block có thể do rule sai class (template SQLi nhưng chỉ 933xxx PHP nổ), do cộng dồn generic/protocol (920/921), hoặc đúng class nhưng fire ở field phụ / trên discover request → đều **not** root-cause. Score/block là fact phụ, không tự nâng thành covered.
</HARD-GATE>

<HARD-GATE id="pl2-default">
Probe **một lần tại PL2**. Đổi PL chỉ khi user yêu cầu tường minh.
</HARD-GATE>

<HARD-GATE id="no-conf-read">
KHÔNG `Read` full file `.conf`, KHÔNG grep regex operator body (machine-generated ~12KB/dòng — vô dụng để reason, tốn token). Engine là oracle match (rule nào fire, match var nào). **Source location + metadata của MỌI rule (fired hay không) lấy từ `.claude/skills/crs-retrieve-analyze/index/<fileid>.tsv` theo `id`** (cột `file`/`line`/`operator`/`variables`/`transforms`/`chain`/`phase`/`tags`/`msg`, regex đã strip) — KHÔNG grep `.conf` để lấy `line`. probe output KHÔNG cấp `file`/`line`/`operator` (Coraza line sai). Cần biết match hay không → probe.

**Exception — INSPECT-ROOT-CAUSE (nhánh covered only):** Với từng root-cause rule, **chỉ** được `Read coreruleset/rules/<file>` (`offset=<line>-1` + `limit=40`) **khi index row có `operator`=`@rx` HOẶC `chain`=1** — đó là hai ca duy nhất index không tải nổi (regex body / điều kiện chain). Với `@detectSQLi`/`@detectXSS`/`@pm`/`@pmFromFile` và `chain`=0 thì index row đã đủ (operator type + data file + transforms + variables) → **KHÔNG** Read `.conf`. Scope cứng: **chỉ root-cause rules**, không expand sang candidate/related/fired-off-root-cause. Source of truth cho `file` và `line` vẫn là index TSV. Mục đích: extract operator type, transforms, key pattern (truncate `@rx` tại 300 chars), chain structure — để giải thích cơ chế bắt, KHÔNG để quyết coverage (oracle vẫn là probe-engine).
</HARD-GATE>

<HARD-GATE id="catalog-scope">
Việc chọn file CRS để tra ở RETRIEVE (theo ##CATALOG) chỉ **scope RETRIEVE/handoff**, KHÔNG gate probe — probe luôn bắn qua toàn ruleset. Đây chỉ là bảng tra, **không** phải field lưu trong artifact. Không grep repo-wide tùy hứng. Exception: Grep theo CVE ID trên `coreruleset/rules/` — **bonus best-effort, hit-rate thấp** (toàn corpus chỉ ~23 CVE, đều ở comment, KHÔNG có tag CVE, KHÔNG nằm trên dòng regex): dùng `output_mode:content` + `-n` + `head_limit≈10`, **bỏ qua** match trên dòng `SecRule`/regex; map comment→id qua index (không `-A`/Read `.conf`). Attack class không xác định → `934` (GENERIC) + `confidence: low`.
</HARD-GATE>

<HARD-GATE id="cap">
Ở RETRIEVE (chỉ nhánh not-covered), deep-inspect tối đa **5 candidate** cho `candidate_rules` (ưu tiên rule engine đã thấy fire nhưng off-root-cause, rồi rule cùng class từ index). Rule còn lại chỉ enumerate id + assessment ngắn; không expand regex.
</HARD-GATE>

<HARD-GATE id="conservative">
Không có root-cause rule (không rule nào fire, hoặc fire nhưng sai class/sai scope), coverage uncertain, hoặc probe `error` → `not-covered`. Không nhượng bộ coverage chỉ vì PoC bị block hay vì family match.
</HARD-GATE>

<HARD-GATE id="terminal">
Sau khi verdict artifact đã write → HALT. Không author/synthesize/patch rule, không invoke skill khác.
</HARD-GATE>

> Anti-Patterns + Red Flags đầy đủ ở `reference.md`. Tham chiếu khi định shortcut.

---

## CRAFT — chọn request exploit + ghi probe-input file

1. **Read** template `.yaml` (path là input sẵn — KHÔNG cần Glob đi tìm template). Extract: `id`, `info.name`, `info.description`, `info.tags`, `info.severity`, `cwe-id` (hint phụ), và **`http[]` block** (`method`, `path`/`raw`, `headers`, `body`) + `matchers` (payload cụ thể).
2. **Quyết định request(s) nào để probe.** `http[]` có thể gồm nhiều request — một số là **discover/setup** (tìm path, lấy token/CSRF) đứng trước; exploit thật nằm ở request mang payload (đối chiếu `matchers`). Probe-engine chạy **mỗi request như một transaction độc lập** (không giữ session) → chỉ craft request **mang payload exploit**, bỏ discover request. Template multi-vector → craft nhiều request exploit (mỗi vector một entry). Không synth generic `/p?q=`. Route payload đúng location: query → `uri` (**URL-encode**; space/quote thô trip 920100); body → `body` + đúng `Content-Type` (kích body processor; thiếu thì payload không vào ARGS); header/cookie → `headers` map. Request layout sai → probe fire sai rule.
3. **Write `out/<template_id>/probe-input.json`** — luôn dùng dạng batch `requests[]` (kể cả 1 request) + `paranoia: 2`. Mọi artifact của template sống trong **một folder `out/<template_id>/`**; Write đầu tiên này tạo folder, các bước sau (probe-raw/probe/analysis/verdict) ghi vào cùng folder nên shell redirect ở PROBE không phải mkdir. Thứ tự trong mảng = `index` ở output, ghi nhớ index nào ↔ request/vector nào để map về `injection_point`.
   ```json
   { "requests": [
       { "method": "GET", "uri": "/duomiphp/ajax.php?action=addfav&uid=<POC_URL_ENCODED>",
         "headers": { "Content-Type": "application/json" }, "body": "" }
     ],
     "paranoia": 2 }
   ```
4. **Ghi `injection_point` (plain) + `injection_slot` (ModSec var)** — hai field bổ sung nhau trong `classification`:
   - **`injection_point`** (plain prose, human record): request nào (method+path của exploit request) + tên param/header/body (vd "query param `uid`", "header `Referer`", "JSON body `cmd`"). Đây là record duy nhất về điểm tiêm khi không rule nào fire (nhánh not-covered) ở dạng người đọc.
   - **`injection_slot`** (ModSec request-variable string, machine handoff): cùng điểm tiêm đó nhưng diễn đạt bằng **biến ModSec** của request `exploit_index` — vd `REQUEST_HEADERS:Authorization`, `ARGS_GET:uid`, `ARGS_POST:cmd`, `REQUEST_BODY`, `REQUEST_COOKIES:PHPSESSID`. Đây là vector **chuẩn** chia sẻ với Stage 2 (variant-gen craft trong slot này; rule-author scope rule vào đúng biến này), nên KHÔNG để variant-gen tự đoán lại từ prose. Khi **covered**, `injection_slot` phải khớp `matched_var` của root-cause rule (engine trả dạng SecLang — chính là biến này). Bảng map var→slot vật lý + var được phép: `crs-variant-gen/reference.md ##SCHEMA` (header/cookie cần `:Name`; `ARGS` mơ hồ → tách `ARGS_GET`/`ARGS_POST`; `REQUEST_LINE`/`FULL_REQUEST`/`REQUEST_METHOD` không phải slot).
5. **payload_samples**: chỉ `poc` (exact string từ template) + `poc-decoded` (nếu encoded) — để tài liệu hóa + nuôi handoff. **Không** tạo bypass variant ở Stage 1.
> Signal precedence cho classify: payload trong `matchers`/`raw` > `tags` > `name`/`description` > `cwe-id`.

## PROBE — adjudication chính (engine-as-oracle, PL2)

Pipeline file-based 3 bước (path **tương đối repo root**, command tường minh — KHÔNG cần đọc README tool). Bỏ `.exe` trên Linux/macOS. **KHÔNG prefix `cd <path> &&`** — working directory khi chạy trong skill đã là repo root; thêm `cd` với output redirection bị Claude Code flag "path resolution bypass" → prompt thủ công.

1. **Probe** (đọc probe-input, log raw output):
   ```bash
   ./tools/probe-engine/probe-engine.exe --crs coreruleset \
     --input out/<template_id>/probe-input.json --output out/<template_id>/probe-raw.json
   ```
2. **Parse** (project whitelist field, drop noise — script tự lo projection):
   ```bash
   python .claude/skills/crs-retrieve-analyze/tools/parse_probe.py \
     out/<template_id>/probe-raw.json out/<template_id>/probe.json
   ```
   `probe-raw.json` là **pure staging** — sau khi ghi `probe.json` thành công, script **tự xoá** raw (file lớn/noisy nhất, không ai khác đọc). Crash trước đó → raw còn nguyên để soi. Cần giữ để debug → thêm `--keep-raw`.
3. **Read `out/<template_id>/probe.json`** (đã gọn, chỉ field cần). **KHÔNG** Read `probe-raw.json` (đã bị xoá; vốn đầy noise).

Parsed schema: `{status, error, results[]}`; mỗi `results[]` = `{index, paranoia, blocked, anomaly_score{inbound,threshold,to_block,score_pl1,score_pl2}, matched_rules[]{id,tags,paranoia_level,msg,matched_var[],variables[]{variable,key,value}}}`. `matched_var[]` = list `"VARIABLE:KEY"` parser tự derive từ `variables[]`. (KHÔNG có `file`/`line`/`operator` — lấy từ index theo `id` ở RETRIEVE.) Chọn `result` ứng request exploit (theo `index` đã ghi nhớ ở CRAFT). Field-consumption contract đầy đủ: ##PROBE (reference.md).

**Adjudicate root-cause** (gate `root-cause-evidence`): với mỗi matched rule, đánh `root_cause:true` khi (1) `tags` chứa `attack-<class>` của template **VÀ** (2) rule bắt đúng exploit — `matched_var` rơi vào đúng param/location mà PoC đặt payload (cùng chỗ với `injection_point`), trên chính request exploit, detection đủ generic (không trùng hợp token vô tình). Xét theo tình huống thực, không so token cứng.
- ≥1 rule `root_cause:true` → **covered**. Ghi rule đó vào `root_causes.root_cause_rules` (kèm `reason`); sinh `recommendation`. Block/score đọc thẳng từ `probe.anomaly_score`, không lưu field riêng.
- Không rule nào `root_cause:true` (kể cả khi `blocked:true` do rule sai class/field phụ/discover request, hoặc không rule nào fire) → **not-covered**, sang RETRIEVE.
- `status:error` → fallback semantic, nghiêng `not-covered` (gate `conservative`).

> `score_pl1` ≥ `threshold` và root-cause rule là PL1 → caught & block ngay ở PL1 (deployment mặc định). `score_pl1 < threshold` nhưng `inbound ≥ threshold` → root cause chỉ block từ PL2 — note vào recommendation. Block nhờ cộng dồn generic (root-cause rule fire nhưng score lẻ) cũng caught hợp lệ, nhưng nếu **không** root-cause rule nào fire thì block đó vô nghĩa cho verdict.

## SCOPE-GATE — chạy khi not-covered (sau adjudication, TRƯỚC GEN-VARIANTS)

Mục tiêu: với template mà adjudication ra **not-covered** (0 rule `root_cause:true`), quyết xem gap có nằm **trong tầm content-inspection của WAF** không. Nếu không → dừng sớm: **KHÔNG spawn variant-gen** (mutate payload vô nghĩa khi exploit không có content signature), emit verdict kèm reasoning trace. Gate **chấp nhận false out-of-scope** (bỏ sót vài variant đáng lẽ tìm thấy) để đổi lấy không đốt token cho lớp vuln mà signature generic không thể phủ (broken-access-control, IDOR, business-logic, missing-auth).

Phân loại theo **cơ chế** (có content token bất thường để match không) — KHÔNG theo tên vuln-family: `auth-bypass` bằng SQLi (`admin'--`) hay traversal (`..;/admin`) vẫn **in-scope**; chỉ auth-bypass *không mang payload* (missing-auth, forced-browsing, default-creds) mới out-of-scope.

Đọc theo thứ tự, **dừng ở dòng đầu tiên kết luận được** (short-circuit). Ghi MỌI câu trả lời đã đánh giá vào `scope_gate` trace.

| # | Câu hỏi | Trả lời | → Kết luận |
|---|---------|---------|-----------|
| **G0** | *(Precondition — đọc thẳng từ `probe.json`, KHÔNG phải LLM judgment)* Có rule nào `root_cause:true` không? | **Có** | `covered` — **không vào gate** (theo luồng covered bình thường) |
| | | Không | → G1 |
| **G1** | Request exploit có mang **token nội dung bất thường** mà request hợp lệ không có không? (injection metachar, traversal `../` `..;/`, string known-bad như `alg:none`, struct malformed/oversized) | **Có** | `in-scope` — có thứ để match → GEN-VARIANTS |
| | | Không | → G2 |
| **G2** | Detect có **bắt buộc app-specific state** WAF không thể biết không? (session hợp lệ, quyền sở hữu object, độ nhạy endpoint, business rule, danh tính người gửi) | **Có** | → G4 |
| | | Không | → G3 |
| **G3** | injection_slot có **payload cụ thể để variant-gen mutate** không, hay exploit chính là **sự vắng mặt** của thứ gì đó (credential/header)? | Vắng mặt / không payload | → G4 |
| | | Có payload | `in-scope` *(G1 có thể đánh giá thiếu — re-examine content signature)* |
| **G4** | Có thể diễn đạt detection bằng một **signature CVE-cứng deterministic** không? (path cố định + điều kiện thiếu header, vd `GET /api/v1/monitor/messages` khi không có `Authorization`) | **Có** | `virtual-patch-only` — viết được nhưng app-specific, ngoài CRS core |
| | | Không | `out-of-scope-structural` — business-logic / IDOR thuần, không signature nào tồn tại |

**Bốn terminal:** `covered` · `in-scope` · `virtual-patch-only` · `out-of-scope-structural`. Verdict nhị phân giữ nguyên (`covered`/`not-covered`); `scope_gate.decision` mang sắc thái + **điều khiển spawn**: chỉ `in-scope` mới sang GEN-VARIANTS, hai cái `*-scope` còn lại **suppress variant-gen** (GEN-VARIANTS skip — xem note ở section đó).

- **G0 là điều kiện cứng** — không bao giờ để G1–G4 đè một probe hit thật. Đặt trước nhất.
- **G1–G4 là LLM judgment** trên `classification` + `payload_samples` đã có ở `variant-handoff.json`; không cần input mới.

Trace **append vào `verdict.json`** (qua `analysis.json` ở EMIT), ghi đủ mọi G đã đánh giá + `rationale`:

```json
"scope_gate": {
  "entered": true,
  "g0_root_cause_fired": 0,
  "g1_content_signature": false,
  "g2_app_state_required": true,
  "g3_mutatable_payload": false,
  "g4_deterministic_cve_signature": true,
  "decision": "virtual-patch-only",
  "rationale": "No payload token in request; detection requires knowing the endpoint is auth-protected (app-state); exploit is absence of Authorization header; but a fixed path + missing-header rule is expressible → virtual-patch-only, not structural."
}
```

> Ví dụ CVE-2026-21445 (missing-auth): G0=0 → G1=no → G2=yes → G4=yes → **`virtual-patch-only`**; variant-gen KHÔNG spawn, `rationale` ghi rõ lý do.

## INSPECT-ROOT-CAUSE — chỉ chạy khi covered (sau PROBE, trước EMIT)

Mục tiêu: với mỗi root-cause rule, drill vào cơ chế cụ thể rule đó bắt exploit như thế nào — operator, transforms, key pattern, và liên kết với payload thực từ probe. Kết quả nuôi `recommendation.rule_analysis[]` ở EMIT.

Với mỗi `id` trong `root_cause_rules` (thường ≤3, gate `cap` không áp):

1. **Lookup index row** — **Grep `^<id>\t`** (`output_mode:content`) trên `.claude/skills/crs-retrieve-analyze/index/<fileid>.tsv` (fileid = 3 chữ số đầu của `id`, vd 932200 → `932.tsv`). Trả đúng 1 row (~200 char) thay vì cả file. Đọc theo header (`id, file, line, phase, pl, variables, operator, transforms, chain, severity, tags, msg`) → lấy `file`, `line`, `operator`, `chain`, `transforms`, `variables`.
2. **Read rule block — CHỈ khi `operator`=`@rx` HOẶC `chain`=1.** `Read coreruleset/rules/<file>` với `offset=<line>-1` + `limit=40` (đủ để thấy SecRule statement + chain nếu có). Nếu `operator` ∈ {`@detectSQLi`,`@detectXSS`,`@pm`,`@pmFromFile`} và `chain`=0 → **bỏ Read**, pattern_excerpt lấy thẳng từ cột `operator` (tên engine / tên data file).
3. **Extract:**
   - **variables scope** — dải biến rule inspect (vd `REQUEST_COOKIES|...|ARGS|XML:/*`)
   - **operator + pattern** — loại operator (`@rx`, `@pm`, `@pmFromFile`, `@detectSQLi`…) + nội dung key: với `@rx` lấy tối đa 300 chars đầu (phần regex thường rất dài, chỉ lấy đầu để identify class pattern); với `@pmFromFile` ghi tên data file; với `@detectSQLi`/`@detectXSS` ghi tên engine
   - **transforms** — list `t:` áp dụng (normalize payload trước khi match)
   - **chain** — nếu SecRule kết thúc `\,`, tóm tắt điều kiện chain (SecRule variables + operator của block tiếp)
4. **Cross-reference với probe payload** — `variables[].value` từ probe là payload đã qua transforms (Coraza thường log sau `t:lowercase`). Với thông tin đã extract, identify **token/construct cụ thể** trong payload triggered rule:
   - `@rx`: từ key subpattern (có thể dài, estimate từ msg + phần đầu pattern) — chỉ ra construct trong payload likely matched (vd lambda pattern, `__import__`, `cat /etc/passwd`)
   - `@pmFromFile`: name data file → infer keyword class; cross-ref payload để chỉ exact keyword
   - `@detectSQLi`/`@detectXSS`: nêu engine phân tích cấu trúc nào của payload
5. **Ghi `rule_analysis[]`** — per-rule: `id`, `msg`, `operator`, `transforms`, `pattern_excerpt`, `matched_at`, `trigger_explanation` (mô tả cơ chế + token trigger cụ thể). Dùng cho `recommendation` ở EMIT.

> Exception gate `no-conf-read` cho phép Read targeted rule block **chỉ khi `operator`=`@rx` hoặc `chain`=1**; KHÔNG Read full file. Source of truth cho `file`/`line`: index TSV.

## RETRIEVE — chạy khi không có root_causes (HOẶC luôn chạy khi `force-candidates` mode)

Mục tiêu: cung cấp material cho Rule Designer — danh sách **CRS rule liên quan** tới gap (cùng class, scope gần, hoặc đã fire off-root-cause), **đã rank theo độ liên quan** kèm `why`. Stage 1 KHÔNG quyết Action A (sửa rule sẵn) hay Action B (author rule mới từ few-shot), cũng KHÔNG gán nhãn fix/example — vì phán điều đó cần đọc rule logic (regex) mà stage này bị cấm đọc. Stage 2 đọc được regex sẽ tự quyết dựa trên `why` + thứ hạng.

> **Force-candidates mode (covered branch):** RETRIEVE chạy y hệt các bước dưới đây, nhưng **loại trừ mọi id đã nằm trong `root_cause_rules`** khỏi `candidate_rules` (candidate là rule *bổ sung*, không lặp root-cause — script abort nếu trùng). Đây là related rule để Stage 2 tham chiếu/mở rộng dù template đã covered.

1. **Chọn file CRS để tra** từ ##CATALOG dựa trên vuln-class **đã xác định ở CRAFT/adjudication** (`classification.families`) — bước RETRIEVE chỉ thêm phần file-selection để scope lookup, không lưu thành field; không re-classify lại từ đầu.
2. **Engine-identified (mạnh nhất):** rule đã fire ở probe nhưng off-root-cause (sai scope / cận class) — lấy `id` từ `matched_rules`, rồi **Grep `^<id>\t`** trên `.claude/skills/crs-retrieve-analyze/index/<fileid>.tsv` lấy `file/line/operator/pl` (1 row, KHÔNG Read full file). `pl` từ index; có thể đối chiếu `matched_rules[].paranoia_level` từ probe (phải khớp). Đây là tín hiệu "related" rõ nhất.
3. **(CVE — bonus, best-effort):** Template có CVE ID → Grep chuỗi CVE trên `coreruleset/rules/` với `output_mode:content` + `-n` + `head_limit≈10`. CVE chỉ ở comment (KHÔNG có tag, KHÔNG ở dòng regex) → token-safe; **bỏ qua** match trên dòng `SecRule`. Hit thì map comment→rule: id của rule có `line` nhỏ nhất > số dòng comment trong cùng file (tra index) — KHÔNG `-A`/Read `.conf`. Phần lớn CVE template grep rỗng (toàn corpus ~23 CVE); coverage vẫn do probe quyết, đây chỉ tín hiệu phụ.
4. **Index-identified:** Read `.claude/skills/crs-retrieve-analyze/index/<fileid>.tsv` (full — cần scan cả class để rank; mỗi file ≤16KB, chấp nhận được), lọc rule class-relevant **không** fire — rank bằng 4 criteria: **scope** (variables ∩ injection_point), **operator+transform** (có normalize được encoding template không), **phase**, **pl** (tie-break: `pl` thấp hơn ưu tiên hơn — rule PL1 hữu ích hơn cho deployment mặc định). Đây là nơi criteria được dùng — để **xếp hạng candidate**, KHÔNG để quyết coverage.
5. Mỗi candidate điền đủ `id/file/line/operator/pl` (từ index cột tương ứng) + `why` (cite cơ chế: scope/operator/transform/phase/pl) theo spec ##SCHEMA. Sắp xếp theo độ liên quan giảm dần (engine-fired off-root-cause + scope gần lên đầu) — order = ưu tiên cho Stage 2.
6. Gate `cap`: ≤5 candidate deep-inspect.

## GEN-VARIANTS — spawn bg Agent (CHỈ theo arg `gen-variants`, độc lập coverage/force-candidates)

`variant-handoff.json` luôn được write trước như một bước chuẩn (xem ##VARIANT-HANDOFF bên dưới). GEN-VARIANTS quyết **có spawn Agent hay không + mode nào**, **chỉ dựa trên arg `gen-variants`** — KHÔNG phụ thuộc covered/not-covered hay `force-candidates`. (`force-candidates` chỉ chi phối RETRIEVE/`candidate_rules`, không đụng tới variant-gen.)

> **SCOPE-GATE override:** nếu `scope_gate.decision` ∈ {`virtual-patch-only`, `out-of-scope-structural`} → **KHÔNG spawn** bất kể arg `gen-variants` (mutate vô nghĩa khi exploit không có content signature). EMIT tự write `extended-requests.json` PoC-only. Chỉ `in-scope` (hoặc gate không chạy vì covered) mới theo bảng `gen-variants` dưới đây.

| `gen-variants` | Hành động |
|---|---|
| `off` | KHÔNG spawn. EMIT tự write `extended-requests.json` (PoC-only). |
| `class-only` (default) | Spawn `--gen-variants=class-only` (craft từ template/family). |
| `root-cause-only` | Spawn `--gen-variants=root-cause-only` (variant-gen fallback class-only nếu no root cause). |
| `all-triggered-rules` | Spawn `--gen-variants=all-triggered-rules` (fallback class-only nếu nothing fired). |

> **Đánh đổi có chủ ý:** vì spawn độc lập coverage, ca `covered` + không `force-candidates` vẫn spawn variant-gen (gen-variants≠off) → `extended-requests.json` sinh ra nhưng rule-author sẽ STOP (covered & `candidate_rules==[]`) nên không ai đọc. Chấp nhận đánh đổi này để mental model đơn giản (gen-variants là knob duy nhất cho variant production).

Spawn timing: sau khi `variant-handoff.json` + `probe.json` tồn tại (covered → sau INSPECT-ROOT-CAUSE; not-covered → sau adjudication). Agent chạy nền; main conversation tiếp tục — RETRIEVE (nếu Stage 2 chạy) rồi EMIT, hoặc EMIT thẳng (covered + không force-candidates).

**Khi spawn:**
```
Agent(run_in_background=True, prompt="""
  Working directory: D:/vcs/crs-rule-generation-workflow
  Invoke Skill(crs-variant-gen) — KHÔNG tự implement, KHÔNG đọc SKILL.md rồi làm thủ công.
  Args:
    --gen-variants=<class-only|root-cause-only|all-triggered-rules>
    out/<id>/variant-handoff.json
    out/<id>/probe.json
    template: <template_path>
""")
```

Agent chạy nền. Main conversation tiếp tục RETRIEVE → EMIT → HALT.
`extended-requests.json` được agent write; Stage 2 chờ file này tồn tại.

## VARIANT-HANDOFF — write sau adjudication (luôn làm, không phụ thuộc gen-variants)

**Write `out/<id>/variant-handoff.json`** ngay sau INSPECT-ROOT-CAUSE (covered) hoặc ngay sau adjudication (not-covered), **trước RETRIEVE**. File này là partial context cho crs-variant-gen — tồn tại bất kể `gen-variants` mode nào (kể cả `off`), vì các mode root-cause-only/all-triggered-rules cần `root_cause_rules`/`matched_rules` từ đây để quyết fallback.

```json
{
  "template_id": "<id>",
  "template_path": "<path>",
  "exploit_index": 0,
  "classification": {"families": [...], "injection_point": "...", "injection_slot": "REQUEST_HEADERS:Authorization", "protocol": "..."},
  "payload_samples": [...],
  "root_cause_rules": [{"id": "...", "reason": "..."}],
  "rule_analysis": [{"id": "...", "msg": "...", "operator": "...", "transforms": [...],
                     "pattern_excerpt": "...", "matched_at": "...", "trigger_explanation": "..."}],
  "scope_gate": {"decision": "in-scope", "rationale": "..."}
}
```
Not-covered: `root_cause_rules: []`, `rule_analysis: []`, `scope_gate` = kết quả SCOPE-GATE (không null). Covered: `root_cause_rules`/`rule_analysis` điền từ INSPECT-ROOT-CAUSE; `scope_gate: null` (gate không chạy).

> **Quan hệ với `analysis.json` (EMIT) — `rule_analysis` để top-level ở đây, có chủ ý:** file này mang `rule_analysis[]` **phẳng** (không bọc trong `recommendation`) vì variant-gen chỉ cần đúng mảng đó. Ở EMIT, `analysis.json` mới bọc nó lại thành `recommendation: {summary, pl_coverage, rule_analysis[]}` (thêm `summary` + `pl_coverage`) — xem ##SCHEMA reference.md. Nhờ vậy **một tên `recommendation` không còn mang hai hình dạng**: ở đây không có field `recommendation`, chỉ `rule_analysis` phẳng. **Drift rule:** `classification`, `payload_samples`, `root_cause_rules`, `rule_analysis` ở `analysis.json` PHẢI copy **verbatim** từ `variant-handoff.json` — chỉ thêm field mới (`summary`/`pl_coverage`/`candidate_rules`/`note`), không sửa nội dung đã có. Not-covered: ở đây `rule_analysis: []`; `analysis.json` thì **bỏ hẳn** `recommendation` (chỉ để `candidate_rules`).

## EMIT — terminal (WRITE-ONLY)

Model **chỉ write JUDGMENT** vào `out/<template_id>/analysis.json`; script `assemble_verdict.py` **nhét probe transcript** từ `probe.json` vào → `verdict.json`. Model **KHÔNG** chép lại transcript bằng tay. Schema 2 file + thứ tự field: ##SCHEMA (reference.md).

1. **Write `out/<template_id>/analysis.json`** — chỉ field model tự quyết: `template_id`, `template_path`, `exploit_index` (index request exploit trong probe-input, default 0), `classification` (gồm `injection_point` plain), `payload_samples`, **`root_cause_rules`** (list `{id, reason}` — rule nào model phán root-cause; `[]` ⇒ not-covered), `recommendation` (khi covered) **hoặc** `candidate_rules` (khi not-covered), **`scope_gate`** (bắt buộc khi not-covered — block trace G0–G4 + `decision` + `rationale` từ SCOPE-GATE; bỏ khi covered), `note` (optional). **Nếu `force-candidates` mode:** thêm `force_candidates: true` và ghi **cả** `recommendation` lẫn `candidate_rules` (covered case) — script sẽ giữ list thay vì ép `[]`.

   **Trường hợp `gen-variants=off`:** EMIT tự write `out/<id>/extended-requests.json` — PoC-only, không spawn agent (độc lập coverage/force-candidates, đối xứng với việc spawn của các mode khác):
   ```json
   {
     "paranoia": <từ probe.json results[exploit_index].paranoia>,
     "requests": [<request tại exploit_index từ probe-input.json.requests[]>],
     "labels": ["poc"],
     "meta": [{"label": "poc", "evades_rule": null, "rationale": "base PoC from template"}]
   }
   ```
   Đọc `probe-input.json` (đã write ở CRAFT) để lấy request. Stage 2 dùng file này trực tiếp — không cần chạy crs-variant-gen. (Các mode `gen-variants≠off` đã spawn agent ở GEN-VARIANTS để write file này.)
2. **Assemble** (script lo phần cơ học: inject transcript, annotate `root_cause` theo id, fill `matched_var`/`msg` từ probe, suy covered, in dòng confirmation):
   ```bash
   python .claude/skills/crs-retrieve-analyze/tools/assemble_verdict.py \
     out/<template_id>/probe.json out/<template_id>/analysis.json out/<template_id>/verdict.json
   ```
   - **Guardrail:** mọi `id` trong `root_cause_rules` PHẢI nằm trong rule đã fire ở exploit request — script abort (exit≠0) nếu không. Sửa adjudication, KHÔNG bịa root-cause rule.
   - **Cleanup:** `analysis.json` là pure staging (`verdict.json` là superset) — sau khi ghi verdict thành công + qua hết guardrail, script **tự xoá** `analysis.json`. Abort thì giữ nguyên để sửa. Cần giữ để soi pre-injection → `--keep-analysis`.
   - covered/not-covered **suy thẳng** từ length `root_cause_rules` (không field `verdict`). Script in **đúng một dòng** `out/<id>/verdict.json — <covered|not-covered>` — đó là output cuối, không in gì thêm.
3. Script lỗi (guardrail/exit≠0) → đọc message, sửa `analysis.json`, chạy lại. HALT sau khi verdict.json tồn tại.

Exception: chỉ present nội dung artifact ra conversation khi user request tường minh.
Không exit nào khác được phép (author rule, edit `.conf`, invoke skill).

---

## Checklist (tạo task, complete theo thứ tự)

1. **CRAFT** — Read template; xác định **vuln-class** (`classification.families`, theo signal precedence) + `injection_point` (plain) + `injection_slot` (ModSec var của request exploit_index); chọn request exploit (bỏ discover); **Write `out/<id>/probe-input.json`** (batch `requests[]`, PL2); ghi `payload_samples` (poc + decoded). Không tạo variant. (vuln-class xác định ở đây để adjudication so `attack-<class>`; RETRIEVE sau chỉ chọn file CRS, không re-classify.)
2. **PROBE** — chạy probe-engine `--input probe-input.json --output probe-raw.json`; `parse_probe.py` → `probe.json`; **Read `probe.json`** (không đọc raw); adjudicate root-cause (class khớp + bắt đúng exploit); covered = `root_cause_rules` non-empty.
3. *(nhánh covered)* **INSPECT-ROOT-CAUSE** — với từng root-cause rule: Grep `^<id>\t` index row lấy `file`/`line`/`operator`/`chain`; **Read rule block** (`offset=line-1, limit=40`) **chỉ khi `@rx` hoặc `chain`=1**, còn lại dùng thẳng index row; extract operator/transforms/pattern_excerpt; cross-reference `variables[].value` từ probe → `trigger_explanation`. Kết quả → `rule_analysis[]` cho recommendation. Sau đó **Write `variant-handoff.json`** (luôn làm — xem ##VARIANT-HANDOFF). **gen-variants≠off:** spawn bg Agent(crs-variant-gen `--gen-variants=<mode>`) — độc lập coverage/force-candidates.
   *(nhánh not-covered)* **Write `variant-handoff.json`** ngay sau adjudication (luôn làm). **gen-variants≠off:** spawn bg Agent(crs-variant-gen `--gen-variants=<mode>`) trước RETRIEVE. **RETRIEVE** — chọn file CRS theo ##CATALOG (vuln-class đã có từ CRAFT/adjudication, không re-classify); engine-fired off-root-cause + index lookup + 4-criteria rank ≤5 → `candidate_rules` (đã rank, kèm `why`).
   *(force-candidates mode, covered)* chạy **thêm** RETRIEVE (sau INSPECT-ROOT-CAUSE); candidate_rules loại id đã là root-cause; set `force_candidates: true`. (force-candidates **không** ảnh hưởng spawn variant-gen.)
4. **EMIT** — **Write `out/<id>/analysis.json`** (chỉ judgment: classification, payload_samples, `root_cause_rules`{id,reason}, recommendation structured object / candidate_rules; `force_candidates:true` nếu mode bật → ghi cả hai); chạy `assemble_verdict.py probe.json analysis.json verdict.json` (script inject transcript + in dòng confirmation); **gen-variants=off:** cũng write `extended-requests.json` (PoC-only, đọc từ `probe-input.json`); HALT. Không phát nội dung ra conversation.

## Failure handling
1. Template sparse (không matcher/`raw`) → classify theo `name`/`description`, set `confidence: low`, dựng request best-effort, proceed.
2. `probe.json` có `status:"error"` (bad `--crs`, ruleset hỏng, input JSON sai — message ở `error`) → KHÔNG đọc thành coverage; fallback semantic, verdict nghiêng `not-covered`, ghi `note` lý do.
3. Có rule fire & blocked nhưng **không** root-cause (sai class/sai scope) → `not-covered` (đúng behavior); rule đó giữ trong `probe.matched_rules` với `root_cause:false` (không list riêng).
4. `.claude/skills/crs-retrieve-analyze/index/<fileid>.tsv` missing hoặc nghi stale (coreruleset vừa update) → chạy `python .claude/skills/crs-retrieve-analyze/tools/build_rule_index.py` rồi proceed; target file absent khỏi index → report user, không fabricate rule ID. (Index chỉ cần cho RETRIEVE handoff; probe không phụ thuộc index.)
