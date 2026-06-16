---
name: crs-retrieve-analyze
description: Stage 1 của pipeline CRS rule-generation (purple-team oriented). Coverage analysis cho MỘT Nuclei template (.yaml) đối chiếu OWASP CRS bằng engine-as-oracle (probe-engine/Coraza). Dựng request thật từ template, probe PoC tại PL2, đọc matched_rules + anomaly-score, và adjudicate theo tiêu chí ROOT-CAUSE — có ≥1 rule bắt đúng root cause (attack-class tag khớp + bắt đúng exploit, xét tình huống thực) → covered (recommend rule sẵn có); ngược lại → not-covered + dựng candidate_rules (fired-off-root-cause + related rules cùng class, rank theo độ liên quan) cho Rule Designer. covered/not-covered suy từ length root_cause_rules, không có field verdict. KHÔNG author hay modify rule.
model: claude-sonnet-4-6
effort: high
allowed-tools:
  - Read
  - Grep
  - Glob
  - Write
  - Bash(python *)
  - Bash(echo * | ./tools/probe-engine/probe-engine*)
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

---

## State machine

```
CRAFT ──► PROBE(PL2) ──┬─ root-cause rule fired ──────► INSPECT-ROOT-CAUSE ──► EMIT covered ──► STOP
 (dựng req thật        │   (drill cơ chế từng rule:       (đọc rule block,          (recommendation
  từ template, PoC)    │    class khớp + đúng chỗ)         operator/transforms/       chi tiết)
                       │                                    pattern/trigger)
                       ├─ else ─► RETRIEVE ─► EMIT not-covered (handoff) ──────────────────────► STOP
                       │          (classify + grep → related rules, ranked)
                       └─ probe status:error ─► fallback semantic, nghiêng not-covered ─► EMIT ─► STOP
```
Tuần tự nghiêm ngặt. `INSPECT-ROOT-CAUSE` **chỉ** chạy ở nhánh covered (để nuôi recommendation chi tiết). `RETRIEVE` **chỉ** chạy ở nhánh not-covered (để dựng handoff). Không skip stage.

> **Mode `force-candidates` (tùy chọn, OFF mặc định):** khi user yêu cầu tường minh (vd "luôn kèm candidate_rules", "force candidates", "--candidates-always"), `RETRIEVE` chạy **thêm** ở nhánh covered (sau `INSPECT-ROOT-CAUSE`) để populate `candidate_rules` song song với `recommendation`. Verdict covered/not-covered **KHÔNG đổi** (vẫn suy từ `root_cause_rules`) — candidate ở đây chỉ là material bổ sung cho Stage 2, **loại trừ** các id đã là root-cause. Bật bằng cách set `force_candidates: true` trong `analysis.json`; mặc định (không có flag) covered ⇒ `candidate_rules: []`.

---

## HARD GATES — vi phạm một gate là invalidate cả stage

<HARD-GATE id="probe-first">
Coverage được quyết bởi **engine probe qua TOÀN BỘ ruleset**, không bởi classification. KHÔNG kết luận coverage từ suy luận semantic. Engine thấy mọi file — rule fire từ file không ngờ tới đều phải hiện qua probe, không bị classification che. Classify (đầy đủ) chỉ chạy ở RETRIEVE để scope handoff.
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
4. **Ghi `injection_point` dạng plain** — mô tả chỗ payload đi vào bằng ngôn ngữ tự nhiên: request nào (method+path của exploit request) + tên param/header/body (vd "query param `uid`", "header `Referer`", "JSON body `cmd`"). **KHÔNG** cần viết dạng SecLang (`ARGS:uid`…) — engine tự trả `matched_var` dạng đó, ta chỉ đối chiếu xem có cùng chỗ. Đây là record duy nhất về điểm tiêm khi không rule nào fire (nhánh not-covered).
5. **payload_samples**: chỉ `poc` (exact string từ template) + `poc-decoded` (nếu encoded) — để tài liệu hóa + nuôi handoff. **Không** tạo bypass variant ở Stage 1.
> Signal precedence cho classify: payload trong `matchers`/`raw` > `tags` > `name`/`description` > `cwe-id`.

## PROBE — adjudication chính (engine-as-oracle, PL2)

Pipeline file-based 3 bước (path **tương đối repo root**, command tường minh — KHÔNG cần đọc README tool). Bỏ `.exe` trên Linux/macOS.

1. **Probe** (đọc probe-input, log raw output):
   ```bash
   ./tools/probe-engine/probe-engine.exe --crs coreruleset \
     < out/<template_id>/probe-input.json > out/<template_id>/probe-raw.json
   ```
2. **Parse** (project whitelist field, drop noise — script tự lo projection):
   ```bash
   python .claude/skills/crs-retrieve-analyze/tools/parse_probe.py \
     out/<template_id>/probe-raw.json out/<template_id>/probe.json
   ```
3. **Read `out/<template_id>/probe.json`** (đã gọn, chỉ field cần). **KHÔNG** Read `probe-raw.json` (đầy noise).

Parsed schema: `{status, error, results[]}`; mỗi `results[]` = `{index, paranoia, blocked, anomaly_score{inbound,threshold,to_block,score_pl1,score_pl2}, matched_rules[]{id,tags,paranoia_level,msg,matched_var[],variables[]{variable,key,value}}}`. `matched_var[]` = list `"VARIABLE:KEY"` parser tự derive từ `variables[]`. (KHÔNG có `file`/`line`/`operator` — lấy từ index theo `id` ở RETRIEVE.) Chọn `result` ứng request exploit (theo `index` đã ghi nhớ ở CRAFT). Field-consumption contract đầy đủ: ##PROBE (reference.md).

**Adjudicate root-cause** (gate `root-cause-evidence`): với mỗi matched rule, đánh `root_cause:true` khi (1) `tags` chứa `attack-<class>` của template **VÀ** (2) rule bắt đúng exploit — `matched_var` rơi vào đúng param/location mà PoC đặt payload (cùng chỗ với `injection_point`), trên chính request exploit, detection đủ generic (không trùng hợp token vô tình). Xét theo tình huống thực, không so token cứng.
- ≥1 rule `root_cause:true` → **covered**. Ghi rule đó vào `root_causes.root_cause_rules` (kèm `reason`); sinh `recommendation`. Block/score đọc thẳng từ `probe.anomaly_score`, không lưu field riêng.
- Không rule nào `root_cause:true` (kể cả khi `blocked:true` do rule sai class/field phụ/discover request, hoặc không rule nào fire) → **not-covered**, sang RETRIEVE.
- `status:error` → fallback semantic, nghiêng `not-covered` (gate `conservative`).

> `score_pl1` ≥ `threshold` và root-cause rule là PL1 → caught & block ngay ở PL1 (deployment mặc định). `score_pl1 < threshold` nhưng `inbound ≥ threshold` → root cause chỉ block từ PL2 — note vào recommendation. Block nhờ cộng dồn generic (root-cause rule fire nhưng score lẻ) cũng caught hợp lệ, nhưng nếu **không** root-cause rule nào fire thì block đó vô nghĩa cho verdict.

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

1. **Classify đầy đủ** vuln-class + chọn file CRS để tra từ ##CATALOG (chỉ để scope lookup, không lưu thành field).
2. **Engine-identified (mạnh nhất):** rule đã fire ở probe nhưng off-root-cause (sai scope / cận class) — lấy `id` từ `matched_rules`, rồi **Grep `^<id>\t`** trên `.claude/skills/crs-retrieve-analyze/index/<fileid>.tsv` lấy `file/line/operator/pl` (1 row, KHÔNG Read full file). `pl` từ index; có thể đối chiếu `matched_rules[].paranoia_level` từ probe (phải khớp). Đây là tín hiệu "related" rõ nhất.
3. **(CVE — bonus, best-effort):** Template có CVE ID → Grep chuỗi CVE trên `coreruleset/rules/` với `output_mode:content` + `-n` + `head_limit≈10`. CVE chỉ ở comment (KHÔNG có tag, KHÔNG ở dòng regex) → token-safe; **bỏ qua** match trên dòng `SecRule`. Hit thì map comment→rule: id của rule có `line` nhỏ nhất > số dòng comment trong cùng file (tra index) — KHÔNG `-A`/Read `.conf`. Phần lớn CVE template grep rỗng (toàn corpus ~23 CVE); coverage vẫn do probe quyết, đây chỉ tín hiệu phụ.
4. **Index-identified:** Read `.claude/skills/crs-retrieve-analyze/index/<fileid>.tsv` (full — cần scan cả class để rank; mỗi file ≤16KB, chấp nhận được), lọc rule class-relevant **không** fire — rank bằng 4 criteria: **scope** (variables ∩ injection_point), **operator+transform** (có normalize được encoding template không), **phase**, **pl** (tie-break: `pl` thấp hơn ưu tiên hơn — rule PL1 hữu ích hơn cho deployment mặc định). Đây là nơi criteria được dùng — để **xếp hạng candidate**, KHÔNG để quyết coverage.
5. Mỗi candidate điền đủ `id/file/line/operator/pl` (từ index cột tương ứng) + `why` (cite cơ chế: scope/operator/transform/phase/pl) theo spec ##SCHEMA. Sắp xếp theo độ liên quan giảm dần (engine-fired off-root-cause + scope gần lên đầu) — order = ưu tiên cho Stage 2.
6. Gate `cap`: ≤5 candidate deep-inspect.

## EMIT — terminal (WRITE-ONLY)

Model **chỉ write JUDGMENT** vào `out/<template_id>/analysis.json`; script `assemble_verdict.py` **nhét probe transcript** từ `probe.json` vào → `verdict.json`. Model **KHÔNG** chép lại transcript bằng tay. Schema 2 file + thứ tự field: ##SCHEMA (reference.md).

1. **Write `out/<template_id>/analysis.json`** — chỉ field model tự quyết: `template_id`, `template_path`, `exploit_index` (index request exploit trong probe-input, default 0), `classification` (gồm `injection_point` plain), `payload_samples`, **`root_cause_rules`** (list `{id, reason}` — rule nào model phán root-cause; `[]` ⇒ not-covered), `recommendation` (khi covered) **hoặc** `candidate_rules` (khi not-covered), `note` (optional). **Nếu `force-candidates` mode:** thêm `force_candidates: true` và ghi **cả** `recommendation` lẫn `candidate_rules` (covered case) — script sẽ giữ list thay vì ép `[]`.
2. **Assemble** (script lo phần cơ học: inject transcript, annotate `root_cause` theo id, fill `matched_var`/`msg` từ probe, suy covered, in dòng confirmation):
   ```bash
   python .claude/skills/crs-retrieve-analyze/tools/assemble_verdict.py \
     out/<template_id>/probe.json out/<template_id>/analysis.json out/<template_id>/verdict.json
   ```
   - **Guardrail:** mọi `id` trong `root_cause_rules` PHẢI nằm trong rule đã fire ở exploit request — script abort (exit≠0) nếu không. Sửa adjudication, KHÔNG bịa root-cause rule.
   - covered/not-covered **suy thẳng** từ length `root_cause_rules` (không field `verdict`). Script in **đúng một dòng** `out/<id>/verdict.json — <covered|not-covered>` — đó là output cuối, không in gì thêm.
3. Script lỗi (guardrail/exit≠0) → đọc message, sửa `analysis.json`, chạy lại. HALT sau khi verdict.json tồn tại.

Exception: chỉ present nội dung artifact ra conversation khi user request tường minh.
Không exit nào khác được phép (author rule, edit `.conf`, invoke skill).

---

## Checklist (tạo task, complete theo thứ tự)

1. **CRAFT** — Read template; chọn request exploit (bỏ discover); **Write `out/<id>/probe-input.json`** (batch `requests[]`, PL2); xác định `injection_point`; ghi `payload_samples` (poc + decoded). Không tạo variant.
2. **PROBE** — chạy probe-engine `< probe-input.json > probe-raw.json`; `parse_probe.py` → `probe.json`; **Read `probe.json`** (không đọc raw); adjudicate root-cause (class khớp + bắt đúng exploit); covered = `root_cause_rules` non-empty.
3. *(nhánh covered)* **INSPECT-ROOT-CAUSE** — với từng root-cause rule: Grep `^<id>\t` index row lấy `file`/`line`/`operator`/`chain`; **Read rule block** (`offset=line-1, limit=40`) **chỉ khi `@rx` hoặc `chain`=1**, còn lại dùng thẳng index row; extract operator/transforms/pattern_excerpt; cross-reference `variables[].value` từ probe → `trigger_explanation`. Kết quả → `rule_analysis[]` cho recommendation.
   *(nhánh not-covered)* **RETRIEVE** — classify đầy đủ; engine-fired off-root-cause + index lookup + 3-criteria rank ≤5 → `candidate_rules` (đã rank, kèm `why`).
   *(force-candidates mode, covered)* chạy **cả** INSPECT-ROOT-CAUSE **và** RETRIEVE; candidate_rules loại id đã là root-cause; set `force_candidates: true`.
4. **EMIT** — **Write `out/<id>/analysis.json`** (chỉ judgment: classification, payload_samples, `root_cause_rules`{id,reason}, recommendation structured object / candidate_rules; `force_candidates:true` nếu mode bật → ghi cả hai); chạy `assemble_verdict.py probe.json analysis.json verdict.json` (script inject transcript + in dòng confirmation); HALT. Không phát nội dung ra conversation.

## Failure handling
1. Template sparse (không matcher/`raw`) → classify theo `name`/`description`, set `confidence: low`, dựng request best-effort, proceed.
2. `probe.json` có `status:"error"` (bad `--crs`, ruleset hỏng, input JSON sai — message ở `error`) → KHÔNG đọc thành coverage; fallback semantic, verdict nghiêng `not-covered`, ghi `note` lý do.
3. Có rule fire & blocked nhưng **không** root-cause (sai class/sai scope) → `not-covered` (đúng behavior); rule đó giữ trong `probe.matched_rules` với `root_cause:false` (không list riêng).
4. `.claude/skills/crs-retrieve-analyze/index/<fileid>.tsv` missing hoặc nghi stale (coreruleset vừa update) → chạy `python .claude/skills/crs-retrieve-analyze/tools/build_rule_index.py` rồi proceed; target file absent khỏi index → report user, không fabricate rule ID. (Index chỉ cần cho RETRIEVE handoff; probe không phụ thuộc index.)
