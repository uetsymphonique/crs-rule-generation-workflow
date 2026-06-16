# Chaining SecRules trong CRS

---

## Tại Sao Cần Chain?

### Giới hạn cơ bản của SecRule

Một `SecRule` đơn chỉ có thể làm được:
- Inspect **một tập variables** (hoặc một collection) với **một operator**
- Thực hiện **một disruptive action**

Điều này tạo ra giới hạn cơ bản: **không thể biểu diễn điều kiện AND trong một rule duy nhất**. Chain là cơ chế duy nhất của ModSecurity để nói "nếu A VÀ B VÀ C thì fire".

---

### Các trường hợp điển hình cần chain

#### 1. Attack chỉ có nghĩa khi nhiều điều kiện cùng xảy ra

Nhiều attack pattern chỉ là anomaly thực sự khi nhiều tín hiệu xuất hiện đồng thời. Từng tín hiệu đơn lẻ có thể hoàn toàn bình thường:

```
GET request     → bình thường
Body có data    → bình thường
GET + body      → protocol violation (RFC 9110 khuyến cáo không nên)
```

Nếu chỉ dùng 1 rule check "GET request" hoặc chỉ check "có body" thì FP rate cực cao. Chain cho phép **AND hai điều kiện** → chỉ fire khi cả hai cùng xảy ra.

> **Ví dụ thực tế:** Rule 920170 — GET/HEAD with body (Pattern 1)

---

#### 2. Match rộng để bắt attack, chain hẹp để loại bỏ FP

Vấn đề phổ biến trong WAF rule writing: regex đủ rộng để bắt attack thường cũng match traffic hợp lệ. Giải pháp là **"cast wide net, then exclude benign"**:

```
Bước 1: Match pattern tổng quát (nhiều match)
Bước 2: Chain với !@rx loại trừ các known-good strings
→ Kết quả: chỉ còn actual attacks
```

Lý do cần chain thay vì viết regex phức tạp hơn: regex negative lookahead (`(?!...)`) **bị cấm** trong CRS vì RE2 incompatibility. Chain là cách thay thế để loại trừ patterns.

> **Ví dụ thực tế:** Rule 932180 — Restricted file upload (Pattern 4)

---

#### 3. Cần xác nhận thêm trên chính matched value

Khi pattern cần phân tích sâu hơn:

```
Bước 1: Match primary pattern → capture matched value
Bước 2: Verify thêm điều kiện trên MATCHED_VARS hoặc TX:0
→ Chỉ fire nếu matched value thực sự nguy hiểm
```

Trường hợp này không thể giải quyết bằng 1 regex vì cần **kiểm tra cùng 1 value với 2 điều kiện độc lập** (ví dụ: "phải chứa `/`" AND "phải chứa whitespace"). Regex có thể làm được, nhưng tạo ra catastophic backtracking risk. Chain giải quyết cleanly và RE2-safe.

> **Ví dụ thực tế:** Rule 932200 — RCE bypass (Pattern 5)

---

#### 4. Cần extract subgroup trước khi check tiếp

Một số attack pattern nằm bên trong một larger context (ví dụ: payload trong URL path, sau khi bỏ qua domain). Cần:

```
Bước 1: Capture toàn bộ URL/header
Bước 2: Extract phần quan trọng (subgroup) vào TX:1, TX:2
Bước 3: Apply detection logic trên subgroup đó
```

Không có cơ chế nào trong 1 SecRule để vừa capture vừa check subgroup. Chain với `capture` action là cách duy nhất để "drill down" vào nested patterns.

> **Ví dụ thực tế:** Rule 932205 — RCE bypass trong Referer (Pattern 6)

---

#### 5. Check sự tồn tại của header/variable trước khi check nội dung

Hai thao tác này về bản chất khác nhau và không thể gộp vào 1 rule:

```
&REQUEST_HEADERS:Host "@eq 0"     → đếm số headers (trả về số nguyên)
REQUEST_HEADERS:Host "@rx ^$"     → check nội dung header (trả về string)
```

Nếu cần logic "header tồn tại VÀ có giá trị X" thì phải chain. Nếu dùng `REQUEST_HEADERS:Host "@rx pattern"` khi header không tồn tại → variable là empty string → có thể FP hoặc FN tùy operator.

> **Ví dụ thực tế:** Rule 920310/920311 — Empty Accept header (Pattern 2 variant)

---

#### 6. Feature flag / config gate

Admin configure thresholds và features trong `crs-setup.conf` thông qua TX variables. Detection rule chỉ nên chạy nếu feature được bật:

```
Bước 1: TX:SOME_CONFIG_FLAG "@eq 1"  → gate
Bước 2: Actual detection logic
```

Nếu không có gate chain, rule sẽ chạy unconditionally → ignores admin configuration.

> **Ví dụ thực tế:** Rule 920250 — UTF-8 validation (Pattern 7)

---

### Khi KHÔNG cần chain

| Tình huống | Giải pháp thay chain |
|-----------|---------------------|
| Cần OR conditions | Dùng `\|` trong VARIABLES hoặc `@rx a\|b` trong pattern |
| Nhiều targets cùng pattern | Dùng `REQUEST_COOKIES\|ARGS\|REQUEST_HEADERS` |
| Exclude một vài values | Dùng `ARGS\|!ARGS:safe_param` (exclusion prefix) |
| PL 1 — giữ atomic | Viết regex đủ specific thay vì chain |

### Trade-off của chain

**Lợi ích:**
- Giảm FP dramatically khi kết hợp đúng conditions
- Bypass RE2 incompatibility của lookahead/lookbehind
- Cho phép multi-step analysis trên matched values
- Logic rõ ràng, dễ đọc hơn một regex mega-pattern

**Chi phí:**
- Không được phép ở PL 1 (atomic check only)
- Engine chỉ evaluate child rules khi starter matches — thứ tự conditions ảnh hưởng performance
- Disruptive action chỉ ở starter → nếu chain fail ở bước cuối, không có partial scoring
- Metadata (msg, tag, severity) chỉ ở starter → tất cả matches trong chain share cùng 1 alert message

---

## Cú pháp và Indentation

```apache
SecRule VARIABLE_A "OPERATOR_A" \
    "id:XXXXXX,\
    phase:N,\
    block,\
    ...,\
    chain"
    SecRule VARIABLE_B "OPERATOR_B" \
        "t:none,\
        chain"
        SecRule VARIABLE_C "OPERATOR_C" \
            "t:none,\
            setvar:'tx.inbound_anomaly_score_plN=+%{tx.critical_anomaly_score}'"
```

- Mỗi child rule indent thêm **4 spaces** so với parent
- Rule cuối chain **không có `chain`**
- `setvar` luôn đặt ở rule **cuối cùng** của chain (trừ trường hợp đặc biệt — xem phần capture)

---

## Ràng Buộc Quan Trọng (từ Reference Manual)

Actions sau **chỉ được phép trong chain starter** (rule đầu tiên):

| Action | Ghi chú |
|--------|---------|
| `id` | Định danh rule |
| `phase` | Phase xử lý |
| Disruptive actions | `block`, `deny`, `allow`, `pass`, `drop` |
| `msg` | Log message |
| `tag` | Tags |
| `severity` | Severity level |
| `logdata` | Log data |
| `ver` | Version string |
| `skip` / `skipAfter` | Flow control |

Child rules chỉ được dùng: `t:xxx`, `capture`, `setvar`, `setenv`, `ctl`, `nolog`, `chain`.

---

## Pattern 1: Simple AND Chain (2 điều kiện)

**Use case:** Điều kiện A AND điều kiện B mới là attack.

**Ví dụ thực tế (Rule 920170):** GET/HEAD request có body → protocol violation

```apache
# Rule 920170 — GET or HEAD Request with Body Content
SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" \
    "id:920170,\
    phase:1,\
    block,\
    t:none,\
    msg:'GET or HEAD Request with Body Content',\
    logdata:'%{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-protocol',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/PROTOCOL-ENFORCEMENT',\
    tag:'capec/1000/210/272',\
    ver:'OWASP_CRS/4.25.0-dev',\
    severity:'CRITICAL',\
    chain"
    SecRule REQUEST_HEADERS:Content-Length "!@rx ^0?$" \
        "t:none,\
        setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

**Nhận xét:**
- Child rule dùng `!@rx` (inverted match): "Content-Length tồn tại VÀ không phải 0 hoặc rỗng"
- `setvar` chỉ ở child rule (last in chain)
- Metadata, tags, severity chỉ ở starter

---

## Pattern 2: AND Chain với `&` Count

**Use case:** Kiểm tra sự tồn tại/vắng mặt của header kết hợp với điều kiện khác.

**Ví dụ thực tế (Rule 920171):** GET/HEAD với Transfer-Encoding header

```apache
# Rule 920171 — Stricter sibling of 920170
SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" \
    "id:920171,\
    phase:1,\
    block,\
    t:none,\
    msg:'GET or HEAD Request with Transfer-Encoding',\
    logdata:'%{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-protocol',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/PROTOCOL-ENFORCEMENT',\
    tag:'capec/1000/210/272',\
    ver:'OWASP_CRS/4.25.0-dev',\
    severity:'CRITICAL',\
    chain"
    SecRule &REQUEST_HEADERS:Transfer-Encoding "!@eq 0" \
        "t:none,\
        setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

**Nhận xét:**
- `&REQUEST_HEADERS:Transfer-Encoding` đếm số Transfer-Encoding headers
- `!@eq 0` = "header này tồn tại" (count != 0)
- Kết hợp `&` với inverted operator là pattern rất phổ biến trong CRS

---

## Pattern 3: Deep AND Chain (4 điều kiện)

**Use case:** Nhiều điều kiện phải đồng thời thỏa mãn.

**Ví dụ thực tế (Rule 920180):** POST HTTP/1.x thiếu cả Content-Length lẫn Transfer-Encoding

```apache
# Rule 920180 — POST without Content-Length and Transfer-Encoding headers
# Logic: NOT (HTTP/2 or HTTP/3) AND method==POST AND no Content-Length AND no Transfer-Encoding
SecRule REQUEST_PROTOCOL "!@within HTTP/2 HTTP/2.0 HTTP/3 HTTP/3.0" \
    "id:920180,\
    phase:1,\
    block,\
    t:none,\
    msg:'POST without Content-Length and Transfer-Encoding headers',\
    logdata:'%{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-protocol',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/PROTOCOL-ENFORCEMENT',\
    tag:'capec/1000/210/272',\
    ver:'OWASP_CRS/4.25.0-dev',\
    severity:'WARNING',\
    chain"
    SecRule REQUEST_METHOD "@streq POST" \
        "chain"
        SecRule &REQUEST_HEADERS:Content-Length "@eq 0" \
            "chain"
            SecRule &REQUEST_HEADERS:Transfer-Encoding "@eq 0" \
                "setvar:'tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}'"
```

**Nhận xét:**
- Starter dùng `!@within` (inverted list check): loại trừ HTTP/2 và HTTP/3
- Child 2 và 3 dùng `&` + `@eq 0` = "header không tồn tại"
- Chỉ child cuối mới có `setvar`
- Child trung gian chỉ có `"chain"` — không cần `t:none` nếu không có transformation

---

## Pattern 4: Inverted Chain để Loại Trừ FP

**Use case:** Match attack pattern nhưng loại trừ các benign strings bằng `!@rx`.

**Ví dụ thực tế (Rule 932180):** Restricted file upload — loại trừ các filename lành tính

```apache
# Rule 932180 — Restricted File Upload Attempt
# Main rule matches known restricted filenames; chain rule excludes benign matches
SecRule FILES|REQUEST_HEADERS:X-Filename|REQUEST_HEADERS:X_Filename|REQUEST_HEADERS:X-File-Name \
    "@pmFromFile restricted-upload.data" \
    "id:932180,\
    phase:2,\
    block,\
    capture,\
    t:none,\
    msg:'Restricted File Upload Attempt',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-rce',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-RCE',\
    tag:'capec/1000/152/248/88',\
    ver:'OWASP_CRS/4.25.0-dev',\
    severity:'CRITICAL',\
    chain"
    SecRule MATCHED_VARS "!@rx (?i)(?:\.boto|buddyinfo|mtrr|acpi|zoneinfo)\B" \
        "t:none,\
        setvar:'tx.rce_score=+%{tx.critical_anomaly_score}',\
        setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

**Nhận xét:**
- `@pmFromFile` match danh sách từ file `.data` (pattern matching)
- Child dùng `MATCHED_VARS` (collection chứa tất cả values đã match) + `!@rx` = "trừ khi match benign pattern"
- Đây là pattern **"match rộng, exclude hẹp"** — rất phổ biến để giảm FP
- `capture` ở starter để lưu match vào `TX:0` (dùng trong `logdata`)
- Child có **2 `setvar`**: cả `rce_score` lẫn `inbound_anomaly_score`

---

## Pattern 5: capture + MATCHED_VARS qua Chain (3 cấp)

**Use case:** Match phức tạp — cần xác nhận thêm điều kiện trên matched value.

**Ví dụ thực tế (Rule 932200):** RCE Bypass — cần cả `/` VÀ whitespace trong matched string

```apache
# Rule 932200 — RCE Bypass Technique
# Logic: match bypass pattern AND matched string contains "/" AND matched string contains whitespace
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* \
    "@rx ['\*\?\x5c`][^\n/]+/|/[^/]+?['\*\?\x5c`]|\$[!#\$\(\*\-0-9\?-\[_a-\{]" \
    "id:932200,\
    phase:2,\
    block,\
    capture,\
    t:none,t:lowercase,t:urlDecodeUni,\
    msg:'RCE Bypass Technique',\
    logdata:'Matched Data: %{TX.0} found within %{TX.932200_MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-rce',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-RCE',\
    tag:'capec/1000/152/248/88',\
    ver:'OWASP_CRS/4.25.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.932200_matched_var_name=%{matched_var_name}',\
    chain"
    SecRule MATCHED_VARS "@rx /" \
        "t:none,\
        chain"
        SecRule MATCHED_VARS "@rx \s" \
            "t:none,\
            setvar:'tx.rce_score=+%{tx.critical_anomaly_score}',\
            setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

**Nhận xét:**
- Starter có `setvar:'tx.932200_matched_var_name=...'` để lưu context cho `logdata` — **setvar trong starter khi không phải anomaly score**
- `MATCHED_VARS` trong child rules refer đến các values đã match ở starter
- Child rules chỉ check thêm điều kiện trên **cùng matched values** — đây là cách verify multi-condition trên 1 value
- PL 2 → `inbound_anomaly_score_pl2`

---

## Pattern 6: capture + TX:N xuyên Chain (4 cấp)

**Use case:** Cần extract subgroup từ matched value rồi kiểm tra tiếp trên subgroup đó.

**Ví dụ thực tế (Rule 932205):** RCE bypass trong Referer header — cần isolate URL path trước khi check

```apache
# Rule 932205 — Sibling of 932200, targeting Referer header
# Logic: capture Referer → extract path after domain → check path contains "/" AND whitespace
SecRule REQUEST_HEADERS:Referer "@rx ^[^#]+" \
    "id:932205,\
    phase:1,\
    block,\
    capture,\
    t:none,t:lowercase,t:urlDecodeUni,\
    msg:'RCE Bypass Technique',\
    logdata:'Matched Data: %{TX.2} found within %{TX.932205_MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-rce',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-RCE',\
    tag:'capec/1000/152/248/88',\
    ver:'OWASP_CRS/4.25.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.932205_matched_var_name=%{matched_var_name}',\
    chain"
    SecRule TX:0 "@rx ^[^\.]+\.[^;\?]+[;\?](.*(['\*\?\x5c`][^\n/]+/|/[^/]+?['\*\?\x5c`]|\$[!#\$\(\*\-0-9\?-\[_a-\{]))" \
        "capture,\
        t:none,\
        chain"
        SecRule TX:1 "@rx /" \
            "t:none,\
            chain"
            SecRule TX:1 "@rx \s" \
                "t:none,\
                setvar:'tx.rce_score=+%{tx.critical_anomaly_score}',\
                setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

**Nhận xét:**
- Starter capture toàn bộ Referer → lưu vào `TX:0`
- Child 1 check `TX:0`, dùng `capture` thêm lần nữa → subgroup 1 lưu vào `TX:1`, subgroup 2 lưu vào `TX:2`
- Child 2 và 3 check `TX:1` (phần sau domain trong URL)
- **Mỗi lần `capture` trong chain đều overwrite `TX:0`, `TX:1`...** — cẩn thận thứ tự

---

## Pattern 7: Config Gate Chain

**Use case:** Chỉ check khi admin bật một feature qua `crs-setup.conf`.

**Ví dụ thực tế (Rule 920250):** UTF-8 validation — chỉ chạy nếu `TX:CRS_VALIDATE_UTF8_ENCODING == 1`

```apache
# Rule 920250 — UTF8 Encoding Abuse Attack Attempt
# Only fires if admin opted in via crs-setup.conf
SecRule TX:CRS_VALIDATE_UTF8_ENCODING "@eq 1" \
    "id:920250,\
    phase:2,\
    block,\
    t:none,\
    msg:'UTF8 Encoding Abuse Attack Attempt',\
    logdata:'%{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-protocol',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/PROTOCOL-ENFORCEMENT',\
    tag:'capec/1000/255/153/267',\
    ver:'OWASP_CRS/4.25.0-dev',\
    severity:'WARNING',\
    chain"
    SecRule REQUEST_FILENAME|ARGS|ARGS_NAMES "@validateUtf8Encoding" \
        "setvar:'tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}'"
```

**Nhận xét:**
- Starter check `TX:` variable (config flag được set trong initialization) làm **gate condition**
- Child thực hiện việc detection thực sự
- Pattern này được dùng khi feature detection có thể gây FP trên nhiều site → để admin opt-in

---

## Pattern 8: Transformation trong Child Rule

**Use case:** Cần apply transformation khác nhau ở từng bước.

**Ví dụ thực tế (Rule 920360):** Argument name too long — check length bằng transformation

```apache
# Rule 920360 — Argument name too long
# Check if TX:ARG_NAME_LENGTH config exists, then measure actual arg name length
SecRule &TX:ARG_NAME_LENGTH "@eq 1" \
    "id:920360,\
    phase:2,\
    block,\
    t:none,\
    msg:'Argument name too long',\
    logdata:'%{MATCHED_VAR_NAME}=%{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-protocol',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/PROTOCOL-ENFORCEMENT',\
    tag:'capec/1000/210/272',\
    ver:'OWASP_CRS/4.25.0-dev',\
    severity:'CRITICAL',\
    chain"
    SecRule ARGS_NAMES "@gt %{tx.arg_name_length}" \
        "t:none,t:length,\
        setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

**Nhận xét:**
- Starter check `&TX:ARG_NAME_LENGTH "@eq 1"` = "config variable này có tồn tại không"
- Child dùng `t:length` — transformation biến value thành số byte của string, rồi so sánh với threshold
- `t:none,t:length` = clear inherited transforms rồi apply length measurement
- `@gt %{tx.arg_name_length}` = macro expansion, lấy giá trị từ TX collection

---

## Pattern 9: skipAfter + SecMarker (Either/Or Logic)

**Use case:** Nếu điều kiện A fire thì skip điều kiện B (mutual exclusive checks).

**Ví dụ thực tế (Rules 920280/920290):** Check missing Host header — nếu đã không có header thì skip kiểm tra empty

```apache
# Rule 920280 — Missing Host Header: không có header → score + skip empty check
SecRule &REQUEST_HEADERS:Host "@eq 0" \
    "id:920280,\
    phase:1,\
    block,\
    t:none,\
    msg:'Request Missing a Host Header',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-protocol',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/PROTOCOL-ENFORCEMENT',\
    tag:'capec/1000/210/272',\
    ver:'OWASP_CRS/4.25.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}',\
    skipAfter:END-HOST-CHECK"

# Rule 920290 — Empty Host Header: header tồn tại nhưng rỗng
SecRule REQUEST_HEADERS:Host "@rx ^$" \
    "id:920290,\
    phase:1,\
    block,\
    t:none,\
    msg:'Empty Host Header',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-protocol',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/PROTOCOL-ENFORCEMENT',\
    tag:'capec/1000/210/272',\
    ver:'OWASP_CRS/4.25.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

SecMarker "END-HOST-CHECK"
```

**Nhận xét:**
- `skipAfter` là action trong rule starter (không phải trong chain)
- Nếu Host header absent → rule 920280 match → skip đến `END-HOST-CHECK` marker → rule 920290 không chạy
- Nếu Host header present nhưng empty → rule 920280 không match → rule 920290 chạy
- `SecMarker` tạo jump target, không làm gì khác
- Pattern này tránh double-scoring khi 2 rules có thể match cùng 1 request

---

## Pattern 10: PL Skip Rules (Boilerplate)

Đầu và cuối mỗi PL block trong mọi file:

```apache
# Đầu file — PL skip rules (boilerplate, thêm cho mỗi phase)
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" \
    "id:920011,phase:1,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.25.0-dev',\
    skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT"
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" \
    "id:920012,phase:2,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.25.0-dev',\
    skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT"

# ... PL 1 rules (920100 - 920xxx) ...

SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" \
    "id:920013,phase:1,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.25.0-dev',\
    skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT"
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" \
    "id:920014,phase:2,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.25.0-dev',\
    skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT"

# ... PL 2 rules ...

# ... (tương tự cho PL 3: 920015/016, PL 4: 920017/018) ...

SecMarker "END-REQUEST-920-PROTOCOL-ENFORCEMENT"
```

**Nhận xét:**
- ID `9xx011`–`9xx018` là **reserved** cho PL skip rules (2 rules per PL per phase: phase:1 và phase:2)
- `pass,nolog` — không score, không log
- `skipAfter` nhảy đến marker ở cuối file
- Nếu `TX:DETECTION_PARANOIA_LEVEL` ≥ N thì skip rule không fire → các PL N rules vẫn chạy
- **Mọi file** đều phải có boilerplate này ở đầu/giữa/cuối tương ứng với từng PL block

---

## Tóm tắt — Chọn Pattern

| Tình huống | Pattern |
|-----------|---------|
| Cần 2 điều kiện AND | Simple chain (Pattern 1) |
| Kiểm tra header tồn tại/vắng | `&` count chain (Pattern 2) |
| 3+ điều kiện AND | Deep chain (Pattern 3) |
| Match rộng, loại trừ FP | Inverted `!@rx` chain (Pattern 4) |
| Verify thêm trên matched value | `MATCHED_VARS` chain (Pattern 5) |
| Extract và check subgroup | `capture` + `TX:N` chain (Pattern 6) |
| Feature opt-in/opt-out | Config gate chain (Pattern 7) |
| Đo length/size | `t:length` chain (Pattern 8) |
| Mutual exclusive conditions | `skipAfter` + `SecMarker` (Pattern 9) |
| PL gating cho toàn block | PL skip rules (Pattern 10) |
