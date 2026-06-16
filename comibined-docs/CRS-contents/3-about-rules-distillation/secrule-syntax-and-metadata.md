# SecRule: Cú pháp, Metadata và Rule ID

---

## Cấu trúc cơ bản

```apache
SecRule VARIABLES "OPERATOR" "TRANSFORMATIONS,ACTIONS"
```

4 thành phần của một SecRule:
- **VARIABLES** — *where* to look: chỉ định ModSecurity kiểm tra ở đâu
- **OPERATOR** — *when* to match: điều kiện trigger
- **TRANSFORMATIONS** — *how* to normalize: chuẩn hóa dữ liệu trước khi match
- **ACTIONS** — *what* to do: hành động khi rule match

### 6 ràng buộc bắt buộc

1. Phải có VARIABLE
2. Phải có OPERATOR — nếu không khai báo, mặc định là `@rx`
3. Phải có ACTION — action bắt buộc duy nhất là `id`; các action khác kế thừa từ `SecDefaultAction`
4. Phải có `phase` — mặc định là `phase:2` nếu không khai báo
5. Phải có disruptive action — mặc định là `pass` nếu không khai báo
6. Transformations là optional nhưng **nên dùng** để chống bypass

> **Lưu ý quan trọng cho CRS:** Các ví dụ trong phần này dùng `deny` để minh họa cú pháp. Trong CRS thực tế, detection rule KHÔNG dùng `deny` mà dùng `block` + `setvar` theo anomaly scoring pattern (xem `2-how-crs-works-distillation/`).

---

## Variable: Cách truy cập

### Collection iteration
Khi VARIABLE là collection (ví dụ `ARGS`, `REQUEST_COOKIES`), ModSecurity iterate qua từng value:
```apache
SecRule ARGS_GET "@contains test" "id:1,phase:1,t:lowercase,deny"
```

### Index access (`:`)
Truy cập một key cụ thể trong collection:
```apache
SecRule ARGS_GET:username "@contains admin" "id:1,phase:1,t:lowercase,deny"
```

### Kết hợp nhiều variable (`|`)
```apache
SecRule ARGS_GET|ARGS_POST|REQUEST_COOKIES "@rx hello\s\d{1,3}" "id:1,phase:2,t:lowercase,deny"
```

### Loại trừ index (`!`)
```apache
SecRule ARGS|!ARGS:password "@rx (admin|administrator)" "id:1,phase:2,t:lowercase,deny"
```

### Đếm số phần tử trong collection (`&`)
Prefix `&` trả về số lượng biến trong collection thay vì iterate qua values:
```apache
# trigger nếu không có Host header
SecRule &REQUEST_HEADERS:Host "@eq 0" "id:10,phase:1,deny,msg:'Missing Host Header'"

# trigger nếu request có hơn 100 arguments
SecRule &ARGS "@gt 100" "id:11,phase:2,deny,msg:'Too many arguments'"
```

---

## Transformation: Tại sao cần nhiều lớp

> **`t:none` best practice:** Luôn bắt đầu danh sách transformation bằng `t:none` để clear các transform có thể được kế thừa từ `SecDefaultAction`. Không làm vậy, rule có thể áp dụng transform không mong muốn. Đây là khuyến nghị chính thức trong Reference Manual.

Mỗi lớp transform chặn một vector bypass. Ví dụ với XSS detection:

```apache
# Bị bypass bằng uppercase: ?x=<sCript>
SecRule ARGS "@contains <script>" "id:1,deny,status:403"

# Bị bypass bằng whitespace: ?x=<sCript >
SecRule ARGS "@contains <script>" "id:1,deny,status:403,t:lowercase"

# Bị bypass bằng HTML entity: ?x=&lt;sCript >
SecRule ARGS "@contains <script>" "id:1,deny,status:403,t:lowercase,t:removeWhitespace"

# Robust hơn:
SecRule ARGS "@contains <script>" "id:1,deny,status:403,t:lowercase,t:removeWhitespace,t:htmlEntityDecode"
```

**Nguyên tắc:** Mỗi transform phải có lý do cụ thể (loại bỏ encoding, chuẩn hóa case, v.v.). Không add transform tùy tiện.

---

## Operator: Regex best practices

- Tránh dùng `^` và `$` — kẻ tấn công có thể thêm ký tự trước/sau để bypass
- Pattern phải case-insensitive — dùng `t:lowercase` kết hợp
- Tránh dùng `.` (match mọi ký tự trừ newline) ở những chỗ không cần thiết — có thể bypass bằng newline injection
- Giới hạn `{}` repetition cẩn thận — quá chặt hoặc quá lỏng đều tạo bypass
- Dùng `+` (one or more) chỉ khi thực sự cần; `*` (zero or more) thường an toàn hơn
- Dùng `t:urlDecodeUni` thay vì `t:urlDecode`
- Áp dụng đúng scope: check cả cookie names/values, argument names/values, header names/values
- Whitespace không chỉ là `%20` — newline (`%0d`, `%0a`) cũng là whitespace trong nhiều context

---

## Metadata Tags

### Paranoia level tag

Rule ở PL > 1 **bắt buộc** có tag:
```apache
tag:'paranoia-level/2'   # hoặc /3, /4
```
Rule PL 1 không cần tag này.

### CRS 3.x tag taxonomy

Mỗi rule thường có đủ 4 loại tag phân loại:

| Category | Format | Ví dụ phổ biến |
|---|---|---|
| application | `application-<name>` | `application-multi`, `application-wordpress` |
| language | `language-<name>` | `language-multi`, `language-php`, `language-java` |
| platform | `platform-<name>` | `platform-multi`, `platform-unix`, `platform-windows` |
| attack | `attack-<type>` | `attack-sqli`, `attack-xss`, `attack-rce`, `attack-lfi`, `attack-rfi`, `attack-injection-php`, `attack-protocol` |

Dùng `multi` khi rule áp dụng cho nhiều platform/language/application.

### Tags bắt buộc trong mọi CRS rule

```apache
tag:'OWASP_CRS'                    # marker nhận diện rule thuộc CRS
tag:'capec/1000/...'               # CAPEC classification (lấy từ CAPEC database)
ver:'OWASP_CRS/4.x.x-dev'         # version string
```

### Legacy CRS 2.x tags (vẫn còn trong rules thực tế)

```apache
tag:'OWASP_CRS/WEB_ATTACK/XSS'
tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION'
tag:'OWASP_CRS/WEB_ATTACK/COMMAND_INJECTION'
tag:'OWASP_CRS/WEB_ATTACK/DIR_TRAVERSAL'
tag:'OWASP_CRS/WEB_ATTACK/RFI'
tag:'OWASP_CRS/WEB_ATTACK/PHP_INJECTION'
tag:'OWASP_CRS/WEB_ATTACK/SESSION_FIXATION'
tag:'OWASP_CRS/AUTOMATION/SECURITY_SCANNER'
tag:'OWASP_CRS/LEAKAGE/SOURCE_CODE_PHP'
tag:'OWASP_CRS/LEAKAGE/ERRORS_SQL'
tag:'OWASP_CRS/PROTOCOL_VIOLATION/INVALID_REQ'
```

---

## Rule ID trong CRS

### CRS ID range: **900,000 – 999,999**

### Cấu trúc ID trong một file

- Mỗi rule file được cấp **1000 IDs**
- Các rule cách nhau **10 IDs** (ví dụ: 920100, 920110, 920120...)
- IDs `000–090` (bội của 10) dành riêng cho control flow rules (skip, pass)
- Rule detection đầu tiên trong file thường bắt đầu ở `9[FileID]100`

**Ví dụ:** File `REQUEST-920-PROTOCOL-ENFORCEMENT.conf` có file ID `920` → detection rules bắt đầu từ `920100`, rule mới nhất thêm vào cuối.

### Khi thêm rule mới

- Thêm vào cuối file, ID = ID rule cuối + 10
- Nếu phải chèn giữa hai rule có ID liền kề → ghi comment giải thích
