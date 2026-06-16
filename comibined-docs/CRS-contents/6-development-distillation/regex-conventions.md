# Regex Conventions trong CRS

---

## Ký tự đặc biệt — Cách biểu diễn

### Backslash (`\`)

CRS dùng `\x5c` để biểu diễn backslash — **không** dùng `[\\\\]`:

```
\x5c          # ✓ — portable, hoạt động với Apache, Nginx, Coraza, crs-toolchain
[\\\\]        # ✗ — deprecated, không hoạt động với Coraza và crs-toolchain
```

Lý do `[\\\\]` bị loại bỏ: Apache double-unescapes character escapes, nên cần 4 backslash để ra 1 literal backslash. Cách này không portable và không rõ ràng.

### Forward Slash (`/`)

CRS dùng **unescaped** forward slash trong regex — không escape thành `\/`:

```
/admin/content   # ✓
\/admin\/content  # ✗
```

Lý do: PCRE dùng `/` làm delimiter trong một số contexts, nhưng CRS dùng unescaped để dễ đọc. Nếu test trên third-party tool mà gặp lỗi vì unescaped `/`, thay delimiter của tool thành ký tự khác.

### PCRE_DOTALL — Mặc Định Trong ModSecurity

ModSecurity compile regex với flag **PCRE_DOTALL** — nghĩa là `.` match **mọi ký tự kể cả newline**. Khác với default PCRE behavior (`.` không match `\n`).

Hệ quả thực tế:
- `[\s\S]` và `.` có cùng behavior trong ModSecurity context (cả hai match newline)
- Pattern viết cho tool ngoài (regex101 với PCRE non-dotall) có thể behave khác trong engine
- Cũng compile với **PCRE_DOLLAR_ENDONLY**: `$` anchor sẽ không match trailing newline

### Vertical Tab

Dùng `\x0b` thay vì `\v`:

```
[\s\x0b]   # ✓
[\s\v]     # ✗
```

Lý do: RE2 không bao gồm `\v` trong `\s`, nhưng PCRE thì có. `\v` trong PCRE expand thành danh sách ký tự và không thể dùng trong range expressions. `\x0b` là literal vertical tab, portable giữa PCRE và RE2.

---

## Anchoring — Khi Nào Dùng `^` và `$`

> **Mặc định: KHÔNG anchor.** CRS regex search trong input, không match toàn bộ. Chỉ anchor khi có lý do cụ thể.

### Dùng `^` khi cần match từ đầu string

```apache
# Đảm bảo Content-Type phải bắt đầu với "multipart/form-data"
"@rx (?i)^multipart/form-data"
```

Không anchor → `multipart/form-data` trong middle của header value vẫn match → có thể FP hoặc FN tùy context.

### Dùng `$` khi cần tránh FP do suffix

```apache
# Match /admin/content/assets/add/<filename> nhưng không match subdirectory
"@rx /admin/content/assets/add/[a-z]+$"

# Không anchor: /admin/content/assets/add/evilbutactuallynot/nonevilfile cũng match
"@rx /admin/content/assets/add/evil"   # ✗ dễ FP
```

### Dùng cả `^...$` khi cần exact match

```apache
# Chỉ match chính xác "edit" hoặc "editpost", không match "myedit" hay "editable"
"@rx ^(?:edit|editpost)$"
```

### Không dùng anchors khác

`\A`, `\G`, `\Z` — **CẤMD** trong CRS:
- Không phải mọi engine đều hỗ trợ
- Thường có cách viết lại không cần chúng

---

## Non-Capturing Groups — Bắt Buộc Dùng `(?:...)`

Khi cần grouping/precedence mà không cần capture, **phải dùng non-capturing group**:

```apache
"@rx a|(?:b|c)d"      # ✓ non-capturing
"@rx a|(b|c)d"         # ✗ capturing — tốn CPU và memory không cần thiết
```

**Capturing group chỉ dùng khi thực sự cần lưu matched value** (ví dụ: dùng `capture` action để lưu vào `TX:N`).

---

## Lazy Matching — Cẩn Thận Với `*?` và `+?`

Lazy quantifiers (`.*?`, `.+?`) đổi greedy thành "match ít nhất có thể". Chúng **không** loại bỏ backtracking trong PCRE.

### Khi lazy tốt hơn greedy

```apache
# Cookie session fixation detection
"@rx (?i)\.cookie\b.*?;\W*?(?:expires|domain)\W*?="
```

Input: `document.cookie = "name=evil; domain=https://example.com"`

- Greedy `.*`: match đến cuối string rồi backtrack từng ký tự → nhiều steps
- Lazy `.*?`: expand từng ký tự cho đến khi tìm thấy `;` → ít steps hơn

### Khi lazy tệ hơn greedy

```apache
# Attribute matching
"@rx (?i)\b(?:s(?:tyle|rc)|href)\b[\s\S]*?="
```

Input: `style                     =` (nhiều spaces)

- Lazy `[\s\S]*?`: expand từng space một → 21 steps
- Greedy `[\s\S]*`: match đến cuối, backtrack 1 bước, tìm `=` → 3 steps

> **Nguyên tắc:** Chỉ dùng lazy khi có lý do cụ thể và đã test performance. Không thêm `?` vào quantifiers một cách tùy tiện.

---

## RE2 Compatibility — Danh Sách CẤMD

> **Quan trọng:** ModSecurity sử dụng **PCRE** (Perl Compatible Regular Expressions) — engine hỗ trợ đầy đủ lookahead, lookbehind, backreferences, v.v. Danh sách cấm dưới đây là **CRS policy** (từ `6-1-contribution-guidelines`), không phải engine limitation. Mục tiêu: đảm bảo rules có thể chạy trên cả các WAF engine không dùng PCRE (ví dụ Coraza/RE2), và tránh ReDoS trên backtracking engines.

CRS cố gắng tương thích với non-backtracking engines (RE2) để tránh ReDoS. Các constructs sau **không được phép**:

| Construct | Ví dụ | Lý do cấm |
|-----------|-------|-----------|
| Positive lookahead | `(?=regex)` | Không có trong RE2 |
| Negative lookahead | `(?!regex)` | Không có trong RE2 |
| Positive lookbehind | `(?<=regex)` | Không có trong RE2 |
| Negative lookbehind | `(?<!regex)` | Không có trong RE2 |
| Named capture group | `(?P<name>regex)` | Không có trong RE2 |
| Backreference | `\1` | Không có trong RE2 |
| Named backreference | `(?P=name)` | Không có trong RE2 |
| Conditional | `(?(regex)then\|else)` | Không có trong RE2 |
| Recursive group call | `(?1)` | Không có trong RE2 |
| Possessive quantifier | `(?:regex)++` | Không có trong RE2 |
| Atomic group | `(?>regex)` | Không có trong RE2 |

Nếu cần functionality của lookahead/lookbehind, hầu hết trường hợp có thể viết lại dùng chain rules thay thế.

---

## `.ra` File Format — Regex Assembly

CRS không viết raw regex trực tiếp cho complex rules mà dùng `.ra` assembly files trong `regex-assembly/`. Files này được process bởi `crs-toolchain` để tạo ra optimized regex.

### Cú pháp cơ bản

```
##! comment — bị skip khi process
##! dùng để giải thích từng entry

##!+ i          # flag: ignore case
##!+ s          # flag: dot matches newline

##!^ \b         # prefix — prepend vào expression
##!$ \W*\(      # suffix — append vào expression

# Các dòng còn lại là alternations của regex:
select
union
where
from
```

File trên tạo ra: `(?i)\b(?:from|select|union|where)[^0-9A-Z_a-z]*\(`

### Processors

#### `cmdline` — command line evasion

```
##!> cmdline unix
  wget@
  curl@
  python~
##!<
```

- `@` — word ending, cho phép whitespace/operators theo sau
- `~` — word ending, KHÔNG cho phép whitespace ngay sau (dùng cho ambiguous words)
- Mỗi dòng được escape để handle shell evasion patterns

#### `assemble` — combine alternations

```
##!> assemble
  line1
  ##!=>
    ##!> assemble
      ab
      cd
    ##!<
##!<
```

Tạo ra: `line1(?:ab|cd)`

Dùng `##!=< identifier` để store block, `##!=> identifier` để reuse:

```
##!> assemble
  \x5c
  %2f
  %5c
  ##!=< slashes          # store vào "slashes"
  ##!=> slashes          # output "slashes"

  \.
  \.%00
  ##!=>
  ##!=> slashes          # reuse "slashes" ở cuối
##!<
```

#### `define` — macro substitution

```
##!> define slashes [/\x5c]
regex with {{slashes}}
```

Tạo ra: `regex with [/\x5c]`

#### `include` — reuse across files

```
##!> include http-methods   # include file include/http-methods.ra
OPTIONS                      # thêm vào danh sách
```

#### `include-except` — include với exclusion cho FP control

```
##!> include-except command-list pl1-exclude-list
```

Hữu ích cho PL: list đầy đủ ở PL 3/4, loại trừ high-FP words ở PL 1/2.

### Workflow `.ra`

```bash
# 1. Edit file assembly
# 2. Check format
crs-toolchain regex format 942170

# 3. Preview kết quả
crs-toolchain regex compare 942170

# 4. Cập nhật rule file
crs-toolchain regex update 942170
```

> **Không tự optimize regex.** `crs-toolchain` tự optimize alternations. Việc của contributor là viết rõ ràng, dễ đọc — để tool lo phần optimize.

