# Testing CRS Rules

---

## Test Infrastructure

CRS dùng **go-ftw** (Go Framework for Testing WAFs) để chạy regression tests.

```
tests/
└── regression/
    └── tests/
        ├── REQUEST-911-METHOD-ENFORCEMENT/
        │   ├── 911100.yaml      # tests cho rule 911100
        │   └── 911110.yaml      # tests cho rule 911110
        ├── REQUEST-942-APPLICATION-ATTACK-SQLI/
        │   ├── 942100.yaml
        │   └── ...
        └── ...
```

**Quy tắc:** Mỗi **file** (vulnerability class) → 1 thư mục. Mỗi **rule ID** → 1 YAML file chứa tất cả tests cho rule đó.

---

## YAML Test Format

### Positive Test — rule phải match

```yaml
- test_id: 1
  desc: "Unix command injection via backtick"
  stages:
    - input:
        dest_addr: "127.0.0.1"
        port: 80
        method: POST
        uri: "/"
        headers:
          Host: localhost
          User-Agent: "OWASP CRS test agent"
          Accept: "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"
        data: "var=` /bin/cat /etc/passwd`"
        version: HTTP/1.1
      output:
        log:
          expect_ids: [932230]
```

Test pass khi log **có** entry cho rule 932230.

### Negative Test — rule không được match (check FP)

```yaml
- test_id: 4
  stages:
    - input:
        dest_addr: "127.0.0.1"
        method: POST
        port: 80
        headers:
          User-Agent: "OWASP CRS test agent"
          Host: "localhost"
          Accept: "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"
        data: "foo=ping pong tables"
        uri: "/"
      output:
        log:
          no_expect_ids: [932260]
```

Test pass khi log **không có** entry cho rule 932260.

### Encoded Request — cho binary/malformed payloads

Khi payload chứa bytes không thể biểu diễn bằng YAML text hoặc request cần intentionally malformed:

```yaml
- test_id: 5
  desc: "Malformed HTTP request"
  stages:
    - input:
        encoded_request: "R0VUIFwgSFRUUA0KDQoK"
      output:
        log:
          expect_ids: [920260]
```

`encoded_request` là **toàn bộ raw HTTP request** được encode base64. Khi dùng field này, không khai báo `headers`, `method`, `data` riêng lẻ.

---

## Best Practices Viết Tests

### Luôn include 3 headers bắt buộc

```yaml
headers:
  Host: localhost
  User-Agent: "OWASP CRS test agent"
  Accept: "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"
```

CRS có rules detect missing/empty headers. Thiếu 3 headers này → các rules đó match → test nhiễu, không isolated.

### Mỗi positive test chỉ trigger đúng 1 rule

Nếu payload trigger thêm rules khác ngoài rule cần test → refine payload để isolate.

### `desc` field phải mô tả rõ

```yaml
desc: |
  Testing Unix command injection via backtick substitution.
  Payload: var=` /bin/cat /etc/passwd`
  Expected: rule 932230 fires (unix RCE detection)
```

Dùng YAML literal scalar (`|`) cho multi-line descriptions.

### Viết đủ cả positive và negative tests

- **Positive**: payload rõ ràng là attack, rule phải match
- **Negative**: traffic hợp lệ trông giống attack pattern, rule không được match

---

## Chạy Tests với go-ftw

### Setup Docker (cách khuyến nghị)

```bash
docker compose -f tests/docker-compose.yml up -d modsec2-apache
```

### Chạy toàn bộ test suite

```bash
# Apache
go-ftw run --config .ftw.apache.yaml -d tests/regression/tests/

# Nginx
go-ftw run --config .ftw.nginx.yaml -d tests/regression/tests/
```

### Chạy tests cho 1 rule cụ thể

```bash
go-ftw run --config .ftw.apache.yaml -d tests/regression/tests/ -i "932230"
```

`-i` nhận regex — match theo test ID pattern.

### Debug khi test fail

```bash
# Xem requests/responses đầy đủ
go-ftw run ... -i "932230-1$" --trace

# Xem audit log
tail -200 tests/logs/modsec2-apache/modsec_audit.log
```

### Config file go-ftw

```yaml
# .ftw.apache.yaml
logfile: /var/log/apache2/error.log
logmarkerheadername: X-CRS-TEST
testoverride:
  input:
    dest_addr: "127.0.0.1"
    port: 80
```

---

## Sau Khi Thêm/Xóa Tests

Renumber để test IDs liên tục:

```bash
crs-toolchain util renumber-tests
```

---

## Ghi Chú Compatibility

- Platform chính thức được test: **ModSecurity 2 + Apache httpd**
- `libmodsecurity3` (dùng cho nginx) **không hoàn toàn compatible** với ModSecurity 2 — một số tests có thể fail trên nginx
- Nếu cần ignore known incompatibilities, thêm vào config:
  ```yaml
  testoverride:
    ignore:
      '941190-3$': 'known MSC bug - PR #2023 (Cookie without value)'
  ```

