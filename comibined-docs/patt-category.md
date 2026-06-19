# PayloadsAllTheThings — Category Index (prose `.md`, no raw payloads)

Mục đích: index tra cứu cho `crs-variant-gen` (##CRAFT-PLAYBOOK). Map `classification.families` token (đồng bộ `crs-retrieve-analyze` ##CLASS-TAG/##CATALOG) → folder `PayloadsAllTheThings/<Class>/` → các anchor section trong `README.md` (+ sibling `.md` khi cần engine/bypass cụ thể).

Phạm vi: **mọi file `.md`** của class — `README.md` (methodology tổng) + sibling `.md` (engine-specific `MySQL.md`/`Python.md`/`Java.md`…, hoặc topic như `XSS Filter Bypass.md`, `Wrappers.md`, `LFI-to-RCE.md`). Đây là nguồn *methodology / technique enumeration* dạng prose. Trade-off có chủ đích — **chỉ loại payload thô**: KHÔNG đọc `Files/`, `Intruder/`, `*.txt` (tới hàng chục KB, gắn slot mặc định của tác giả nên dù sao cũng phải re-home) và `Images/`. Lấy *technique* để tự dựng payload, không bê chuỗi sẵn.

Đường dẫn gốc: `PayloadsAllTheThings/` (submodule read-only, KHÔNG edit).

---

## Access-discipline

1. **Chỉ file `.md`**: `<Class>/README.md` + sibling `.md` (cột "sibling" dưới). KHÔNG đọc `Files/`, `Intruder/`, `Images/`, `*.txt`. Mặc định bắt đầu từ `README.md`; chỉ mở sibling `.md` khi cần engine-specific (SQL/SSTI theo backend) hoặc bypass-doc riêng (XSS).
2. **Đọc theo size** (áp cho mọi `.md`):
   - `.md` nhỏ (≤~250 dòng) → Read whole.
   - `.md` lớn (≥~400 dòng: XXE 688, XSS README 609, SQL README 596, `MySQL Injection.md` 775, `XSS Filter Bypass.md` 578, `SSTI/Java.md` 525, …) → Grep `^#{2,3} ` lấy TOC trước, rồi Read **đúng 1–2 section** liên quan + section bypass. KHÔNG Read whole.
3. **Cap**: ≤2–3 technique-section mỗi lần craft, tổng ≤2 file `.md`. Methodology-section → trục "đổi construct"; bypass-section → trục encoding-layer.
4. **Không bê payload verbatim**: prose cho *technique*, không phải chuỗi để copy. Tự dựng payload, re-home vào `injection_slot` thật, giữ class-valid.

---

## Map: families → folder → anchor

Cột "bypass anchor" (nếu có) = nguồn gadget encoding-layer / WAF-bypass. Tên header khác nhau giữa class — dùng đúng chuỗi ở cột này khi Grep.

| families token | PaTT folder | Methodology anchor (`## `) | Bypass / encoding anchor | size (dòng) | CRS file |
|---|---|---|---|---|---|
| `sqli` | `SQL Injection/` | `Authentication Bypass`, `UNION Based Injection`, `Blind Injection`, `Stacked Based Injection`, `Polyglot Injection`, `Second Order SQL Injection` | `Generic WAF Bypass` | 596 | 942 |
| `xss` | `XSS Injection/` | `XSS in HTML/Applications`, `XSS in Wrappers for URI`, `XSS in PostMessage`, `Mutated XSS` | sibling: `3 - XSS Common WAF Bypass.md`, `1 - XSS Filter Bypass.md`, `4 - CSP Bypass.md` (xem mục Sibling) | 609 | 941 |
| `rce` / `cmdi` | `Command Injection/` | `Methodology`, `Polyglot Command Injection`, `Tricks` | `Filter Bypasses` | 476 | 932 |
| `injection-php` (php) | `Command Injection/` + `File Inclusion/` | `Methodology`; FI: `Local File Inclusion`, `Remote File Inclusion` | Command: `Filter Bypasses` | 476 / 145 | 933 |
| `injection-generic` (ssti / code-inj) | `Server Side Template Injection/` | `Methodology` | sibling engine: `Python.md`, `Java.md`, `PHP.md`, `Ruby.md`, `JavaScript.md`, `ASP.md`, `Elixir.md` (xem mục Sibling) | 228 | 934 |
| `injection-generic` (ssrf) | `Server Side Request Forgery/` | `Methodology`, `Exploitation via URL Scheme`, `Blind Exploitation` | `Bypassing Filters` | 464 | 934 |
| `injection-java` (deser / ognl / spel) | `Insecure Deserialization/` (+ `Java RMI/`, `CVE Exploits/Log4Shell.md`) | `Deserialization Identifier`, `POP Gadgets` | — | 60 | 944 |
| `lfi` / traversal | `Directory Traversal/` + `File Inclusion/` | DT: `Methodology`, `Exploit`, `Path Traversal`; FI: `Local File Inclusion` | (encoding traversal trong `Path Traversal`) | 355 / 145 | 930 |
| `rfi` | `File Inclusion/` | `Remote File Inclusion` | — | 145 | 931 |
| `protocol` (crlf) | `CRLF Injection/` | `Methodology` (`Session Fixation`, `Cross Site Scripting`, `Open Redirect`) | `Filter Bypass` | 152 | 921 / 920 |
| `protocol` (smuggling) | `Request Smuggling/` | `Methodology`, `HTTP/2 Request Smuggling`, `Client-Side Desync` | — | 181 | 921 |
| `protocol` (hpp) | `HTTP Parameter Pollution/` | `Methodology` | — | 100 | 921 |
| `fixation` | `CRLF Injection/` | `Methodology` → `### Session Fixation` | `Filter Bypass` | 152 | 943 |
| `multipart` / upload | `Upload Insecure Files/` | `Methodology` | — | 384 | 922 |
| (xxe) | `XXE Injection/` | `Detect The Vulnerability`, `Exploiting XXE to Retrieve Files`, `Exploiting XXE to Perform SSRF Attacks`, `Exploiting Blind XXE...` | `WAF Bypasses` | 688 | 934 |
| (nosqli) | `NoSQL Injection/` | `Methodology`, `Blind NoSQL` | — | 247 | 942 / 934 |
| (ldap) | `LDAP Injection/` | `Methodology`, `Exploiting userPassword Attribute` | — | 174 | 921 / 934 |
| (xpath) | `XPATH Injection/` | `Methodology` | — | 79 | 934 |
| (ssi / esi) | `Server Side Include Injection/` | `Methodology`, `Edge Side Inclusion` | — | 68 | 934 |
| (xslt) | `XSLT Injection/` | `Methodology` | — | 246 | 934 |
| (proto-pollution) | `Prototype Pollution/` | `Methodology` | — | 170 | 934 |
| (open-redirect) | `Open Redirect/` | `Methodology`, `Redirect Methods` | `Filter Bypass` | 178 | 921 / 942 |
| (jwt) | `JSON Web Token/` | `JWT Signature`, `JWT Secret`, `JWT Claims` | — | 523 | — (app-layer) |

### Encoding-layer (cross-class)

| Nguồn | Anchor | Dùng khi |
|---|---|---|
| `Encoding Transformations/README.md` | `Unicode` (normalization → `‥`→`../`, fullwidth), `Base64` | payload bị bọc transport-encoding (base64/hex/nested-url/JWT) hoặc cần đổi biểu diễn ký tự |
| `## Filter Bypass` / `## WAF Bypasses` / `## Generic WAF Bypass` / `## Bypassing Filters` của từng class | (xem cột bypass trên) | tìm gadget né regex *cùng class* |

Lưu ý CRS-normalization: đổi encoding **bề mặt** (url-encode/case) bị `t:urlDecodeUni,t:lowercase` normalize về cũ → không thoát. Biến đổi encoding-**layer** chỉ là trục breadth thật **khi không CRS rule nào decode lớp đó** (the gap). Nguồn gadget cho lớp đó = bảng trên.

### Sibling `.md` đáng dùng (mở khi cần engine/bypass cụ thể, KHÔNG mặc định)

Bắt đầu từ README; chỉ mở sibling khi template chỉ rõ engine/backend hoặc cần bypass-doc riêng. `.md` lớn (≥~400) → Grep anchor + Read offset/limit.

| Class | Sibling `.md` (size dòng) |
|---|---|
| SQL Injection | `MySQL Injection.md` (775), `MSSQL Injection.md` (443), `PostgreSQL Injection.md`, `OracleSQL Injection.md`, `SQLite Injection.md`, `DB2`/`Cassandra`/`BigQuery Injection.md` |
| XSS Injection | `1 - XSS Filter Bypass.md` (578), `3 - XSS Common WAF Bypass.md` (120), `4 - CSP Bypass.md` (179), `2 - XSS Polyglot.md`, `5 - XSS in Angular.md` |
| SSTI | `Python.md` (466), `Java.md` (525), `PHP.md`, `Ruby.md`, `JavaScript.md`, `ASP.md`, `Elixir.md` |
| Insecure Deserialization | `Java.md` (315), `PHP.md` (261), `Python.md`, `Node.md`, `DotNET.md`, `Ruby.md` |
| File Inclusion | `Wrappers.md` (275), `LFI-to-RCE.md` (303) |
| SSRF | `SSRF-Advanced-Exploitation.md` (168), `SSRF-Cloud-Instances.md` |

---

## Out-of-scope (KHÔNG map — không phải payload-in-request cho WAF SecRule)

Logic / operational / client-side / recon: `Account Takeover`, `Brute Force Rate Limit`, `Business Logic Errors`, `Clickjacking`, `Client Side Path Traversal`, `CORS Misconfiguration`, `Cross-Site Request Forgery`, `CSS Injection`, `CSV Injection`, `Denial of Service`, `Dependency Confusion`, `DNS Rebinding`, `DOM Clobbering`, `External Variable Modification`, `Google Web Toolkit`, `GraphQL Injection`, `Headless Browser`, `Hidden Parameters`, `Insecure Direct Object References`, `Insecure Management Interface`, `Insecure Randomness`, `Insecure Source Code Management`, `Mass Assignment`, `OAuth Misconfiguration`, `ORM Leak`, `Prompt Injection`, `Race Condition`, `Regular Expression`, `Reverse Proxy Misconfigurations`, `SAML Injection`, `Tabnabbing`, `Type Juggling`, `Virtual Hosts`, `Web Cache Deception`, `Web Sockets`, `XS-Leak`, `Zip Slip`.

Meta: `_template_vuln/`, `_LEARNING_AND_SOCIALS/`, `CVE Exploits/`, `Methodology and Resources/`, `API Key Leaks/`.

(Một số có thể liên quan gián tiếp — vd `GraphQL Injection`, `Web Cache Deception` — nhưng không thuộc class CRS lõi nên không đưa vào map mặc định; thêm khi có template thực tế.)
