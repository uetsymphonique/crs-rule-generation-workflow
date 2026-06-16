# Rule Authoring Standards — CRS

---

## Formatting Rules

- Indent: **4 spaces** (không dùng tab)
- Line length: **80 ký tự** tối đa (cố gắng tuân thủ)
- Action list phải dùng **double quotes**, kể cả khi chỉ có 1 action:
  ```apache
  SecRule ARGS "@rx foo" "id:1,phase:1,pass,t:none"   # ✓
  SecRule ARGS "@rx foo" id:1,phase:1,pass,t:none      # ✗
  ```
- Luôn khai báo tường minh operator `@rx` — không bỏ implicit:
  ```apache
  SecRule ARGS "@rx foo" "..."   # ✓
  SecRule ARGS "foo" "..."       # ✗
  ```
- Phase phải dùng số, không dùng tên: `phase:1` không phải `phase:REQUEST`
- File kết thúc bằng **một** newline, không có trailing blank lines
- Comment đặt **trước** rule, không được chen giữa chained rules
- `SecMarker` dùng double quotes, UPPERCASE, phân cách bằng hyphen:
  ```apache
  SecMarker "END-REQUEST-942-APPLICATION-ATTACK-SQLI"
  ```

---

## Action Order (Canonical)

> **Lưu ý:** ModSecurity engine không require thứ tự actions cụ thể — thứ tự dưới đây là **CRS convention** bắt buộc theo `contribution-guidelines`. Engine xử lý actions theo nhóm (disruptive, non-disruptive, flow, meta-data), không theo vị trí trong string.

Mọi rule trong CRS phải liệt kê actions theo thứ tự sau:

```
id
phase
allow | block | deny | drop | pass | proxy | redirect
status
capture
t:xxx
log
nolog
auditlog
noauditlog
msg
logdata
tag
sanitiseArg
sanitiseRequestHeader
sanitiseMatched
sanitiseMatchedBytes
ctl
ver
severity
multiMatch
initcol
setenv
setvar
expirevar
chain
skip
skipAfter
```

**Lưu ý quan trọng:** `setvar` luôn nằm sau `severity`, và `chain` luôn ở cuối. Đây là yêu cầu bắt buộc của CRS contribution guidelines, không chỉ là style.

---

## Variable Naming Convention

| Context | Format | Ví dụ |
|---------|--------|-------|
| Định nghĩa (`setvar`) | lowercase, dot separator | `setvar:tx.foo_bar_variable` |
| Sử dụng trong rule | UPPERCASE, colon separator | `SecRule TX:foo_bar_variable` |

- Tên variable: chỉ dùng `a-z`, `0-9`, và underscore
- Không dùng uppercase trong tên variable

---

## PL Constraints — Kiểu Rule Được Phép Ở Mỗi PL

### PL 1 — Default Level

- Phần lớn cài đặt production chạy ở level này
- Chỉ dùng **atomic checks** trong single rule (không có chain)
- Pattern phải cụ thể, unambiguous — confirmed matches only
- **Không được có false positive** — đây là hard requirement
- Tất cả score levels được phép (critical, error, warning, notice)

### PL 2

- **Chain được phép**
- Confirmed matches → dùng score `critical`
- Matches có thể gây FP → giới hạn score `notice` hoặc `warning`
- FP rate thấp

### PL 3

- Chain với complex regex và macro expansions được phép
- Confirmed matches → score `warning` hoặc `critical`
- Matches có thể gây FP → giới hạn score `notice`
- FP rate cao hơn nhưng chỉ khi có nhiều matches (không phải single string)

### PL 4

- Kiểm tra mọi thứ
- Variable creation được phép để bypass engine limitations
- Confirmed matches → `notice`, `warning`, hoặc `critical`
- FP rate cao hơn (kể cả single string)
- False negative không được xảy ra ở level này
- Validate mọi thứ theo RFC và allowlist

> **Nguyên tắc chọn PL cho rule mới:** Nếu pattern cụ thể và unambiguous → PL 1. Nếu cần chain → tối thiểu PL 2. Nếu dùng lookaround hoặc macro → tối thiểu PL 3.

---

## ID Numbering Scheme

### Phân vùng

| Loại rule | ID range |
|-----------|---------|
| Request rules | 900,000 – 949,999 |
| Response rules | 950,000 – 999,999 |
| Rule exclusion packages / plugins | 9,000,000 – 9,999,999 |

### Cấu trúc trong file

- Mỗi file/vulnerability class chiếm **1 block 1000 IDs** (ví dụ: SQLi → 942,000–942,999)
- File ID = 3 chữ số đầu (ví dụ: file `REQUEST-942-...` → ID prefix `942`)
- Block `9xx000–9xx099`: reserved cho CRS helper/control flow, không có blocking rules
- Helper rules (PL skip rules): reserved IDs `9xx011–9xx018`
- Detection/blocking rules: bắt đầu từ `9xx100`, step **10** (→ 9xx100, 9xx110, 9xx120...)
- Các rule được sắp xếp theo PL tăng dần trong file (PL 1 trước, PL 4 sau)

### Stricter Siblings

Một số rules có **stricter siblings** — bản copy với threshold chặt hơn hoặc target khác nhau:
- Base rule và sibling **chia sẻ 5 chữ số đầu** của ID
- Sibling ID = base ID + 1 (ví dụ: base `942160` → sibling `942161`)
- Sibling thường ở **PL khác** với base rule → không nằm cạnh nhau trong file
- Comment của base rule nên liệt kê tất cả siblings; comment của sibling nên reference về base

```apache
# Base rule: 942160 (PL1)
# Stricter siblings: 942161 (PL2), 942162 (PL3)
SecRule ... "id:942160,..."

# --- PL2 rules bắt đầu ---

# This is a stricter sibling of rule 942160
SecRule ... "id:942161,..."
```

---

## Rule Writing Workflow (8 Bước)

1. **Hiểu attack** — nghiên cứu technique, thu thập real-world payload examples
2. **Test payload behavior** — dùng database playground, test variations (spacing, comments, case, encoding)
3. **Develop detection pattern** — draft regex, test trên regex101.com, check cả malicious và legitimate traffic
4. **Consider evasion** — test encoded versions, obfuscation techniques
5. **Quyết định placement** — rule mới hay extend rule cũ? **Ưu tiên extend rule có sẵn**
6. **Tạo hoặc update rule** — nếu extend, update `.ra` assembly file; chạy `crs-toolchain regex update`
7. **Test** — viết go-ftw tests (positive + negative), chạy full test suite
8. **Document và submit** — giải thích attack technique và lý do chọn pattern trong PR

