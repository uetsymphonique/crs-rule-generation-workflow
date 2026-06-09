Lesson Learned: Viết Skills Hiệu Quả cho AI Agents

Rút ra từ phân tích Superpowers — một trong số ít plugin có tỉ lệ PR chấp nhận cao trong cộng đồng Claude.

---
Nguyên tắc nền tảng

Skill là code định hình hành vi, không phải prose hướng dẫn.

Agent không "đọc hiểu" skill như con người đọc tài liệu. Agent xử lý skill như một constraint system. Mỗi câu bạn viết cần được kiểm tra: "Nếu agent muốn bỏ qua điều này, nó có thể không?" Nếu có thể, bạn chưa viết đủ cứng.

---
Lesson 1: Dùng Hard Gate thay vì lời khuyên

Sai:

▎ Bạn nên hiểu yêu cầu trước khi viết code.

Đúng:
<HARD-GATE>
Do NOT write any code until you have presented a design and received explicit approval.
This applies to ALL tasks regardless of perceived simplicity.
</HARD-GATE>

Tại sao: Agent luôn có xu hướng tối ưu hóa về phía "làm ngay". Lời khuyên mềm tạo ra chỗ để agent lý luận rằng "trường hợp này đủ đơn giản để bỏ qua". Hard gate không có chỗ đó.

Khi nào dùng: Mọi bước mà nếu bị bỏ qua sẽ làm hỏng toàn bộ quy trình.

---
Lesson 2: Đặt tên và phủ nhận rationalization trước

Agent có một tập rationalization cố định để bỏ qua process. Liệt kê chúng ra và phản bác ngay trong skill.

Mẫu:
## Anti-Pattern: "[Tên rationalization phổ biến nhất]"

[Giải thích tại sao rationalization này sai, cụ thể và không nhượng bộ.]

Ví dụ thực tế từ Superpowers:
## Anti-Pattern: "This Is Too Simple To Need A Design"
Simple projects are where unexamined assumptions cause the most wasted work.
The design can be short, but you MUST present it and get approval.

Danh sách rationalization phổ biến cần phủ nhận trước:
- "Cái này quá đơn giản, không cần [bước X]"
- "Đang gấp, bỏ qua [kiểm tra Y] lần này"
- "Tôi thấy vấn đề rồi, sửa luôn thôi"
- "Làm nhiều thứ một lúc cho nhanh"
- "Thử cái này xem sao đã, điều tra sau"

---
Lesson 3: Mô hình hóa flow bằng state machine, không phải danh sách

Sai (danh sách tuyến tính):
1. Hỏi clarifying questions
2. Propose approaches
3. Present design
4. Get approval

Đúng (state machine với nhánh điều kiện):
digraph {
    "Ask questions" -> "Propose approaches";
    "Propose approaches" -> "Present design";
    "Present design" -> "User approves?" [shape=diamond];
    "User approves?" -> "Write doc" [label="yes"];
    "User approves?" -> "Present design" [label="no, revise"];
}

Tại sao: Danh sách không nói được điều gì xảy ra khi user từ chối, khi bị block, hay khi có nhánh điều kiện. State machine buộc bạn phải thiết kế tất cả các trường hợp.

Áp dụng thực tế: Ngay cả khi không render được DOT graph, viết dưới dạng "if/then" tường minh vẫn tốt hơn bullet list.

---
Lesson 4: Khai báo terminal state tường minh

Mọi skill cần biết nó kết thúc ở đâu và cấm cụ thể các exit sai.

**The terminal state is X.**
Do NOT invoke Y, Z, or any other action. X is the only next step.

Tại sao: Không có terminal state rõ ràng, agent sẽ tự suy luận bước tiếp theo — thường là sai. Cấm các exit sai cụ thể hiệu quả hơn chỉ nói exit đúng, vì agent biết tên của các skill/action có thể dùng.

---
Lesson 5: Red Flags table — ánh xạ suy nghĩ nội tâm sang hành động đúng

Đây là kỹ thuật đặc biệt hiệu quả: thay vì liệt kê rules, ánh xạ suy nghĩ của agent sang cảnh báo.

## Red Flags — STOP nếu bạn đang nghĩ:

| Nếu bạn nghĩ... | Thực tế là... |
|-----------------|---------------|
| "Quick fix rồi điều tra sau" | Pattern này tạo ra 3 bug thay vì 1 |
| "Tôi thấy vấn đề rồi" | Thấy symptom ≠ hiểu root cause |
| "Thêm nhiều fix cùng lúc cho chắc" | Không cô lập được cái gì thực sự work |
| "Lần này ngoại lệ vì [lý do]" | Không có ngoại lệ |

Tại sao hiệu quả: Agent nhận ra pattern trong reasoning của chính mình ngay lúc nó đang xảy ra, không phải sau khi đã hành động sai.

---
Lesson 6: Checklist với task tracking bắt buộc

## Checklist

You MUST create a task for each item and mark complete in order:

1. **[Tên bước]** — [mô tả ngắn hành động cụ thể]
2. **[Tên bước]** — ...

Tại sao: Không có tracking, agent có thể claim đã làm bước mà thực ra bỏ qua. Yêu cầu tạo task và đánh dấu tạo ra observability — bạn (và agent) có thể thấy state thực sự.

Nguyên tắc thứ tự: Bước nào phụ thuộc vào bước nào phải được đánh số rõ ràng, không để agent tự sắp xếp lại.

---
Lesson 7: Hướng dẫn model selection trong skill

## Model Selection

**Tác vụ cơ học** (1-2 file, spec rõ ràng): dùng model nhanh/rẻ
**Tác vụ tích hợp** (nhiều file, phụ thuộc phức tạp): dùng model trung bình
**Tác vụ kiến trúc/review**: dùng model mạnh nhất

Tại sao: Mặc định agent dùng cùng một model cho mọi subtask. Hướng dẫn rõ ràng trong skill tiết kiệm cost đáng kể mà không giảm chất lượng.

---
Lesson 8: Provenance-based decisions cho destructive actions

Trước mọi hành động không thể hoàn tác, skill cần dạy agent suy luận về ownership thay vì hành động theo rule cứng.

Trước khi [xóa/ghi đè/dừng] X, xác định:
- X được tạo ra bởi ai? (session này, tool khác, user tạo tay?)
- Nếu session này tạo ra → ta chịu trách nhiệm cleanup
- Nếu không phải → KHÔNG touch, báo cho user

Tại sao: Rule cứng ("luôn xóa khi xong") không xử lý được edge case. Suy luận về provenance tránh được toàn bộ class of bugs liên quan đến shared state.

---
Lesson 9: Escalation path rõ ràng cho trạng thái bị block

## Khi bị block

**BLOCKED:** Đánh giá nguyên nhân:
1. Thiếu context → cung cấp thêm context, thử lại
2. Task quá phức tạp → dùng model mạnh hơn
3. Task quá lớn → chia nhỏ
4. Plan sai → **escalate lên human, không tự quyết**

KHÔNG: bỏ qua block, force retry mà không thay đổi gì, tự quyết khi không chắc

Tại sao: Không có escalation path, agent sẽ tự looping hoặc tự quyết sai. Path rõ ràng giới hạn blast radius khi gặp vấn đề.

---
Lesson 10: Confirmation tường minh cho destructive options

**Trước khi [hành động không thể hoàn tác]:**

Hiển thị chính xác những gì sẽ bị mất:
- [Item 1]
- [Item 2]

Yêu cầu user gõ '[từ xác nhận cụ thể]' để tiếp tục.
Tại sao: "Bạn có chắc không?" quá dễ để agent tự trả lời "có". Yêu cầu gõ một từ cụ thể tạo ra friction thực sự và buộc human phải đọc warning.

---
Checklist khi viết một skill mới

Trước khi ship skill, kiểm tra:

- [ ] Mỗi bước quan trọng có hard gate không, hay chỉ là lời khuyên?
- [ ] Đã liệt kê và phủ nhận ít nhất 3 rationalization phổ biến nhất chưa?
- [ ] Flow có được mô hình hóa với nhánh điều kiện không?
- [ ] Terminal state có được khai báo tường minh và exit sai bị cấm không?
- [ ] Có Red Flags table với suy nghĩ nội tâm → cảnh báo không?
- [ ] Mọi destructive action có confirmation step với từ cụ thể không?
- [ ] Escalation path khi bị block có rõ ràng không?
- [ ] Checklist có yêu cầu task tracking không?