# Đặc tả profile sql-injection-v0.3

- **Ngày:** 2026-11-16.
- **Trạng thái:** **thử nghiệm**. Phát hiện và giữ, nhiều công cụ. Phép gộp mới chỉ được đo bằng cách
  chạy lại trên SARIF đã lưu, chưa có số liệu đánh giá độc lập. Thiết kế và kết quả nằm ở
  [docs/plans/multi-cwe.md](../../docs/plans/multi-cwe.md), mục 23.
- **Kiểu profile:** `detection`, schema 2. Chỉ chạy như một thành viên của profile ghép
  `multi-cwe-v0.4`.
- **Nhóm phân tích:** `sql-injection` (CWE-89), Python và JavaScript/TypeScript.
- **Quan hệ với `sql-injection-v0.2`:** v0.2 vẫn là một profile riêng và không thay đổi. v0.3 ghim
  đúng các công cụ, luật, cấu hình, truy vấn và ánh xạ CWE của v0.2 (mục 1 của
  [đặc tả v0.2](../sql-injection-v0.2/DETECTION.md)). Chỉ cách gộp đơn vị ở Python là khác.

## 1. Công cụ và luật

Như `sql-injection-v0.2`:

| Ngôn ngữ | Lượt | Công cụ |
|---|---|---|
| Python | `semgrep-sql-injection` | Semgrep CE 1.178.0, 25 file luật thượng nguồn nguyên văn |
| Python | `bandit-sql-injection` | Bandit 1.9.4, `B608`, `B610`, `B611` |
| Python | `codeql-sql-injection` | CodeQL 2.27.1, `Security/CWE-089/SqlInjection.ql` |
| JS/TS | `semgrep-sql-injection` | Semgrep CE 1.178.0, 12 file luật thượng nguồn nguyên văn |
| JS/TS | `codeql-sql-injection` | CodeQL 2.27.1, `Security/CWE-089/SqlInjection.ql` |

Mỗi file được ghim bằng cùng SHA-256 như ở v0.2.

## 2. Đơn vị và gộp (`sql-call-site-v2`)

**Bước 1, giữ nguyên `sql-call-site-v1`:**

- Cảnh báo có vùng báo nằm trọn trong cùng một lời gọi thực thi SQL đã định vị được gộp thành một
  đơn vị của lời gọi đó.
- Lời gọi thực thi là lời gọi `execute`, `executemany`, `executescript`, `raw`, `extra` hoặc
  `RawSQL`; khi các lời gọi lồng nhau, lấy lời gọi trong cùng nhất.

**Bước 2, mới:**

- Một cảnh báo Bandit `B608` nằm ngoài mọi lời gọi được nối vào đơn vị của đúng một lời gọi thực
  thi, khi phân tích cú pháp cùng phạm vi (module, class hoặc hàm) xác nhận cả sáu điều sau:
  1. Vùng báo trùng đúng một chuỗi literal hay f-string mà vế phải của câu gán `tên = <biểu thức>`
     được dựng từ đó. "Trùng" nghĩa là cùng dòng đầu, cột đầu và cột cuối. Không so dòng cuối, vì với
     chuỗi nhiều dòng Bandit 1.9.4 ghi `endLine` không phải dòng cuối của chuỗi. "Dựng từ" chỉ gồm
     `+`, `%` và `.format()`; một lời gọi hàm bọc quanh chuỗi làm mất liên kết.
  2. `tên` chỉ được gán bằng đúng câu lệnh đó trong phạm vi. Các trường hợp tính là gán thêm:
     tham số cùng tên, `+=`, biến vòng lặp, `with … as`, `import`, `except … as`, `global` hay
     `nonlocal`.
  3. `tên` không xuất hiện trong phạm vi lồng nhau: hàm con, lambda, class con, comprehension.
  4. `tên` được đọc đúng một lần trong phạm vi, và lần đọc đó là đối số vị trí đầu tiên của một lời
     gọi thực thi đứng sau câu gán.
  5. Các dòng của câu gán và của lời gọi đều là ASCII.
  6. Lời gọi đó đã có cảnh báo CodeQL hoặc Semgrep.
- Thiếu bất kỳ điều nào, cảnh báo giữ đơn vị riêng như ở v0.2, kèm lý do không nối trong bản ghi
  chạy. Ví dụ: có phép gán lại, nhiều lời gọi thực thi dùng cùng biến, biến còn được dùng ở chỗ khác,
  hoặc câu SQL đi vào một hàm bọc chưa xác định.
- Cảnh báo được nối:
  - giữ nguyên vị trí, quy tắc và nhãn CWE gốc của nó;
  - có `mapping_method` là `explicit_link`;
  - trong bằng chứng có `linked_by`, ghi biến và câu gán.

**Phạm vi:**

- Mọi cảnh báo khác, và toàn bộ JavaScript/TypeScript, giữ cách gộp của v0.2.
- Mọi đơn vị nhận mức `U` và quyết định `K10_DETECTED_KEPT`.
- Phiên bản đơn vị là `detection-units-v3`; phiên bản bộ định vị là `sql-call-site-v2`.

## 3. Gạn và lượt chạy lỗi

Như `sql-injection-v0.2`:

- Không có điều kiện gạn; mọi đơn vị ở danh sách rà chính.
- Một lượt lỗi hoặc dở làm nhóm chạy dở và giữ cảnh báo của các lượt còn lại.
