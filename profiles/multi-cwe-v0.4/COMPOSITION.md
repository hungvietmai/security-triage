# Đặc tả profile multi-cwe-v0.4

- **Ngày:** 2026-11-16.
- **Trạng thái:** **profile ghép thử nghiệm**. Thiết kế và kết quả nằm ở
  [docs/plans/multi-cwe.md](../../docs/plans/multi-cwe.md), mục 23.
- **Nội dung:**
  - Profile này không có luật, truy vấn, chính sách hay quy tắc gạn của riêng nó.
  - Nó ghim manifest của ba profile thành viên và quét chúng trong cùng một lượt, cách ghép
    `family-composition-v0.1`.
- **Các profile ghép trước:** `multi-cwe-v0.1`, `multi-cwe-v0.2` và `multi-cwe-v0.3` vẫn là các
  profile riêng và không thay đổi.

## 1. Thành viên

| Nhóm phân tích | CWE | Profile thành viên | Kiểu | Ngôn ngữ |
|---|---|---|---|---|
| `command-injection` | CWE-78 | `command-injection-v0.3` | xếp hạng và gạn (G1–G4) | Python, JavaScript/TypeScript |
| `path-traversal` | CWE-22 | `path-traversal-v0.2` | bằng chứng an toàn | Python |
| `sql-injection` | CWE-89 | `sql-injection-v0.3` | chỉ phát hiện và giữ, Semgrep + Bandit + CodeQL | Python, JavaScript/TypeScript |

- Hai thành viên đầu giống hệt `multi-cwe-v0.3`: cùng manifest, cùng hash.
- Thành viên CWE-89 chạy cùng công cụ, luật và cấu hình như `sql-injection-v0.2`. Khác biệt duy
  nhất: một cảnh báo Bandit B608 ở câu gán dựng chuỗi SQL được nối với cảnh báo CodeQL hoặc Semgrep
  tại lời gọi thực thi chuỗi đó, theo điều kiện ở `profiles/sql-injection-v0.3/DETECTION.md`.

## 2. Cách chạy, phân loại, lỗi

Như `multi-cwe-v0.3`:

- Mỗi thành viên có lượt chạy riêng, có tên. Trong một lượt quét, các thành viên phải ghim cùng phiên
  bản CodeQL, Semgrep và Bandit.
- Nhóm của mỗi cảnh báo được gán theo lượt chạy, trước mọi phép gộp.
- Mức hoàn tất tính theo nhóm. Mọi cảnh báo của lượt quét nằm trong đúng một đơn vị.
