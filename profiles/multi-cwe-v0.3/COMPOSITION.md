# Đặc tả profile multi-cwe-v0.3

- Ngày: 2026-11-16. Trạng thái: **profile ghép; kiểm chứng kỹ thuật và đo trên dữ liệu phát triển,
  chưa có số liệu đánh giá độc lập**. Thiết kế và kết quả: [docs/plans/multi-cwe.md](../../docs/plans/multi-cwe.md),
  mục 21.
- Profile này không có luật, truy vấn, chính sách hay quy tắc gạn của riêng nó. Nó ghim manifest
  của ba profile thành viên và quét chúng trong cùng một lượt, cách ghép `family-composition-v0.1`.
- `multi-cwe-v0.1` và `multi-cwe-v0.2` vẫn là các profile riêng và không thay đổi; `multi-cwe-v0.2`
  là mốc chỉ dùng CodeQL cho CWE-89.

## 1. Thành viên

| Nhóm phân tích | CWE | Profile thành viên | Kiểu | Ngôn ngữ |
|---|---|---|---|---|
| `command-injection` | CWE-78 | `command-injection-v0.3` | xếp hạng và gạn (G1–G4) | Python, JavaScript/TypeScript |
| `path-traversal` | CWE-22 | `path-traversal-v0.2` | bằng chứng an toàn | Python |
| `sql-injection` | CWE-89 | `sql-injection-v0.2` | chỉ phát hiện và giữ, Semgrep + Bandit + CodeQL | Python, JavaScript/TypeScript |

Hai thành viên đầu giống hệt `multi-cwe-v0.1` và `multi-cwe-v0.2`: cùng manifest, cùng hash.

## 2. Cách chạy

1. Thành viên đứng đầu chạy công cụ sàng lọc và tạo một database CodeQL cho mỗi ngôn ngữ, như ở
   profile ghép trước.
2. Mỗi thành viên còn lại có lượt riêng của mình: `codeql-path-traversal` (Python) trên database dùng
   chung; `semgrep-sql-injection`, `bandit-sql-injection` (Python) và `codeql-sql-injection` cho nhóm
   CWE-89. Mỗi lượt có tên, SARIF, log, thời gian và `tool_run` riêng. Luật và cấu hình của các
   thành viên không bao giờ được đưa chung vào một lệnh.
3. Các thành viên phải ghim cùng phiên bản CodeQL, Semgrep và Bandit; nếu không, lượt quét bị từ
   chối.

## 3. Phân loại, gộp và gạn

Như các profile ghép trước: mỗi lượt chạy chỉ phục vụ một thành viên, nên nhóm của mỗi cảnh báo được
gán theo lượt chạy trước mọi phép gộp; một cảnh báo không bao giờ nằm trong đơn vị của nhóm khác.
Trong nhóm `sql-injection`, cảnh báo của các công cụ chỉ được gộp khi cùng nằm trong một lời gọi thực
thi SQL được định vị (đặc tả: `profiles/sql-injection-v0.2/DETECTION.md`). Nhóm này không bị gạn.

## 4. Lỗi và lượt chạy dở

Mức hoàn tất tính theo nhóm; một lượt lỗi của nhóm CWE-89 làm nhóm đó chạy dở và giữ cảnh báo của các
lượt khác, không làm đổi kết quả của hai nhóm kia. Mọi cảnh báo của lượt quét nằm trong đúng một đơn vị.
