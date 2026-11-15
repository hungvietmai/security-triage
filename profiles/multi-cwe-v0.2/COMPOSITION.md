# Đặc tả profile multi-cwe-v0.2

- Ngày: 2026-11-15. Trạng thái: **profile ghép; mới kiểm chứng kỹ thuật trên dữ liệu phát triển,
  chưa có số liệu đánh giá riêng**. Thiết kế và kết quả kiểm chứng:
  [docs/plans/multi-cwe.md](../../docs/plans/multi-cwe.md), mục 19 và 20.
- Profile này không có luật, truy vấn, chính sách hay quy tắc gạn của riêng nó. Nó ghim manifest
  của ba profile thành viên và quét chúng trong cùng một lượt.
- Phiên bản cách ghép: `family-composition-v0.1`, như `multi-cwe-v0.1`. Cách ghép không đổi; khác
  biệt duy nhất là có thêm một thành viên.
- `multi-cwe-v0.1` vẫn là một profile riêng và không thay đổi.

## 1. Thành viên

| Nhóm phân tích | CWE | Profile thành viên | Kiểu | Ngôn ngữ |
|---|---|---|---|---|
| `command-injection` | CWE-78 | `command-injection-v0.3` | xếp hạng và gạn (G1–G4) | Python, JavaScript/TypeScript |
| `path-traversal` | CWE-22 | `path-traversal-v0.2` | bằng chứng an toàn | Python |
| `sql-injection` | CWE-89 | `sql-injection-v0.1` | chỉ phát hiện và giữ | Python, JavaScript/TypeScript |

Hai thành viên đầu giống hệt `multi-cwe-v0.1`: cùng manifest, cùng hash. Mỗi thành viên giữ nguyên
mọi tệp nó ghim và đặc tả của riêng nó. Thành viên đứng đầu chạy các công cụ sàng lọc và tạo
database CodeQL.

## 2. Cách chạy

1. Với mỗi ngôn ngữ mà thành viên đứng đầu có cấu hình, các công cụ của thành viên đó chạy một lần
   và một database CodeQL được tạo.
2. Mỗi thành viên còn lại có một lượt phân tích riêng trên chính database đó:
   `codeql-path-traversal` (Python) và `codeql-sql-injection` (Python, JavaScript/TypeScript). Truy
   vấn của các thành viên không bao giờ được đưa chung vào một lệnh phân tích.
3. Thành viên không có cấu hình cho một ngôn ngữ thì không tham gia ở ngôn ngữ đó.
4. Các thành viên phải ghim cùng một phiên bản CodeQL; nếu không, lượt quét bị từ chối.

## 3. Phân loại và định tuyến

Như `multi-cwe-v0.1`: mỗi cảnh báo giữ `reported_cwes` (nhãn công cụ, nguyên văn), `mapped_cwes`
(các CWE của định nghĩa rule đã ghim; có thể nhiều hơn một) và `analysis_family`. Mỗi lượt chạy
công cụ chỉ phục vụ một thành viên, nên nhóm được gán theo lượt chạy, trước khi có bất kỳ phép gộp
nào. Một cảnh báo không bao giờ được gộp vào đơn vị của nhóm khác, kể cả khi hai nhóm báo cùng một
vùng mã.

## 4. Thẩm định và gạn

- `command-injection` và `path-traversal`: đúng như khi quét riêng bằng profile thành viên, và đúng
  như trong `multi-cwe-v0.1`.
- `sql-injection`: không xếp hạng, không gạn. Mọi cảnh báo thành đơn vị mức `U` ở danh sách rà chính
  (đặc tả: `profiles/sql-injection-v0.1/DETECTION.md`).
- Không điều kiện gạn nào được dùng chung giữa các nhóm.

## 5. Lỗi và lượt chạy dở

Mức hoàn tất tính theo từng nhóm. Lượt `codeql-sql-injection` lỗi hoặc chạy dở không làm đổi kết quả
của hai nhóm kia; cảnh báo nó đã báo vẫn được giữ để rà. Mọi cảnh báo của lượt quét nằm trong đúng
một đơn vị; lượt quét thất bại thay vì ghi một kết quả thiếu cảnh báo.
