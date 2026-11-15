# Đặc tả profile multi-cwe-v0.1

- Ngày: 2026-11-15. Trạng thái: **profile ghép; mới kiểm chứng kỹ thuật trên dữ liệu phát triển,
  chưa có số liệu đánh giá riêng**. Thiết kế và kết quả kiểm chứng:
  [docs/plans/multi-cwe.md](../../docs/plans/multi-cwe.md).
- Profile này không có luật, truy vấn, chính sách hay quy tắc gạn của riêng nó. Nó ghim manifest
  của hai profile thành viên và quét chúng trong cùng một lượt.
- Phiên bản cách ghép: `family-composition-v0.1`.

## 1. Thành viên

| Nhóm phân tích | CWE | Profile thành viên | Ngôn ngữ |
|---|---|---|---|
| `command-injection` | CWE-78 | `command-injection-v0.3` | Python, JavaScript/TypeScript |
| `path-traversal` | CWE-22 | `path-traversal-v0.2` | Python |

Mỗi thành viên giữ nguyên mọi tệp nó ghim: công cụ, luật, truy vấn, bảng rule-claims, chính sách
ưu tiên, gói bằng chứng và điều kiện gạn. Đặc tả của từng thành viên vẫn là đặc tả có hiệu lực
cho nhóm của nó. Thành viên đứng đầu chạy các công cụ sàng lọc và tạo database CodeQL.

## 2. Cách chạy

1. Với mỗi ngôn ngữ mà thành viên đứng đầu có cấu hình, các công cụ của thành viên đó chạy một
   lần và một database CodeQL được tạo.
2. Gói truy vấn của thành viên `path-traversal` được phân tích trên chính database đó, trong một
   lượt riêng tên `codeql-path-traversal`. Hai gói truy vấn không bao giờ được đưa chung vào một
   lệnh phân tích.
3. Thành viên không có cấu hình cho một ngôn ngữ thì không tham gia ở ngôn ngữ đó.
4. Các thành viên phải ghim cùng một phiên bản CodeQL; nếu không, lượt quét bị từ chối.

## 3. Phân loại và định tuyến

Mỗi cảnh báo có ba dữ kiện tách biệt:

- `reported_cwes`: nhãn công cụ gắn cho rule, giữ nguyên như công cụ viết;
- `mapped_cwes`: các CWE mà định nghĩa rule đã ghim được ánh xạ tới; một rule có thể có nhiều CWE;
- `analysis_family`: nhóm phân tích xử lý cảnh báo.

Nhóm được gán khi và chỉ khi xác định được đúng một nhóm: lượt chạy công cụ sinh ra cảnh báo chỉ
phục vụ một thành viên, hoặc đúng một thành viên ghim rule đó. Việc định tuyến xảy ra trước khi
gộp cảnh báo, nên cảnh báo của nhóm này không bao giờ được gộp vào đơn vị của nhóm kia.

## 4. Đánh giá

Cảnh báo của mỗi nhóm được đánh giá bằng đúng đường xử lý của profile thành viên. Với cùng
snapshot và cùng công cụ, đơn vị và đánh giá của một nhóm bằng kết quả quét riêng profile thành
viên đó; khác biệt duy nhất là `raw_id` của cảnh báo từ lượt `codeql-path-traversal` mang tên
lượt này thay cho `codeql`.

Profile ghép không thêm, không nới và không dùng chung điều kiện gạn nào giữa các nhóm.

## 5. Cảnh báo được giữ ngoài kết quả của thành viên

Mọi cảnh báo của lượt quét nằm trong đúng một đơn vị. Hai loại đơn vị sau do lớp ghép tạo, luôn
ở mức `U`, luôn ở danh sách rà, và không quy tắc gạn nào được áp dụng cho chúng:

| Mã quyết định | Khi nào | Nhóm ghi trên đơn vị |
|---|---|---|
| `F00_FAMILY_UNRESOLVED` | Không xác định được đúng một nhóm cho cảnh báo | `unassigned` |
| `F10_FAMILY_NOT_RANKED` | Thành viên không xếp hạng cảnh báo nào của nhóm: lượt chạy của nhóm chưa hoàn tất, hoặc bước đánh giá của thành viên thất bại | nhóm của cảnh báo |

Đơn vị loại này là một vị trí được báo; cảnh báo cùng nhóm ở cùng vị trí nằm chung một đơn vị.

## 6. Trạng thái

- Trạng thái của một nhóm là trạng thái lượt chạy của thành viên đó. Lỗi của lượt chạy chỉ phục vụ
  một nhóm không làm đổi kết quả của nhóm khác.
- Trạng thái của lượt quét: `completed` khi mọi nhóm hoàn tất; `failed` khi không nhóm nào có kết
  quả dùng được; còn lại là `partial`.

## 7. Giới hạn đã biết

- Chỉ ghép được một thành viên chạy công cụ sàng lọc với các thành viên bằng chứng an toàn chạy
  trên database dùng chung.
- JavaScript/TypeScript chỉ có nhóm `command-injection`.
- Chưa có lượt chạy công cụ nào phục vụ hai nhóm, nên trạng thái `unassigned` chưa gặp trên dữ
  liệu thật.
