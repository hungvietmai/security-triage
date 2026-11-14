# Giao thức kiểm tra độc lập đợt 5 — bước gạn trên mã Python thật chưa từng xem

Viết ngày 2026-11-14, **trước khi quét bất kỳ nguồn nào dưới đây**. Mã băm của tệp này, của
[sources.json](sources.json), của ba script và của cấu hình quyết định hành vi được ghi trong
[PREREGISTRATION.json](PREREGISTRATION.json) trước lượt quét đầu tiên.

## 1. Mục đích

Qua bốn đợt trước, bước gạn chưa chuyển ứng viên nào sang "Đã gạn" trên dữ liệu độc lập: ở đợt
1–3 không ứng viên nào có bằng chứng bác bỏ, ở đợt 4 lượt quét chạy dở nên bước gạn bị tắt. Đợt
này hỏi:

1. Trên mã ứng dụng Python thật, **ở các lượt quét hoàn tất**, bước gạn có hành động không: bao
   nhiêu ứng viên bị gạn, theo quy tắc nào;
2. Mỗi ứng viên bị gạn có **đúng là an toàn** không, theo một phép kiểm độc lập với ứng dụng.

Đây **không** phải đánh giá trên tập giữ lại của `pairs-v1`; không cặp nào của tập đó bị quét.

## 2. Nguồn và cách chọn

- **Quy tắc chọn, không chọn tay:** một lần gọi API tìm kho của GitHub với truy vấn
  `language:python topic:cli stars:>1000 size:<2000 archived:false`, sắp theo số sao giảm dần;
  lấy **20 kết quả đầu** (trong 48). Mỗi kho được ghim ở commit đầu nhánh mặc định lúc lấy danh
  sách. Truy vấn, thời điểm và danh sách nằm trong [sources.json](sources.json).
- **Vì sao truy vấn này:** công cụ dòng lệnh viết bằng Python thường gọi lệnh hệ điều hành; giới
  hạn kích thước giữ thời gian quét ngắn. Truy vấn được chọn trước khi xem bất kỳ kho nào.
- **Chưa từng dùng:** không tên kho nào trong 20 kho xuất hiện trong repo trước ngày này.
- **Đã xem trước khi quét:** chỉ siêu dữ liệu mà API trả về (tên, số sao, kích thước). Chưa tải,
  chưa đọc và chưa quét mã của kho nào.

## 3. Nhãn

**Không có nhãn.** Các kho này không có lỗ hổng đã biết, nên đợt này không đo độ bao phủ, độ
chính xác hay F1. Mọi ứng viên là "chưa xác định"; đợt này đo đúng một việc: các ứng viên **chưa
xác định bị gạn**, và kiểm từng cái.

## 4. Cấu hình cố định

- Profile `command-injection-v0.2` (manifest `6993df05…`), bước gạn `adjudicate-v0.2` và các gói
  bằng chứng: đúng các tệp đã băm ở các đợt trước, không đổi.
- Worker là bản đã có hai bản sửa lỗi của ngày 2026-11-14 (ký tự xuống dòng; tệp Python không
  phân tích được). Mã băm của hai tệp đó được ghi trong bản đăng ký.
- Mỗi nguồn quét **một lần** ([collect.py](collect.py)); lượt lỗi hoặc dở được giữ nguyên.

## 5. Chỉ số

Tính bằng [filtered_candidates.py](filtered_candidates.py) và
[verify_filtered.py](verify_filtered.py), viết và kiểm thử trên dữ liệu tổng hợp trước khi quét.

| Chỉ số | Ý nghĩa |
|---|---|
| Số lượt quét `completed`, `partial`, `failed` | Bước gạn chỉ hoạt động ở lượt `completed` |
| Ứng viên, danh sách rà chính, đã gạn, chỉ hạ ưu tiên: từng lượt và tổng | Trước–sau |
| Số ứng viên bị gạn theo từng quy tắc | G2, G1, G3 |
| Phán quyết của phép kiểm độc lập cho từng ứng viên bị gạn | Gạn đúng hay sai |

**Phép kiểm độc lập** (chốt trước): với ứng viên bị gạn vì "toàn bộ lệnh là hằng" (G2), script
đọc tệp ở commit đã ghim, phân tích cú pháp bằng thư viện chuẩn của Python và xét đối số lệnh
của lời gọi ở đúng dòng đó. Đối số là hằng khi nó là chuỗi hằng, phép nối các chuỗi hằng, hoặc
danh sách/bộ gồm toàn chuỗi hằng. Tên biến, thuộc tính, lời gọi, f-string có chỗ điền, phép `%`
đều **không** là hằng. Phép kiểm này không dùng mã của ứng dụng.

## 6. Diễn giải đã chốt trước

- `constant_command`: gạn đúng. Một lệnh hằng không thể bị chèn qua đối số đó.
- `not_constant`: **thất bại** của bước gạn, bất kể lý do.
- `unreadable`: không kết luận.
- Ứng viên bị gạn bởi G1 hoặc G3 (không có G2) không có phép kiểm tự động: các dòng mã được in ra
  và đọc lại sau khi chạy; nhận định về chúng là xem xét sau, ghi đúng như vậy.
- Nếu không ứng viên nào bị gạn ở các lượt hoàn tất, kết luận là bước gạn không hành động trên
  mẫu này. Kết quả được báo cáo dù thuận hay không thuận.

## 7. Giới hạn biết trước

- Không có nhãn dương tính: đợt này **không** đo được số lỗi thật bị mất ngoài các ứng viên bị
  gạn, và không nói gì về phát hiện.
- "Lệnh là hằng" là loại cảnh báo sai dễ nhất. Kết quả thuận ở đây không nói gì về các loại cảnh
  báo sai khác, vốn là phần lớn trên dữ liệu phát triển.
- Phép kiểm độc lập xét cùng tính chất mà quy tắc G2 dựa vào; nó kiểm việc cài đặt quy tắc, không
  kiểm bản thân lập luận "lệnh hằng thì an toàn".
- 20 kho chọn theo một truy vấn: mẫu thuận tiện, không đại diện cho mã Python nói chung.
- Giao thức được viết và băm trong cùng phiên làm việc với lượt quét, chưa được công bố bằng
  commit hay push.
