# Giao thức kiểm tra độc lập quy mô nhỏ (CWE-78)

Viết ngày 2026-11-14, **trước khi quét bất kỳ nguồn nào dưới đây**. Mã băm của tệp này, của
[labels.json](labels.json) và của các tệp quyết định hành vi được ghi trong
[PREREGISTRATION.json](PREREGISTRATION.json) trước lượt quét đầu tiên.

## 1. Mục đích

Kiểm tra trên mã **chưa từng được dự án quét hay xem** hai tính chất của quy trình:

1. *Phát hiện:* hợp các nguồn có báo vị trí lỗi chèn lệnh đã được tác giả ứng dụng công bố không;
2. *An toàn của bước gạn:* bước gạn có đưa vị trí lỗi thật nào ra khỏi danh sách rà chính không.

Đây **không** thay cho đánh giá trên tập `pairs-v1` (50 cặp CVE lỗi/vá, 16 cặp giữ lại). Tập đó
chưa được quét và không bị đụng tới ở đây: dùng nó cần chủ đề án quyết định và một giao thức được
công bố bằng commit trước khi quét.

## 2. Nguồn

Ba ứng dụng "cố ý có lỗ hổng" công khai, mỗi cái công bố một lỗi chèn lệnh hệ điều hành.

| Mã | Kho và commit | Ngôn ngữ | Vị trí đã công bố | Căn cứ |
|---|---|---|---|---|
| `dvna` | `appsecco/dvna@9ba473a` | JavaScript | `core/appHandler.js:39` | Tài liệu của dự án nêu tên tệp, trích mã và chuỗi khai thác |
| `dsvw` | `stamparm/DSVW@9ca3c9a` | Python | `dsvw.py:31` | Danh sách ca của chính ứng dụng, kèm chuỗi khai thác |
| `nodejs-goof` | `snyk-labs/nodejs-goof@add14ba` | JavaScript | `routes/index.js:174` | README liệt kê "Command execution"; vị trí do đọc mã xác định |

- **Cách chọn:** tìm ứng dụng công khai có công bố lỗi chèn lệnh, đủ nhỏ so với giới hạn của ứng
  dụng (50 MiB tải về). Đây là mẫu chọn có chủ đích, không phải mẫu ngẫu nhiên. Hai ứng viên khác
  bị loại trước khi quét: `we45/Vulnerable-Flask-App` (không có lời gọi thực thi lệnh) và
  `adeyosemanputra/pygoat` (không xác định được vị trí lỗi từ tệp đã đọc).
- **Chưa từng dùng:** không tên kho nào trong ba kho xuất hiện trong repo trước ngày này
  (`git grep` theo tên chủ kho không có kết quả).
- **Đã xem trước khi quét:** chỉ tài liệu của từng dự án và tệp chứa vị trí đã công bố, để ghi
  nhãn. Chưa chạy công cụ quét nào trên ba kho.

## 3. Cấu hình cố định

- Profile `command-injection-v0.2`; công cụ theo [tools/pins.env](../../../tools/pins.env).
- Bước gạn `adjudicate-v0.2` và các gói bằng chứng như trong working tree lúc viết giao thức;
  mã băm ghi ở `PREREGISTRATION.json`.
- Mỗi nguồn quét **một lần** qua ứng dụng đang chạy
  (`python experiments/evaluation/collect_report.py`). Không quét lại sau khi đổi quy tắc.
- Lượt quét lỗi hoặc dở được giữ nguyên trong bảng kết quả; không thay nguồn.

## 4. Nhãn và đơn vị đếm

- Nhãn chỉ gồm **vị trí lỗi đã công bố** (dương tính). Không vị trí nào được gán nhãn an toàn.
- Đơn vị là ứng viên rà soát (một lời gọi). Một vị trí công bố được tính là "được báo" khi có
  ứng viên cùng tệp và bắt đầu đúng dòng đó.
- Mọi ứng viên khác là **chưa có nhãn**: chỉ được đếm theo danh sách và mức ưu tiên, không được
  tính là đúng hay sai.

## 5. Chỉ số

Tính bằng [known_sites.py](known_sites.py), viết trước khi quét:

| Chỉ số | Ý nghĩa |
|---|---|
| Vị trí công bố được báo / tổng số | Độ bao phủ trên lỗi đã biết |
| Công cụ nào báo từng vị trí | Đóng góp của từng nguồn |
| Mức ưu tiên của vị trí | Có nằm trong nhóm rà trước (P1, P2) không |
| Vị trí công bố bị gạn | Lỗi thật bị mất do gạn; kỳ vọng bằng 0 |
| Ứng viên chưa có nhãn theo danh sách và mức | Khối lượng người rà còn phải xem |
| Ứng viên chưa có nhãn bị gạn | Liệt kê từng cái để xem lại sau khi chạy |

**Không tính được:** độ chính xác, F1 và số cảnh báo sai được gạn đúng, vì không có nhãn âm tính.

## 6. Diễn giải đã chốt trước

- Một vị trí công bố bị gạn là **thất bại** của bước gạn, bất kể lý do.
- Một vị trí công bố không được báo là bỏ sót của bước phát hiện; ghi rõ công cụ nào im lặng.
- Ứng viên chưa có nhãn bị gạn sẽ được đọc lại sau khi chạy; kết luận về nó là xem xét sau khi
  đã biết kết quả và được ghi đúng như vậy.
- Kết quả được báo cáo dù thuận hay không thuận.

## 7. Giới hạn biết trước

- Ba nguồn, ba vị trí: quá ít để ước lượng tỷ lệ.
- Ứng dụng cố ý có lỗ hổng thường viết lỗi ở dạng dễ thấy; không đại diện cho mã sản xuất.
- Bước gạn chỉ có gói bằng chứng cho Python, nên với hai nguồn JavaScript, kỳ vọng hợp lý là
  không gạn gì.
- Giao thức được viết và băm trong cùng phiên làm việc với lượt quét, chưa được công bố bằng
  commit hay push. Không có dấu thời gian bên ngoài chứng minh thứ tự.
