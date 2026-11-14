# Giao thức kiểm tra độc lập đợt 2 — CVE chèn lệnh trên package npm (CWE-78)

Viết ngày 2026-11-14, **trước khi quét bất kỳ nguồn nào dưới đây**. Mã băm của tệp này, của
[labels.json](labels.json), của các script và của cấu hình quyết định hành vi được ghi trong
[PREREGISTRATION.json](PREREGISTRATION.json) trước lượt quét đầu tiên.

## 1. Mục đích

Đợt 1 ([../independent/](../independent/PROTOCOL.md)) chỉ có ba vị trí trong ba ứng dụng cố ý
có lỗ hổng. Đợt này lặp lại cùng câu hỏi trên **lỗ hổng thật đã công bố**, với số lượng đủ để
so các cấu hình:

1. *Phát hiện:* Semgrep riêng, CodeQL riêng, ESLint riêng, Semgrep ∪ CodeQL và hợp mọi nguồn báo
   được bao nhiêu vị trí lỗi đã công bố;
2. *An toàn của bước gạn:* bước gạn có đưa vị trí lỗi thật nào ra khỏi danh sách rà chính không;
3. *Xếp ưu tiên:* bao nhiêu vị trí lỗi thật nằm trong nhóm rà trước (P1, P2).

Đây **không** phải đánh giá trên tập giữ lại của `pairs-v1`. Không cặp nào của `pairs-v1` (phát
triển hay giữ lại) bị quét ở đây.

## 2. Nguồn và cách chọn

- **Bộ dữ liệu:** SecBench.js, thư mục `command-injection`, commit
  `5d362353550a8baa42bba34edd26e5fb86d41b60` (cùng commit mà
  [inventory](../../inventory/README.md) của dự án đã ghim).
- **Quy tắc chọn, không chọn tay:** mọi thư mục package trong đó mà package **không** có trong
  [pair-inventory.csv](../../inventory/pair-inventory.csv). Kết quả: 53 thư mục; các trường đã
  công bố của chúng được chép vào [secbench-metadata.json](secbench-metadata.json).
- **Vì sao chúng nằm ngoài inventory:** cả 53 mục đều có `fixedVersion: n/a`, nên không lập được
  cặp lỗi/vá và đã không được đưa vào inventory. Vì vậy đợt này chỉ quét phiên bản có lỗi.
- **Loại trừ cơ học** ([build_labels.py](build_labels.py)): mục mà trường `dependencies` không
  khớp tên và phiên bản của thư mục, hoặc trường `sink` không có dạng `tệp:dòng:cột`. Áp dụng
  quy tắc này loại 1 mục (`jison_0.4.17`), còn **52 nguồn**.
- **Chưa từng dùng:** không tên package nào trong 53 mục xuất hiện trong repo trước ngày này
  (tìm theo `npm:<tên>@`, `<tên>_<phiên bản>`, `secbench-<tên>-`).
- **Đã xem trước khi quét:** chỉ tệp `package.json` của SecBench.js cho từng mục (mã CVE, phiên
  bản, vị trí sink). **Chưa tải, chưa đọc và chưa quét mã nguồn của package nào.**

## 3. Nhãn và đơn vị đếm

- Mỗi nguồn có đúng một nhãn dương tính: vị trí `sink` do SecBench.js công bố (tệp, dòng, cột),
  tức lời gọi thực thi lệnh mà bộ khai thác của bộ dữ liệu chạm tới. Nhãn do tác giả bộ dữ
  liệu đưa ra; dự án không kiểm lại bằng cách đọc mã trước khi quét.
- Không vị trí nào được gán nhãn an toàn. Mọi ứng viên khác là **chưa có nhãn**: chỉ được đếm.
- Đơn vị là ứng viên rà soát (một lời gọi). **Quy tắc khớp chính, giữ nguyên từ đợt 1:** vị trí
  được tính là "được báo" khi có ứng viên cùng tệp và bắt đầu đúng dòng đó.
- Một ứng viên cùng tệp nhưng khác dòng **không** được tính. Dòng bắt đầu của các ứng viên cùng
  tệp được in kèm (`same_file_candidate_lines`) để người đọc thấy ca lệch dòng; chúng không
  đổi kết quả chính.

## 4. Cấu hình cố định

- Profile `command-injection-v0.2` (manifest `6993df05…`), công cụ theo
  [tools/pins.env](../../../tools/pins.env), bước gạn `adjudicate-v0.2`: đúng các tệp đã băm ở
  đợt 1, không đổi từ đó.
- Mỗi nguồn quét **một lần** qua ứng dụng đang chạy ([collect.py](collect.py) gọi
  [../collect_report.py](../collect_report.py)). Nguồn đã có thư mục kết quả thì không quét lại.
- Lượt quét lỗi, dở hoặc không tải được nguồn được giữ nguyên trong bảng; không thay nguồn.
  Mẫu số của mọi tỷ lệ là số vị trí thuộc các lượt quét `completed`; số nguồn không quét được
  được báo riêng.

## 5. Chỉ số

Tính bằng [configurations.py](configurations.py) (dùng lại nguyên
[../independent/known_sites.py](../independent/known_sites.py)), viết và kiểm thử trên dữ liệu
tổng hợp trước khi quét:

| Chỉ số | Ý nghĩa |
|---|---|
| Vị trí công bố được báo, theo từng cấu hình | So Semgrep riêng, CodeQL riêng, ESLint riêng, Semgrep ∪ CodeQL, hợp mọi nguồn |
| Vị trí chỉ một công cụ báo | Đóng góp riêng của từng nguồn |
| Vị trí công bố bị gạn | Lỗi thật mất do gạn; kỳ vọng bằng 0 |
| Vị trí còn lại sau gạn, theo mức ưu tiên | Bao nhiêu lỗi thật ở P1+P2 |
| Ứng viên chưa có nhãn theo danh sách và mức | Khối lượng người rà còn phải xem |
| Thời gian mỗi lượt quét | Tổng, trung vị, lớn nhất |

**Không tính được:** độ chính xác, F1 và số cảnh báo sai được gạn đúng, vì không có nhãn âm tính.

## 6. Diễn giải đã chốt trước

- Một vị trí công bố bị gạn là **thất bại** của bước gạn, bất kể lý do.
- Một vị trí công bố không được báo là bỏ sót theo quy tắc khớp chính, kể cả khi có ứng viên
  lệch dòng. Các ca lệch dòng được liệt kê và đọc lại **sau khi** có kết quả; nhận định về chúng
  là xem xét sau, được ghi đúng như vậy và không sửa con số chính.
- So sánh giữa các cấu hình là mô tả trên mẫu này, không kèm kiểm định thống kê.
- Kết quả được báo cáo dù thuận hay không thuận, kể cả khi hợp các nguồn không hơn CodeQL riêng.

## 7. Giới hạn biết trước

- Chỉ JavaScript. Bước gạn chưa có gói bằng chứng cho JavaScript, nên kỳ vọng hợp lý là không
  gạn gì: đợt này kiểm tra bước gạn **không làm hại**, không kiểm tra nó có ích.
- Chỉ có nhãn dương tính: không nói được gì về cảnh báo sai.
- Package trong SecBench.js phần lớn nhỏ, lỗi nằm ở hàm công khai gọi `exec` trực tiếp; không
  đại diện cho ứng dụng lớn.
- Package không còn trên npm sẽ thành nguồn không quét được.
- Vị trí `sink` do công cụ đo của SecBench.js ghi lại; có thể lệch so với dòng bắt đầu lời gọi
  mà ứng dụng dùng làm khóa, làm kết quả chính thấp hơn thực tế.
- Giao thức được viết và băm trong cùng phiên làm việc với lượt quét, chưa được công bố bằng
  commit hay push. Không có dấu thời gian bên ngoài chứng minh thứ tự.
