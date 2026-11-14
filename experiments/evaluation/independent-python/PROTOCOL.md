# Giao thức kiểm tra độc lập đợt 3 — ứng dụng Python có lỗi chèn lệnh đã công bố (CWE-78)

Viết ngày 2026-11-14, **trước khi quét bất kỳ nguồn nào dưới đây**. Mã băm của tệp này, của
[labels.json](labels.json) và của các tệp quyết định hành vi được ghi trong
[PREREGISTRATION.json](PREREGISTRATION.json) trước lượt quét đầu tiên.

## 1. Mục đích

Bước gạn của quy trình chỉ có gói bằng chứng cho **Python**. Đợt 2
([../independent-secbench/](../independent-secbench/PROTOCOL.md)) chỉ gồm JavaScript nên không
thử được câu hỏi quan trọng nhất của bước gạn: *trên mã Python chưa từng xem, bước gạn có đưa
lỗi thật ra khỏi danh sách rà chính không*. Đợt 1 chỉ có một vị trí Python (DSVW). Đợt này thêm
các vị trí Python.

Đây **không** phải đánh giá trên tập giữ lại của `pairs-v1`; không cặp nào của tập đó bị quét.

## 2. Nguồn và cách chọn

| Mã | Kho và commit | Vị trí đã công bố | Căn cứ |
|---|---|---|---|
| `vulnerable-api` | `mattvaldes/vulnerable-api@4b05023` | `ansible/roles/api/files/vAPI.py:232` | README liệt kê "Command Injection" và mô tả `GET /uptime/FLAG` |
| `vulnerable-flask-app` | `videvelopers/Vulnerable-Flask-App@155a9d4` | `vulnerable-flask-app-linux.py:58`, `:119`; `vulnerable-flask-app-windows.py:58`, `:119` | README liệt kê "Command Injection"; vị trí do đọc mã xác định |
| `shiftleft-python-demo` | `ShiftLeftSecurity/shiftleft-python-demo@6ea30ac` | `flask_webgoat/actions.py:44` | README chỉ tới chú thích ở dòng 43, ngay trên lời gọi |

- **Cách chọn:** dò mười hai kho ứng dụng luyện tập viết bằng Python; giữ những kho mà README có
  nêu lỗi chèn lệnh hoặc thực thi mã từ xa qua lệnh hệ điều hành. Đây là mẫu chọn có chủ đích.
  Các kho bị loại **trước khi quét**: README không nêu lỗi chèn lệnh (`Contrast-Security-OSS/vulnpy`,
  `fportantier/vulpy`, `payatu/Tiredful-API`, `mpirnat/lets-be-bad-guys`, `NetSPI/django.nV`),
  không phải Python (`snoopysecurity/Broken-Vulnerable-Code-Snippets`), không còn tồn tại (hai
  kho), và một bản sao của kho đã chọn (`jorritfolmer/vulnerable-api`).
- **Chưa từng dùng:** không tên kho hay chủ kho nào xuất hiện trong repo trước ngày này.
- **Đã xem trước khi quét:** README của từng kho và các dòng quanh mỗi lời gọi thực thi lệnh
  trong tệp Python của chúng, để ghi nhãn. Chưa chạy công cụ quét nào trên ba kho.
- **Hai tệp của `vulnerable-flask-app` gần như trùng nhau** (bản Linux và bản Windows của cùng
  ứng dụng). Bốn vị trí của nó tương ứng với hai lỗi độc lập; bảng kết quả phải nêu điều này.
- Khi đọc mã để ghi nhãn, có hai lời gọi nhận lệnh là chuỗi hằng
  (`vulnerable-flask-app-*.py:68`, `cat restapi.log`). Chúng **không** được gán nhãn; nếu bước
  gạn chuyển chúng đi thì đó là ứng viên chưa có nhãn bị gạn và được liệt kê.

## 3. Cấu hình, nhãn, chỉ số

Giữ nguyên từ đợt 1 và đợt 2:

- Profile `command-injection-v0.2`, bước gạn `adjudicate-v0.2`, các gói bằng chứng: đúng các tệp
  đã băm ở đợt 1.
- Mỗi nguồn quét **một lần** ([collect.py](collect.py)); lượt lỗi được giữ nguyên.
- Nhãn chỉ gồm vị trí lỗi đã công bố. Vị trí "được báo" khi có ứng viên cùng tệp và bắt đầu đúng
  dòng đó.
- Chỉ số tính bằng [../independent-secbench/configurations.py](../independent-secbench/configurations.py)
  (không sửa): vị trí được báo theo từng cấu hình, vị trí bị gạn, mức ưu tiên, ứng viên chưa có
  nhãn, thời gian.

## 4. Diễn giải đã chốt trước

- Một vị trí công bố bị gạn là **thất bại** của bước gạn.
- Ứng viên chưa có nhãn bị gạn được đọc lại sau khi chạy; nhận định về nó là xem xét sau.
- Kết quả được báo cáo dù thuận hay không thuận.

## 5. Giới hạn biết trước

- Ba nguồn, sáu vị trí (bốn trong số đó là hai lỗi lặp lại ở hai tệp): quá ít để ước lượng tỷ lệ.
- Ứng dụng luyện tập viết lỗi ở dạng dễ thấy; các tình huống mà gói bằng chứng nhắm tới (nhánh
  điều kiện hằng, đọc phần tử hằng, định tuyến cố định) có thể không xuất hiện, khi đó đợt này
  chỉ cho thấy bước gạn không can thiệp.
- `vAPI.py` có thể viết cho Python 2; công cụ có thể không phân tích được tệp.
- Không có nhãn an toàn: không tính được độ chính xác.
- Giao thức được viết và băm trong cùng phiên làm việc với lượt quét, chưa được công bố bằng
  commit hay push.
