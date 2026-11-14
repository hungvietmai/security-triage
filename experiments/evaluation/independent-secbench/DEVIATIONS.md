# Sai lệch so với bản đăng ký trước (đợt 2 và đợt 3)

Ghi ngày 2026-11-14, sau khi quét. [PREREGISTRATION.json](PREREGISTRATION.json) và
[../independent-python/PREREGISTRATION.json](../independent-python/PREREGISTRATION.json) được giữ
nguyên; tệp này ghi những gì đã khác đi. Bản máy đọc: [DEVIATIONS.json](DEVIATIONS.json).

## 1. Sửa một dòng trong script chấm sau khi quét

- **Tệp:** [configurations.py](configurations.py). Mã băm đã đăng ký `7fe0cb79…`, mã băm hiện tại
  `b434dd93…`.
- **Lỗi:** script dừng với `TypeError` khi sắp xếp trường chẩn đoán `same_file_candidate_lines`,
  vì ứng viên không gộp được vào lời gọi nào có `start_line` rỗng. Kiểm thử trên dữ liệu tổng
  hợp trước khi quét không có ca này.
- **Sửa:** bỏ các ứng viên có `start_line` rỗng khỏi danh sách chẩn đoán đó. Không dòng nào
  khác đổi.
- **Ảnh hưởng tới số liệu:** không. Trường này chỉ để hiển thị ca lệch dòng và, theo giao thức,
  "không đổi kết quả chính". Kiểm chứng: đợt 3 chạy được bằng script đã đăng ký; kết quả của nó
  trước và sau khi sửa **trùng từng byte**. Đợt 2 không chạy được bằng script đã đăng ký nên
  không có bản để so; cách tính số vị trí được báo nằm trong
  [../independent/known_sites.py](../independent/known_sites.py), tệp này không đổi.

## 2. Phân tích viết sau khi biết kết quả

- [posthoc_missed.py](posthoc_missed.py) và [results/posthoc-missed.json](results/posthoc-missed.json)
  đọc lại 17 vị trí không được tính là "được báo". Đây là xem xét sau, đúng như mục 6 của giao
  thức đã định; nó không sửa con số chính.
- [posthoc-after-fix/](posthoc-after-fix/result.json): hai nguồn có lượt quét đã đăng ký thất bại
  vì lỗi của ứng dụng (`buns_1.1.6`, `ts-process-promises_1.0.2`) được quét lại **sau khi sửa
  lỗi đó**. Kết quả này nằm ngoài bảng đã đăng ký: trong bảng chính hai nguồn vẫn là "lỗi".

## 3. Thay đổi mã sau lượt quét đã đăng ký

- `backend/app/scanners/acquisition.py`: giữ nguyên ký tự xuống dòng khi đọc tệp nguồn. Trước
  đó tệp có `\r\n` làm lệch vị trí byte do Semgrep trả về, khiến bộ định vị sink JavaScript dừng
  cả lượt quét. Thay đổi được thực hiện **sau** khi cả đợt 2 và đợt 3 quét xong. Các tệp có mã
  băm trong bản đăng ký (`adjudicate.py`, `reconcile.py`, profile, gói bằng chứng,
  `tools/pins.env`) không đổi.
