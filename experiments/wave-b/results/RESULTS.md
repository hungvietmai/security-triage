# Đợt B — kết quả quét 22 phiên bản (11 cặp lỗi–vá)

Quét ngày 2026-10-16, theo danh sách khóa ở commit `cff13ff` (`LOCK.sha256`; nội dung cuối của
`SELECTION_PROTOCOL.md` và `inventory.yaml` khớp hash đã khóa). Cấu hình: CodeQL 2.27.1 (`python-all` 7.2.6,
`python-queries` 1.8.11), truy vấn mặc định và v0.2 cho CWE-22/78/79/643 với `--rerun`, `Evidence.ql`,
`Coverage.ql` (nguồn/đích mà truy vấn mặc định mô hình hóa), Semgrep 1.178.0 với 61 rule như thí điểm.
Toàn bộ repo được quét; cả 22 lượt đều hoàn tất (mọi bước mã thoát 0). Lệnh: `scan_one.sh`, `pair_summary.py`.

## Theo cặp (CWE nghiên cứu, tại vị trí CVE)

| Cặp | Dự án | Cảnh báo CodeQL (repo) lỗi / vá | Tại vị trí CVE | Sink trong file CVE được mô hình hóa | Nguồn trong file CVE | Ghi chú |
|---|---|---|---|---|---|---|
| GHSA-8mf9 | smolagents (CWE-643) | 0 / 0 | không | 0 | 0 | Selenium `find_elements(By.XPATH)` không là sink XPath |
| GHSA-vc25 | mcp-atlassian | 0 / 0 | không | 16 / 18 | 0 | Tham số tool MCP không là nguồn |
| GHSA-85v3 | copier | 0 / 0 | không | 22 / 22 | 0 | Cấu hình template không là nguồn |
| GHSA-mq5j | microsoft/apm | 0 / 0 | không | 40 / 40 | 0 | Tên member tar không là nguồn |
| GHSA-4vcx | dosage | 0 / 0 | không | 8 / 8 | 0 | Phản hồi HTTP client không là nguồn |
| GHSA-fvgf | Django | 9 / 9 | không | 7 / 7 | 0 | Tên member archive không là nguồn |
| GHSA-2wxc | asyncssh | 0 / 0 | không | 0 / 0 | 0 | |
| GHSA-42h5 | mlflow | 27 / 27 | **không** | 11 / 11 | 1 / 1 | 3 cảnh báo trong `handlers.py` ở hàm khác, không phải `_create_model_version` |
| GHSA-6jrf | changedetection.io | 8 / 8 | không | 0 / 0 | 0 | Đích là fetch URL `file:/` |
| GHSA-f63h | AstrBot | 0 / 0 | không | 5 / 7 | 0 | `request` của Quart không là nguồn |
| GHSA-8359 | datamodel-code-generator | 0 / 0 | không | 4 / 5 | 0 | `$ref` trong schema không là nguồn |

**Ô diễn giải:** cả 11 cặp đều là "không báo / không báo" tại vị trí CVE. Theo giao thức, các cặp này **không cung
cấp bằng chứng về hiệu quả giảm FP tại vị trí CVE** và không vào mẫu số.

**Kết luận đo được:** CodeQL mặc định không phát hiện vị trí CVE ở cả 11 cặp. Phân tích độ phủ cho thấy hạn chế đáng kể
trong mô hình nguồn, đích và luồng dữ liệu đối với API và cấu trúc của các dự án này: trong file CVE, chỉ mlflow có nguồn
được mô hình hóa, smolagents và asyncssh không có đích nào được mô hình hóa. Số nguồn bằng 0 trong file CVE không chứng minh
CodeQL không nhận diện nguồn ở nơi khác trong dự án; việc quy từng trường hợp bỏ sót cho nguồn, đích hay lan truyền là suy
luận chưa được kiểm chứng riêng từng ca.

## Cảnh báo ngoài vị trí CVE (dữ liệu duy nhất của đợt B cho đánh giá FP)

60 cảnh báo duy nhất (giống nhau ở bản lỗi và bản vá): mlflow 27 CWE-22 + 1 CWE-79, Django 9 CWE-22 (2 trong test)
+ 11 CWE-79 (test), changedetection.io 8 CWE-22 + 4 CWE-79. Bảng: `wave_b_codeql_alerts.csv`.

v0.2 đề xuất loại **1** cảnh báo (cả hai phiên bản): `mlflow/utils/uri.py:534`, receiver của
`pathlib.Path(constructed_path).resolve()` trong `validate_path_within_directory`, kết quả được kiểm tra bằng
`is_relative_to` và ném lỗi nếu ra ngoài. Nhãn đề xuất `false_positive` (sink là bước chuẩn hóa, không đọc/ghi file);
quyết định v0.2 nhất quán. **Chưa có TP nào bị loại nhầm.**

## Nhãn đầy đủ 60 cảnh báo (`wave_b_labels.csv`, tổng hợp `wave_b_label_summary.json`)

Mỗi cảnh báo xuất hiện giống hệt ở bản lỗi và bản vá; tính một lần. Người gán nhãn **không mù** với v0.2 (đã thiết kế v0.2,
đã thấy kết quả). Nhãn dựa trên mã nguồn tại commit đã khóa, đường dữ liệu CodeQL đầy đủ (`qreview/EntryPoints.ql`:
mọi nút trên mọi đường nguồn→đích; `qreview/XssPaths.ql`), bản tin công bố sau và kiểm tra thực thi trên mã tự viết
(không import, không chạy mã của dự án). Trạng thái duyệt ghi theo từng nguyên nhân gốc (`review_status`).

Định nghĩa nhãn (chi tiết trong `root_causes.json`, mục `label_definitions`):

- Đơn vị gán nhãn: một cảnh báo = một vị trí sink cùng các luồng CodeQL báo cho nó. Luồng CodeQL không báo là âm tính
  giả của truy vấn, không thuộc nhãn của cảnh báo.
- `true_positive`: một luồng được báo đưa dữ liệu bên ngoài tới sink mà không có kiểm tra chặn hậu quả của CWE.
- `TP_conditional`: như trên, nhưng tác hại hoặc khả năng đưa dữ liệu vào phụ thuộc một điều kiện nêu rõ mà chưa xác lập
  (môi trường, cấu hình, vượt qua một cơ chế khác). Tính là TP khi đo TP bị loại nhầm.
- `false_positive`: không luồng nào được báo có thể gây hậu quả của CWE (luồng không khả thi, hoặc trên mọi đường có
  kiểm tra chặn hậu quả đối với chính giá trị được dùng ở sink).
- `unknown`: chưa đủ bằng chứng. `test_code`: cảnh báo trong mã kiểm thử; đánh giá kỹ thuật ghi ở `technical_label` và
  báo cáo riêng, không gộp vào số liệu của mã sản phẩm.

### Kiểm chứng lại nhãn mlflow (27 cảnh báo CWE-22)

| Nhóm | Trước | Sau kiểm chứng | Bằng chứng chính |
|---|---|---|---|
| RC-M1 | 9 FP | **7 FP đã kiểm chứng**, 2 chuyển sang RC-M6 | Có 4 handler HTTP (không phải 3); 3 handler dùng giá trị trả về của `validate_path_is_safe()`; nhánh `list_artifacts` có `validate_path_within_directory()` (resolve + `is_relative_to`, ném lỗi) trước sink |
| RC-M6 (mới) | — | **2 unknown** (`handlers.py:973`, `local_artifact_repo.py:57`) | `get_logged_model_artifact_handler` gọi `validate_path_is_safe()` nhưng bỏ giá trị trả về và dùng chuỗi gốc; hàm kiểm tra xét bản đã giải mã/chuẩn hóa, có chuỗi gốc qua được kiểm tra nhưng vẫn thoát khỏi thư mục khi nối. Với kho artifact cục bộ có lớp kiểm tra thứ hai; với kho không cục bộ, `download_artifacts()` của lớp cơ sở nối chuỗi gốc dưới thư mục tạm. Chưa xác minh khai thác; có thể là TP |
| RC-M2 | 7 FP | **7 FP đã kiểm chứng** | Lời gọi `list_all` duy nhất mang dữ liệu nhiễm (`local_artifact_repo.py:102`) không truyền `filter_func`; lambda thực tế là `lambda x: True` |
| RC-M3 | 8 FP | **8 FP đã kiểm chứng** | Đường dẫn chỉ được tạo trong `get_session_file()`/`get_process_file()` sau `uuid.UUID()`; thử toàn bộ ký tự Unicode: không chuỗi nào được chấp nhận chứa `/`, `\`, `..`, NUL; ngoại lệ hoặc lan ra, hoặc bị bắt rồi `return` trước sink |
| RC-M4 | 2 unknown | 2 unknown | Mô hình đe dọa của endpoint localhost chưa xác lập |
| RC-M5 | 1 FP | 1 FP (tạm) | v0.2 loại |

RC-M6 cho thấy rủi ro của cơ chế guard liên thủ tục: nếu chỉ dựa vào việc "đã gọi hàm kiểm tra" thì sẽ loại nhầm một
cảnh báo có thể đúng. Chi tiết kỹ thuật của RC-M6 để ở ghi chú riêng (không commit) cho tới khi xác minh và báo cho dự án.

### Kết quả theo phạm vi

| Phạm vi | Cảnh báo | TP | TP_conditional | FP | unknown | Nguyên nhân gốc | v0.2 loại đúng FP | v0.2 loại nhầm TP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Mã sản phẩm | 44 | 4 | 3 | 33 | 4 | 13 | 1/33 | 0/7 |
| Mã kiểm thử (`technical_label`) | 16 | 10 | 0 | 6 | 0 | 7 | 0/6 | 0/10 |

Mã sản phẩm theo dự án: mlflow 24 FP + 4 unknown; Django 3 TP + 4 FP; changedetection.io 1 TP + 3 TP_conditional + 5 FP.
TP mã sản phẩm: Django admindocs `TemplateDetailView` (3, về sau là GHSA-68w8-qjq3-2gfm / CVE-2021-33203),
changedetection.io `static_content` với `group=".."` (1, về sau là GHSA-9jj8-v89v-xjvw / CVE-2026-25527).
TP_conditional: hai nhánh `filename=".."` cùng hàm (RC-C3: vượt ranh giới một cấp với tên tệp cố định; bản vá
CVE-2026-25527 cũng lọc `filename` trước hai nhánh này) và phản hồi lỗi chứa URL thông báo không được escape (RC-C4:
CSRF hạn chế cách đưa dữ liệu vào nhưng không làm đầu ra an toàn).

### Nguyên nhân FP theo cơ chế (để chọn phạm vi v0.3)

| Cơ chế | Cảnh báo (sản phẩm) | Dự án | Kiểm chứng được bằng CodeQL? | Nguy cơ loại nhầm TP |
|---|---:|---|---|---|
| F1 guard liên thủ tục: hàm kiểm tra/containment ném lỗi (RC-M1, RC-M3, Django `safe_join` RC-D2) | 19 (19) | mlflow, Django | Có, nếu chứng minh: hàm ném lỗi khi điều kiện containment/ký tự sai; sink dùng đúng giá trị đã kiểm tra hoặc bản chuẩn hóa tương đương (resolve/realpath/abspath) | Cao nếu chỉ khớp lời gọi: RC-M6 là phản ví dụ thật |
| F2 khóa thuộc tập do server sinh (RC-C1) | 5 (5) | changedetection.io | Một phần: kiểm tra `in`/tra cứu dict và rẽ nhánh được; chứng minh khóa do server sinh khó | Trung bình |
| F3 luồng không khả thi do gọi hàm bậc cao/đa hình không phân biệt ngữ cảnh (RC-M2, RC-D7) | 8 (7) | mlflow, Django | Khó: giới hạn của phân tích dòng dữ liệu, không phải bằng chứng an toàn cục bộ | Thấp |
| F5 nguồn không mang được mã độc hoặc không do bên ngoài đặt được (method, header) | 5 (0) | Django, changedetection.io | `request.method` dễ và an toàn; header là quyết định mô hình đe dọa | Trung bình–cao |
| F6 taint qua phản hồi HTTP ra ngoài (RC-M7) | 1 (1) | mlflow | Một phần | Trung bình |
| F4 guard trong hàm (đã có ở v0.2) | 1 (1) | mlflow | Đã làm | — |

F1 là cơ chế duy nhất xuất hiện ở hai dự án với ba kiểu hàm kiểm tra khác nhau (hàm tự viết, kiểu thư viện `uuid.UUID`,
containment kiểu `safe_join`) và chiếm 19/33 FP mã sản phẩm. Toàn bộ 19 cảnh báo này và RC-M6 là **dữ liệu phát triển**;
đánh giá v0.3 phải dùng repository mới.

## Việc còn lại

- Còn chờ duyệt (17 cảnh báo): RC-M4, RC-M5, RC-M7, RC-D1, RC-D2, RC-C1, RC-C2. RC-D2 thuộc F1 nên phải duyệt trước khi
  dùng làm dữ liệu phát triển.
- RC-M6: xác minh trong môi trường cô lập ngoài pipeline nghiên cứu; nếu đúng, báo riêng cho mlflow trước khi công bố.
- Semgrep: 0–134 cảnh báo mỗi phiên bản, chưa gán nhãn (đã dừng phát triển hướng Semgrep).
