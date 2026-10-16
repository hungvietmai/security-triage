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

Quan sát cho các cảnh báo còn giữ (chưa gán nhãn): một số luồng đi qua `validate_path_within_directory` ở hàm gọi
(ví dụ `local_artifact_repo.py:101`), tức guard nằm ở hàm khác và ném ngoại lệ. v0.2 không mô hình hóa guard liên thủ
tục kiểu này nên giữ cảnh báo. Nếu các cảnh báo này được xác nhận là FP, đây là giới hạn chính của v0.2 trên mã thật;
mọi sửa đổi dựa trên chúng phải coi mlflow là dữ liệu phát triển.

## Nhãn đề xuất: 27 cảnh báo CWE-22 của mlflow (`mlflow_cwe22_labels.csv`)

Mỗi cảnh báo xuất hiện giống hệt ở bản lỗi và bản vá; tính một lần. Người đề xuất nhãn **không mù** với quyết định của v0.2
(đã thiết kế v0.2 và đã thấy kết quả); nhãn dựa trên đường dữ liệu CodeQL và mã nguồn, chờ chủ đề án duyệt.

| Nguyên nhân gốc | Nội dung | Số cảnh báo | Nhãn đề xuất | v0.2 |
|---|---|---:|---|---|
| RC-M1 | `validate_path_is_safe()` ở handler (ném lỗi với `..`, đường dẫn tuyệt đối, ...) + nối dưới thư mục artifact; `validate_path_within_directory()` ở repo | 9 | FP | giữ |
| RC-M2 | Đường không khả thi: sink nằm trong lambda lọc của `FileStore`, CodeQL nối nhầm qua `list_all(filter_func=...)` | 7 | FP | giữ |
| RC-M3 | `uuid.UUID()` trong hàm được gọi, ném `ValueError` | 8 | FP | giữ |
| RC-M4 | Endpoint chỉ cho localhost, cố ý nhận đường dẫn tùy ý | 2 | unknown | giữ |
| RC-M5 | Receiver của `resolve()` trong hàm kiểm tra `is_relative_to` | 1 | FP | **loại (đúng)** |

Nếu các nhãn được duyệt: 25 FP / 0 TP / 2 unknown; v0.2 loại đúng 1/25 FP, không loại nhầm TP nào. 24 FP còn lại do guard
liên thủ tục dựa trên ngoại lệ (RC-M1, RC-M3: 17) và đường không khả thi qua callback (RC-M2: 7), hai cơ chế v0.2 không mô
hình hóa. Đây là dữ liệu phát triển nếu dùng để xây v0.3.

## Việc còn lại

- Duyệt nhãn mlflow; gán nhãn Django 7 + changedetection.io 8 cảnh báo CWE-22 mã sản phẩm, sau đó 19 cảnh báo CWE-79/test.
- Semgrep: 0–134 cảnh báo mỗi phiên bản, chưa gán nhãn (đã dừng phát triển hướng Semgrep).
