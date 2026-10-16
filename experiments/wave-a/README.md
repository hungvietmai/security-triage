# Đợt A — v0.2 trên dự án Python thực tế

Ngày chạy: 2026-10-16. Phiên bản bằng chứng: v0.2 (`SafetyEvidence.qll` sha256 `8c7a6f77…ce2c`,
khớp `FREEZE_v0.2.sha256`). Hash từng truy vấn: `query_hashes.txt`. Lệnh: `run.sh`, `join.py`.

| Dự án | Commit | File .py trích xuất |
|---|---|---|
| Flask-Admin | `4f8be4580b082c6047492baa801f3f08642c9a75` | 168 / 168 |
| Paperless-ngx | `d4a57204ebabd5ab674771ab606a66ea90f9370a` | 410 / 410 |

Công cụ: CodeQL 2.27.1, `python-all` 7.2.6, `python-queries` 1.8.11; truy vấn mặc định (biến thể `none`)
và v0.2 (`all`) cho CWE-22/78/79/643, chạy với `--rerun`; bảng bằng chứng `Evidence.ql`; Semgrep 1.178.0
với 61 rule cộng đồng như thí điểm. Phạm vi: toàn bộ repo; cảnh báo trong `tests/`, `examples/`, `docs/`
được đánh dấu `test-or-example`.

## Kết quả

| Dự án | CodeQL mặc định | v0.2 loại | Semgrep |
|---|---|---|---|
| Flask-Admin | 3 (CWE-22, mã sản phẩm) | 0 | 22 CWE-79 kiểu kiểm tra API (`Markup`, `jinja2`); 19 sản phẩm, 3 ví dụ |
| Paperless-ngx | 0 | — | 8 CWE-79 (`HttpResponse`, `jinja2`), 2 CWE-78 (subprocess, kiểm tra API) |

Không có cảnh báo CWE-643 ở cả hai dự án. Bảng bằng chứng chỉ có 2 dòng (header, ví dụ Flask-Admin)
và 1 dòng ở Paperless; không có bằng chứng nào nằm trên luồng dẫn tới cảnh báo.

**Điều kiện dừng đã chạm:** số cảnh báo CWE-22/643 quá ít để kết luận về giảm FP (3 cảnh báo, 0 bị loại).

## Ba cảnh báo của Flask-Admin

`flask_admin/contrib/fileadmin/__init__.py` dòng 151 (`path_exists`), 175 (`read_file`), 182 (`write_file`).
Luồng: tham số `path` của các view FileAdmin (ví dụ `/edit/`: `request.args`) → `_normalize_path` →
các hàm lưu trữ. Phép kiểm tra chứa `is_in_folder()` là `normpath(directory).startswith(base_path)`,
**không có dấu phân cách**. Mô phỏng: gốc `/srv/files`, `../files-private/secret.txt` → `/srv/files-private/secret.txt`
vẫn qua kiểm tra.

- Nhãn đã duyệt (2026-10-16): `true_positive_conditional`, `review_status = owner_reviewed`,
  `exploit_verification = not_independently_confirmed`. Điều kiện khai thác (thư mục anh em cùng tiền tố,
  quyền vào view quản trị) không làm cảnh báo thành FP.
- Cả ba cảnh báo đi cùng một đường CodeQL: `request.args.getlist("path")` (view `edit`, dòng 1311) →
  `_normalize_path` → kiểm tra `is_in_folder` (dòng 731) → `path_exists` (734) / `write_file` (1337) /
  `read_file` (1355). Báo cáo **3 cảnh báo nhưng 1 nguyên nhân gốc độc lập**
  (`root_cause_id = flask-admin/is_in_folder-prefix-without-separator`).
- Nguồn độc lập: bài viết công khai mô tả đúng lỗi này (infosecwriteups, 29/07/2026); mã vẫn còn ở commit đã quét.
- v0.2 **giữ** cả ba cảnh báo, vì `startswith` không có dấu phân cách không được coi là bằng chứng an toàn.
  v0.1 (đã chạy lại trên cùng database, hash `983127c5…`) cũng giữ cả ba: phép kiểm tra nằm trong một hàm
  khác (`is_in_folder` trả về bool) và được gọi trên `self.normpath(...)`, không trên biến cục bộ, nên
  không quy tắc nào của v0.1 áp dụng. Dự án này vì vậy chưa phân biệt được v0.1 và v0.2.

Semgrep: 32 cảnh báo đều là quy tắc kiểm tra cách dùng API, chưa gán nhãn; theo kế hoạch, Semgrep chưa được
phát triển tiếp.

## Tệp

`flask-admin/alerts.csv`, `paperless-ngx/alerts.csv`: một dòng mỗi cảnh báo theo các trường đã thống nhất
(`repository, commit_sha, cwe, file, sink_location, detected_by, baseline_alert, v02_decision,
evidence_mechanism, manual_label, label_evidence, review_status`, kèm `function`, `scope`, `evidence_detail`).
SARIF, bảng bằng chứng và CodeQL database ở `artifacts/wave-a/` (không commit).
