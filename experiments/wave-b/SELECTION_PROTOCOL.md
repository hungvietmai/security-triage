# Giao thức chọn cặp lỗi–vá (CWE-22, CWE-643) — viết trước khi lọc

Ngày: 2026-10-16. Viết trước khi tải bản tin, trước mọi lần quét. Không chạy Semgrep/CodeQL ở bước này.

## Nguồn

`github/advisory-database`, thư mục `advisories/github-reviewed/` (bản tin GitHub đã rà soát), tại commit
được ghi trong `inventory.yaml` (`source_commit`).

## Lọc tự động (theo thứ tự, ghi lý do loại cho từng bản tin)

1. Có ít nhất một gói hệ sinh thái `PyPI`.
2. `database_specific.cwe_ids` chứa `CWE-22` hoặc `CWE-643` (giữ mọi CWE khác đi kèm để báo cáo).
3. Không bị rút lại (`withdrawn` rỗng).
4. Có ít nhất một tham chiếu dạng `https://github.com/<owner>/<repo>/commit/<sha>` (commit vá).
   Không có thì loại với lý do `no_fix_commit_reference` (không suy đoán commit từ số phiên bản).

## Thứ tự xét tay

Ứng viên còn lại được sắp theo `sha256("security-triage/wave-b-v1/" + ghsa_id)` và chia hai tầng:

- **CWE-643:** xét tay toàn bộ (bộ lọc tự động chỉ còn rất ít bản tin).
- **CWE-22:** xét tay lần lượt theo thứ tự hash cho đến khi có 10 cặp đủ điều kiện hoặc hết ứng viên.

(Sửa đổi 2026-10-16, trước khi xét tay ứng viên nào: sau bước lọc tự động, toàn bộ cơ sở dữ liệu chỉ có 2 bản tin
`pip` mang CWE-643 so với 532 mang CWE-22; một thứ tự chung sẽ gần như không bao giờ chọn CWE-643.)

Không bỏ qua ứng viên vì lý do khác các tiêu chí dưới đây;
mọi ứng viên đã xét đều được ghi kèm quyết định.

## Tiêu chí xét tay (chỉ dựa vào bản tin, diff của commit vá và mã nguồn; không dựa vào công cụ)

- `fix_commit_verified`: commit tồn tại trong repo công khai; `vulnerable_commit` = cha thứ nhất của commit vá.
- `python_change`: diff sửa ít nhất một file `.py`.
- `cwe_relevant`: thay đổi liên quan trực tiếp tới CWE đã gán (đường dẫn tệp hoặc biểu thức XPath), không chỉ
  cập nhật phiên bản/tài liệu.
- `external_source`: dữ liệu ở vị trí lỗi có thể đến từ bên ngoài (HTTP, tệp/kho lưu trữ do người dùng tải lên,
  tham số CLI/API công khai). Ghi loại nguồn trong `relevant_source`.
- `sink_class`: ghi loại đích (`file_open`, `file_write`, `send_file`, `archive_extraction`, `xpath`, ...).
  `archive_extraction` vẫn đủ điều kiện nhưng được ghi là phép thử giới hạn phát hiện của truy vấn CWE-22.
- Một cặp gồm `vulnerable_commit` và `fixed_commit`. Nhiều bản tin cùng một commit vá được gộp thành một cặp.

Quyết định: `eligible` hoặc `excluded:<lý do>`. Mọi cặp vào danh sách có `eligibility: pending_review` cho tới khi
chủ đề án duyệt.

## Sau khi khóa

Danh sách và giao thức này được commit trước lần quét đầu tiên. Mọi cặp đủ điều kiện được quét đồng nhất
(CodeQL mặc định, v0.2, Semgrep), kể cả khi không có cảnh báo. Không loại cặp vì kết quả quét. Nhãn CVE chỉ dùng cho
vị trí của CVE; các cảnh báo khác và cảnh báo còn lại sau bản vá được gán nhãn riêng.
