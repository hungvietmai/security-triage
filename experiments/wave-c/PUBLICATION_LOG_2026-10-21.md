# Chuẩn bị công bố — 2026-10-21

Người dùng đã cho phép commit/push và yêu cầu tuân thủ quy định commit trong `AGENTS.md`.
Không sửa protocol, inventory, QL, kết quả phát triển hoặc các manifest đã khóa.

## Kiểm tra trước commit

- `npm --prefix experiments/locators ci --ignore-scripts`: PASS, 18 package.
- `uv run --project backend --with-requirements experiments/requirements-pairs.txt python -m unittest discover -s experiments/tests -p 'test_*.py' -v`: PASS, 85 test.
- `npm --prefix frontend test`: PASS, 13 file / 62 test.
- Từ `backend/`: `uv run pytest -q --cov --basetemp=.pytest_cache/pre-push-tmp`:
  PASS ngoài sandbox, 375 passed / 2 skipped, coverage 93,84%.
  Lượt trong sandbox trước đó lỗi quyền truy cập thư mục tạm; không tính là test qua.
- `verify_freeze.py --manifest experiments/wave-c/EXECUTION_LOCK.sha256`: PASS, 98 đầu vào.
- `verify_freeze.py --metadata experiments/v03-interprocedural-guard/FREEZE_v0.3_dual.json`:
  PASS, 62 đầu vào và archive.
- `git diff --check`: PASS trên thay đổi được theo dõi trước stage.

Các lệnh `uv` dùng cache workspace `artifacts/uv-cache`. Không chạy lại scanner trên cặp nghiên cứu
lịch sử để kiểm tra tooling. Đây là kiểm tra local, chưa phải kết quả hook hoặc CI.

## Giữ nguyên byte khi công bố

Ngoài ngoại lệ CRLF cho `wave_b_labels.csv` trong `.gitattributes` gốc đã khóa, kiểm tra bổ sung
phát hiện `mlflow_cwe22_labels.csv` cũng dùng CRLF được ghi trong `LABELS_LOCK.sha256`.
Thêm `experiments/wave-b/results/.gitattributes` với `mlflow_cwe22_labels.csv -text` để Git giữ
đúng byte. Không thay bảng nhãn hoặc hash lịch sử để khớp phép chuẩn hóa xuống dòng.

## Dấu thời gian dịch vụ

CI hiện hành chỉ chạy trên push `main` hoặc pull request. Workflow riêng
`.github/workflows/research-publication.yml` chạy khi công bố khóa Wave C, chỉ checkout và
kiểm tra 98 đầu vào Git. Workflow này tạo dấu thời gian GitHub Actions mà runner đã yêu cầu;
không quét repository nghiên cứu, không chạy mã ứng dụng và không cần tạo pull request.

Chỉ điền `publication.json` sau khi có SHA commit đã push và run ID thực tế với `head_sha`
khớp. Chưa có kết quả quét Wave C ở thời điểm ghi nhật ký này. Người dùng đã xác nhận dùng
nguyên danh tính đang cấu hình `Hung. Mai Viet - CMC ATI <mvhung@cmc.com.vn>` cho đợt commit
này dù tên khác tên ghi trong `AGENTS.md`; không đổi cấu hình hay ghi đè tác giả.
