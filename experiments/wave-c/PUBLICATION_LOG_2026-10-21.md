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

## Đã công bố

- Nhánh: `feat/research-safety-evidence`.
- Năm commit: `582ec67` (provenance), `efcd0f8` (nhãn Wave B), `26f078a` (v0.3),
  `7e37357` (Wave C), `2600de1` (workflow công bố).
- Commit công bố: [2600de1acf8dfbea17e6b7fc85ac4ca0ecc6eb03](https://github.com/hungvietmai/security-triage/commit/2600de1acf8dfbea17e6b7fc85ac4ca0ecc6eb03).
- [GitHub Actions run 39541591513](https://github.com/hungvietmai/security-triage/actions/runs/39541591513):
  `created_at=2026-10-21T03:59:48Z`, `head_sha` khớp commit công bố, kết luận `success`.
- `publication.json` chỉ dùng các định danh thật trên; không tự tạo dấu thời gian công bố.
- Đã so Git blob của commit với hash: 98/98 đầu vào execution và 4/4 đầu vào nhãn khớp.
- Đã chạy `npm run prepare` để khôi phục đường dẫn hook Husky `.husky/_`: đường dẫn cũ
  trỏ thẳng `.husky` gây `Exec format error` trước khi commit đầu tiên được tạo.
- Cả năm commit chạy hook pre-commit/commit-msg thành công. `lint-staged` không có task
  cấu hình cho các tệp nghiên cứu này; không nhận đây là kiểm tra lint toàn bộ nghiên cứu.
- Push chạy hook pre-push thành công: frontend 62 test, backend 375 passed / 2 skipped,
  coverage 93,84%. Không bỏ qua hook, không force push.

Sau khi xác minh dấu thời gian dịch vụ, đã khởi chạy lệnh theo giao thức:

```powershell
wsl -d Ubuntu --exec python3 /mnt/d/github/security-triage/experiments/wave-c/run.py --execute --output artifacts/wave-c/study-001
```

Trạng thái đang chạy chưa phải kết quả cuối hoặc xác nhận nhãn. Kết quả scanner và các lỗi
được runner ghi nối tiếp; không sửa phương pháp/khóa sau khi bắt đầu xem output nghiên cứu.
