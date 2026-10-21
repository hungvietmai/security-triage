# Nhật ký chuẩn bị đợt C — 2026-10-20

> Cập nhật tiếp theo: [EXECUTION_LOG.md](EXECUTION_LOG.md) ghi việc tải source, chuẩn bị
> CodeQL thực tế, runner/evaluator và kiểm thử tổng hợp. Các mục dưới giữ nguyên như nhật ký
> của bước khóa mẫu ban đầu; không diễn giải chúng thành trạng thái hiện tại của acquisition.

Không tải source repository mẫu, không chạy Semgrep/CodeQL, không thực thi source của cặp
nghiên cứu và không commit/push. Các script/tool mới chỉ xử lý metadata hoặc fixture tổng hợp.

## Đầu vào và thay đổi

- Đọc handoff, hướng dẫn repository/experiments, SPEC/SPEC_RESOURCE, các báo cáo resource round,
  giao thức gốc và amendments, metadata wave B, inventory split cũ. Không đọc output held-out cũ.
- Ghi quyết định chấp nhận có điều kiện bốn giả định; giữ nguyên QL/policy/kỳ vọng/kết quả lịch sử.
  README được cập nhật số fixture ipg hiện tại (19 an toàn, 26 nguy hiểm); handoff thêm con trỏ mới.
- Hash báo cáo dev: 9/9 khớp. Hash báo cáo cex: 33/34 khớp bản hiện tại; SPEC_RESOURCE có thêm
  mục kết quả. Prefix trước mục 7 với một LF khớp hash cũ; không sửa báo cáo để che sai lệch.
- Sinh exclusions từ metadata các split cũ, repository được xét tay ở wave B, tham chiếu trong
  tài liệu nghiên cứu và danh sách loại bảo thủ cho dự án/API đã xem. Lưu nguồn/hash và lý do.
  `selection.json` cố định seed/số lượng/quy tắc trước khi sinh inventory lần đầu.
- Khóa dual mới: 62 đầu vào; giữ archive/manifest strict lịch sử, không đưa cache vào archive mới.
  Nội dung archive tạo theo tên đường dẫn đã sắp xếp, uid/gid/mtime bằng 0, mode 0644;
  gzip mtime 0 và không tên tệp. Không ghi đè archive/manifest có sẵn.

## Lệnh kiểm tra đã chạy

Môi trường kiểm tra tooling: Python 3.14.4. Không sử dụng môi trường này để chạy ứng dụng backend
(backend yêu cầu Python <3.14). Ruff 0.17.1 được tải vào cache/tool directory trong `artifacts/`;
không sửa dependency ứng dụng hay cấu hình Git. Các lần uv ban đầu bị chặn quyền cache/mạng;
lần tải với quyền mở rộng đã thành công. Những lần check sau chạy offline.

```powershell
python -m unittest discover -s experiments/tests -p test_wave_c_selection.py -v
python -m unittest discover -s experiments/tests -p test_research_freeze.py -v
python experiments/wave-c/select_repositories.py
python experiments/wave-c/select_repositories.py --check
python experiments/v03-interprocedural-guard/scripts/verify_freeze.py --metadata experiments/v03-interprocedural-guard/FREEZE_v0.3_dual.json
python experiments/v03-interprocedural-guard/scripts/verify_freeze.py --manifest experiments/wave-c/LOCK.sha256
git diff --check
```

Kết quả: 3 test selection và 2 test freeze PASS; inventory tạo được 12 repository rồi tái tạo
đúng từng byte; release kiểm tra đủ 62 file và hash archive. `git diff --check` PASS với cảnh báo
CRLF trên CSV wave B có sẵn, không sửa CSV đó trong lượt này. Kiểm tra diff Git không bao gồm
tệp untracked; phần mới được kiểm tra riêng trước khi hoàn tất.

Kiểm tra cuối: khóa đợt C PASS 17/17 file; khóa dual PASS 62/62 file và hash archive.
Đọc 63 member thường trong archive (62 đầu vào + manifest), so từng byte với workspace và dựng
lại tar/gzip bằng cùng quy tắc: hash trùng hoàn toàn
`8ee38a02b8aae10cb805c37ab2cec5813ae28331f6d51e66917bd7e2d40f4a01`.
Kiểm tra UTF-8/newline/whitespace PASS 13 file mới/chỉnh và đoạn thêm đầu handoff. Lần kiểm tra
toàn handoff ban đầu tìm thấy trailing whitespace có sẵn ở dòng 176; giữ nguyên phần lịch sử,
không sửa tệp đầu vào đã khóa để dọn định dạng. Không có lỗi kiểm tra hash hay test còn tồn tại.

```powershell
$env:UV_TOOL_DIR = Join-Path (Get-Location) 'artifacts/uv-tools'
uv --cache-dir artifacts/uv-cache tool run --offline --from ruff ruff format --check --config backend/pyproject.toml experiments/wave-c/select_repositories.py experiments/v03-interprocedural-guard/scripts/verify_freeze.py experiments/tests/test_wave_c_selection.py experiments/tests/test_research_freeze.py
uv --cache-dir artifacts/uv-cache tool run --offline --from ruff ruff check --config backend/pyproject.toml experiments/wave-c/select_repositories.py experiments/v03-interprocedural-guard/scripts/verify_freeze.py experiments/tests/test_wave_c_selection.py experiments/tests/test_research_freeze.py
```

Kết quả: 4 file đã format đúng, lint PASS. Tests sử dụng CLI thật với metadata/manifest/archive
giả trong thư mục tạm: gộp repository, loại split cũ, ổn định khi đổi thứ tự metadata, không ghi
đè kết quả, phát hiện sửa input/inventory/archive, mất file, đường dẫn vượt gốc và manifest lỗi.

## Các kiểm tra không chạy

- Không chạy lại hồi quy CodeQL/BenchmarkPython/wave A/B; QL và dữ liệu kết quả không thay đổi.
- Không chạy full suite backend/frontend/experiments; chỉ thêm tooling độc lập dùng stdlib,
  đã chạy các workflow tests liên quan. Không nhận là hooks/CI/full suites đã qua.
- Không có scan độc lập hoặc nhãn độc lập mới. Publication, source preparation, runner/evaluator,
  pack resolution và review vẫn là công việc tiếp theo theo README/protocol.

Nhật ký này có thể thêm thông tin publication trong tương lai; không thuộc các đầu vào khóa
phương pháp/mẫu. Việc bổ sung nhật ký không được dùng để sửa protocol/inventory đã khóa.
