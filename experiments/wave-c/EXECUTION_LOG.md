# Nhật ký chuẩn bị thực thi — 2026-10-20

Tiếp nối [nhật ký khóa mẫu](PREPARATION_LOG.md). Không commit/push; chưa quét repository nghiên cứu.
Source đã được tải/kiểm tra archive, không được import, build, cài dependency hay thực thi.
Các lượt CodeQL dưới đây chỉ dùng hai file tổng hợp do `smoke_runner.py` tạo, không dùng cặp
nghiên cứu lịch sử hoặc mẫu mới để thử tooling.

## Acquisition

Lệnh thực chạy:

```powershell
python -u experiments/wave-c/prepare_sources.py
python experiments/wave-c/prepare_sources.py --check
```

Lượt tải được chạy với quyền mạng mở rộng. Cả 12 repository giữ nguyên thứ tự inventory:
7 prepared, 3 vượt giới hạn download 50 MiB, 2 bị từ chối vì symlink. Không thay thế, không
nới giới hạn hậu nghiệm. Mọi metadata/byte tải hoàn tất có SHA-256 và cache content-addressed;
archive bị từ chối vì symlink vẫn được giữ. Lượt vượt giới hạn không có hash toàn archive.
Chi tiết trong `sources.lock.json`. Chạy `--check` sau tải PASS, không phát sinh download mới.

Metadata GitHub cho cả 12 xác định được repository/commit; không phát hiện alias/fork với
nhóm cũ. Near-duplicate review còn pending; không tự nhận nhóm nào đã được người dùng duyệt.

## Môi trường và phụ thuộc

Đọc WSL/Docker: Ubuntu WSL2 có sẵn; Docker daemon không chạy, không khởi động Docker.
Ubuntu dùng Python 3.12.3. Các kiểm thử stdlib trên Windows dùng Python 3.14.4; không chạy
backend bằng phiên bản Python ngoài phạm vi backend yêu cầu.

Tải release metadata chính thức và `codeql-linux64.zip` v2.27.1 (416.424.341 byte), xác minh
SHA-256 `6ad2cead390cecf62dd59ae7ffd673d216902a9c00975ce107a362464a8b891e` trước giải nén.
Ubuntu thiếu `unzip`; kiểm tra 3.805 entry ZIP, không symlink, không path traversal, rồi giải
nén bằng Python vào artifacts. Không cài package hệ thống hay đổi cấu hình Git user.

```powershell
wsl -d Ubuntu --exec python3 /mnt/d/github/security-triage/experiments/wave-c/prepare_toolchain.py
python experiments/wave-c/prepare_toolchain.py --check
```

Kết quả PASS: CLI thực tế 2.27.1, python-all 7.2.6, python-queries 1.8.11; 1.628 file công cụ/
phụ thuộc/output resolution được neo trong `toolchain.lock.json`. Cache và pack copy ở artifacts;
không sửa pack QL gốc. Giữ cảnh báo CodeQL về thư viện local trong stderr, không dùng flag
tắt strict mode để che cảnh báo. `pack-locks/` giữ nguyên byte ba lock YAML đã resolve.

Diagnostics chạy `database run-queries --rerun` và decode BQRS, đã kiểm chứng bằng CLI thật.
Kiểm tra riêng help/parse của `query run`: help exit 0, thiếu query/database exit 2. Không dùng
những kiểm tra đó để khẳng định CLI đã từ chối `--rerun`; help không liệt kê tùy chọn này.
Không query nào thực thi trong kiểm tra argument-only. Log ở `artifacts/wave-c/option-check/`.

## Kiểm thử workflow và lint

```powershell
python -m unittest discover -s experiments/tests -p 'test_wave_c_*.py' -v
python -m unittest discover -s experiments/tests -p test_research_freeze.py -v
$env:UV_TOOL_DIR = Join-Path (Get-Location) 'artifacts/uv-tools'
uv --cache-dir artifacts/uv-cache tool run --offline --from ruff ruff format --check --config backend/pyproject.toml experiments/wave-c/*.py experiments/tests/test_wave_c_*.py
uv --cache-dir artifacts/uv-cache tool run --offline --from ruff ruff check --config backend/pyproject.toml experiments/wave-c/*.py experiments/tests/test_wave_c_*.py
```

Kết quả cuối PASS: **21 test wave C + 2 test freeze**, format và lint 11 file Python.
Command/stdout/stderr/mã thoát của kiểm tra cuối ở `artifacts/wave-c/preflight-checks/`.
Trong wrapper ghi log, glob được mở thành danh sách tên file cụ thể trước khi gọi Ruff.

Tests dùng archive/SARIF/CSV tổng hợp, stub download/CodeQL/Git/HTTP tại biên. Logic acquisition,
persistence, gộp sink, chấm điểm và sinh review packet chạy thật. Timeout test chạy process Python
tạm thật. Các rủi ro được kiểm tra gồm cache đổi byte, commit sai, symlink/path traversal,
publication sai/manifest rỗng, lỗi launch/timeout, thiếu coverage/output và loại TP/unknown.
Lỗi lint/format và lỗi bố trí fixture của test mới phát hiện trong lúc phát triển đã được sửa;
không có test/check liên quan còn lỗi ở lần chạy cuối. Không thay QL để xử lý test tooling.

## CodeQL thật trên fixture tổng hợp

```powershell
wsl -d Ubuntu --exec python3 /mnt/d/github/security-triage/experiments/wave-c/smoke_runner.py --output artifacts/wave-c/smoke-001
python experiments/wave-c/evaluate.py --run artifacts/wave-c/smoke-001/run.json --output artifacts/wave-c/smoke-review-001
wsl -d Ubuntu --exec python3 /mnt/d/github/security-triage/experiments/wave-c/smoke_runner.py --output artifacts/wave-c/smoke-002
```

Lượt 001 PASS: `none=1`, `all=1`, `v03=1`, `v03s=1`; cảnh báo nguy hiểm được giữ ở cả bốn
cấu hình, trích xuất 2/2 file Python (gồm test chứa sentinel raise nếu bị chạy), không thiếu file,
không vi phạm tập con. Tổng 608,36 giây. Đủ 15 lệnh create/analyze/diagnostic/decode exit 0;
log, SARIF, CSV và snapshot được giữ nguyên. Đây là kiểm tra không vacuous của runner, không
phải số liệu hiệu quả độc lập. Evaluator CLI đọc được output thật và sinh 1 review unit, mọi nhãn
và reviewer vẫn trống. Chưa nhận là con người đã duyệt fixture hay mẫu nghiên cứu.

Lượt 002 chạy lại sau khi chốt xử lý lỗi launch/timeout và validation của runner: PASS,
`none=all=v03=v03s=1`, trích xuất đủ 2/2 file, 15 lệnh exit 0; tổng 387,23 giây. Giữ cả hai
lượt, không ghi đè kết quả lượt 001. Evaluator CLI của lượt 002 cũng PASS với 1 review unit
chưa gán nhãn. Kết quả và hash command/run/summary được neo trong `results/preflight.json`.

## Plan và cổng publication

```powershell
wsl -d Ubuntu --exec python3 /mnt/d/github/security-triage/experiments/wave-c/run.py --plan --output artifacts/wave-c/plan-001
wsl -d Ubuntu --exec python3 /mnt/d/github/security-triage/experiments/wave-c/run.py --execute --output artifacts/wave-c/study-gate-check
```

Plan PASS: 12 repository đúng thứ tự, chỉ 7 prepared có bộ lệnh; 5 acquisition failures vẫn
có trong plan. Thư mục plan chỉ có `plan.json`, không giải nén source hay tạo database.

Kiểm tra cổng thực thi PASS theo kỳ vọng **exit 1**: thiếu `publication.json`; xác nhận không
tạo `study-gate-check`, không có study database. Không tạo publication giả hoặc chạy skip flag.
User chưa yêu cầu commit/push, nên cổng công bố trong protocol vẫn chưa hoàn tất.

## Bảo toàn bản khóa và Git

Các kiểm tra khóa strict/scoped 62 file, selection 17 file, source cache và toolchain PASS.
Phát hiện Git sẽ chuẩn hóa CRLF của `wave_b_labels.csv`, làm khác hash đã khóa; thêm `-text`
riêng cho file đó trong `.gitattributes`. So `git hash-object` có/không filter sau thay đổi cho
kết quả giống nhau. Không sửa CSV hoặc khóa lịch sử để né sai lệch; các đầu vào khác vẫn giữ
quy tắc LF của repository.

`EXECUTION_LOCK.sha256` là khóa mở rộng mới; không sửa `LOCK.sha256` hoặc các freeze cũ.
Kiểm tra whitespace riêng phần mới vì `git diff --check` không xét file untracked. Giữ trailing
whitespace lịch sử trong handoff đã khóa. Không stage/commit thay đổi có sẵn của người dùng.

Không chạy full suite backend/frontend/experiments, hook commit/push hay CI trong lượt này;
không nhận các kiểm tra đó đã qua. Không chạy lại BenchmarkPython/wave A/B. Bước tiếp theo là
công bố bản khóa khi được yêu cầu, quét 7 snapshot khả dụng và rà nhãn theo protocol; 5 lượt
acquisition thất bại và giới hạn nhóm độc lập tiếp tục phải được báo cáo.
