# Kiểm chứng

Kiểm chứng phần mềm và bằng chứng nghiên cứu là hai việc tách biệt. Test, hook và CI chỉ xác
nhận mã chạy đúng như thiết kế; chúng **không** chứng minh hiệu quả giảm FP. Phần nào của kết
quả nghiên cứu đã được phép kết luận: xem [research.md §4](research.md#4-những-gì-được-phép-kết-luận).

## 1. Các lớp kiểm tra

| Lớp | Nội dung | Cấu hình |
|---|---|---|
| `pre-commit` | Frontend: Prettier, oxlint, `tsc`. Backend: `ruff format`, `ruff check --fix`, `mypy` (chỉ file đã stage) | `.husky/`, `*/lint-staged.config.*` |
| `commit-msg` | Conventional Commits; chặn `Co-authored-by` và dòng ghi công AI | `commitlint.config.mjs` |
| `pre-push` | Toàn bộ test frontend (Vitest) và backend (pytest, ngưỡng coverage 90%) | `.husky/pre-push` |
| CI `experiments` | Toàn bộ test thực nghiệm (85 tại `8e99ecc`) | `.github/workflows/ci.yml` |
| CI `reconciliation-integration` | Build image thực nghiệm; chạy scanner thật và priority v0.1 trên curling (hai cấu hình), R1 và OWASP Python; kiểm tiêu chí chấp nhận của bộ gộp và chính sách | như trên |
| CI `scan-parity` | Quét curling qua CLI và qua API/worker; yêu cầu kết quả giống nhau | như trên |
| CI `frontend` | Lint, format, kiểu API sinh từ `openapi.json`, Vitest, build, E2E Playwright (HTTP giả) | như trên |
| CI `docker-integration` | Dựng toàn stack; test API trên PostgreSQL; ruff, mypy, pip-audit; migration hai chiều; `openapi.json` khớp API; phiên bản scanner và hash profile của worker; proxy, readiness, worker | như trên |
| `research-publication` | Kiểm 98 đầu vào của `EXECUTION_LOCK.sha256` khi file này thay đổi | `.github/workflows/research-publication.yml` |

Kiểm tra khóa nghiên cứu chạy bằng tay: xem
[experiments/README.md](../experiments/README.md#kiểm-tra-khóa).

## 2. Kết quả đã ghi nhận

Mỗi kết quả chỉ đúng cho commit và môi trường đã ghi. Chưa chạy lại thì không được coi là đạt.

| Ngày | Commit | Môi trường | Kết quả | Nguồn |
|---|---|---|---|---|
| 2026-10-07 | `4f2ed0b` | GitHub Actions, CI #115 (run `37567998891`) | Cả 4 job xanh; 206 test backend, coverage nhánh 91,38%; 33 test thực nghiệm; migration `0003 → base → head` | [RESEARCH_LOG.md](../experiments/RESEARCH_LOG.md) |
| 2026-10-21 | trước `8e99ecc` | Máy cục bộ | 85 test thực nghiệm; khóa execution (98 đầu vào), v0.3 (62), chọn mẫu (17), toolchain (1.628): mọi lệnh exit 0 | [study-001/checks.json](../experiments/wave-c/results/study-001/checks.json) |
| 2026-10-27 | `8e99ecc` | Windows, cục bộ | Thực nghiệm: 85 test, 1 lỗi `UnicodeEncodeError` do `run_pilot.py` ghi JSON bằng cp1252 (đạt cả 85 khi đặt `PYTHONUTF8=1`) | lần cập nhật tài liệu này |
| 2026-10-27 | `8e99ecc` | Windows, cục bộ | Khóa `wave-c/LOCK.sha256` (17 file), `EXECUTION_LOCK.sha256` (98 file) và chọn mẫu (12 repository) đạt. Khóa v0.3 `--metadata` không chạy được vì thiếu archive `artifacts/v03/` | lần cập nhật tài liệu này |
| 2026-10-27 | sau các commit sửa lỗi cùng ngày | Windows, cục bộ | Backend: **375 đạt, 2 bỏ qua** (SQLite, không đặt `TEST_DATABASE_URL`); ruff, format, mypy sạch | lần cập nhật tài liệu này |
| 2026-10-27 | sau các commit sửa lỗi cùng ngày | Windows, cục bộ | Thực nghiệm: **85 đạt**, không cần `PYTHONUTF8` | lần cập nhật tài liệu này |
| 2026-10-27 | sau các commit sửa lỗi cùng ngày | Windows, cục bộ | Frontend `npm run check`: typecheck, lint, format, **63 test / 13 file** đạt | lần cập nhật tài liệu này |
| 2026-11-14 | `2344e5b` (thêm profile `path-traversal-v0.2`; chạy trên working tree ngay trước khi commit) | Windows, cục bộ | Backend: **392 đạt, 2 bỏ qua** (SQLite), coverage nhánh 94,08%; ruff, format, mypy sạch. Thực nghiệm: **87 đạt** (`PYTHONUTF8=1`). Frontend `npm run check`: **64 test / 13 file** đạt. `openapi.json` khớp bản xuất từ backend | lần cập nhật tài liệu này |
| 2026-11-14 | như trên | Docker Compose, cục bộ | Service `test` trên PostgreSQL: **394 đạt**, coverage 94,26%. Stack dựng lại và healthy; `scripts.check_worker` trong worker nhận cả hai profile với Semgrep 1.178.0 và CodeQL 2.27.1; `alembic check` không lệch; readiness `ok` | lần cập nhật tài liệu này |
| 2026-11-14 | như trên | Docker Compose, cục bộ; quét thật qua API với profile `path-traversal-v0.2` | `pipecat-ai/pipecat@7519c26` (archive trùng SHA-256 với khóa đợt C): 73 giây, 3 đơn vị, cả 3 **P4** `EV_HIDDEN_BY_EVIDENCE`, khớp đợt C (baseline 3, v0.2 còn 0). `pallets-eco/flask-admin@4f8be45`: 15 giây, 3 đơn vị **P1** `EV_KEPT_NO_PROOF` ở dòng 151, 175, 182 của `fileadmin/__init__.py`, khớp đợt A (3 cảnh báo, v0.2 loại 0). Cả hai repository là dữ liệu phát triển đã quét trước đó | lần cập nhật tài liệu này |
| 2026-11-14 | working tree trên `1d581a6` (thêm profile `command-injection-v0.2`, Bandit và ESLint; chưa commit) | Windows, cục bộ | Backend: **426 đạt, 2 bỏ qua** (SQLite), coverage nhánh 94,36%; ruff, format, mypy sạch. Thực nghiệm: **88 đạt** (`PYTHONUTF8=1`). Frontend `npm run check`: **64 test / 13 file** đạt. `build_profile.py --check` sạch cho cả hai profile ưu tiên | lần cập nhật tài liệu này |
| 2026-11-14 | như trên | Docker Compose, cục bộ | Image worker dựng lại với Bandit 1.9.4, Node.js 24.22.3 và ESLint 10.15.0; mọi kiểm tra phiên bản trong `install-scanners.sh` đạt. Service `test` trên PostgreSQL: **428 đạt**, coverage 94,54%. `scripts.check_worker` nhận ba profile và bốn công cụ; `alembic check` không lệch | lần cập nhật tài liệu này |
| 2026-11-14 | như trên | Docker Compose, cục bộ; quét thật qua API với profile `command-injection-v0.2` | `curling@0.2.0`: `completed`, 1 đơn vị **P1** `D20_STRONG` tại `lib/curl-transport.js:56`, công cụ `codeql` và `eslint` cùng một đơn vị. `paperless-ngx@d4a5720`: `completed`, 6 đơn vị **P3** chỉ có Bandit (`subprocess.run`, `role_unresolved`). `OWASP-Benchmark/BenchmarkPython@f129148`: `completed` sau 57 giây, 24 đơn vị: 9 P1 (Bandit, Semgrep, CodeQL), 4 P2 (chỉ CodeQL), 5 P3 (Bandit, Semgrep), 6 P3 (chỉ Bandit). Đây là kiểm chứng công cụ chạy đúng trên dữ liệu phát triển, **không phải số liệu đánh giá**: chưa đối chiếu với nhãn | lần cập nhật tài liệu này |
| 2026-11-14 | như trên | Docker Compose, cục bộ; hồi quy profile `command-injection-v0.1` | `curling@0.2.0`: 1 đơn vị **P1** `D20_STRONG`, chỉ `codeql`, đúng kỳ vọng phát triển của priority v0.1 | lần cập nhật tài liệu này |
| 2026-11-14 | working tree trên `1d581a6` (thêm bước gạn `adjudicate-v0.1`, truy vấn bằng chứng CWE-78, migration `0007`, báo cáo trước–sau, SARIF hợp nhất; chưa commit) | Windows, cục bộ | Backend: **449 đạt, 2 bỏ qua** (SQLite), coverage nhánh 95%; ruff, format, mypy sạch. Thực nghiệm: **99 đạt** (`PYTHONUTF8=1`), gồm dựng lại mọi tệp `experiments/evaluation/results/` từ `inputs/`. Frontend `npm run check`: **67 test / 14 file** đạt. E2E Playwright với HTTP giả (Chromium): **2 đạt**. `build_profile.py --check` sạch; `openapi.json` khớp bản xuất | lần cập nhật tài liệu này |
| 2026-11-14 | như trên | Docker Compose, cục bộ | Service `test` trên PostgreSQL: **451 đạt**, coverage 94,67%. Migration: trên một database tạm, `upgrade head` → `downgrade base` → `upgrade head` → `alembic check` không lệch; database tạm đã xóa. `scripts.check_worker` nhận ba profile và bốn công cụ | lần cập nhật tài liệu này |
| 2026-11-14 | như trên | Docker Compose, cục bộ; 15 lượt quét thật qua API (dữ liệu phát triển) | Cả 15 lượt `completed`; báo cáo và SARIF xuất được lưu ở `experiments/evaluation/inputs/` kèm SHA-256. OWASP BenchmarkPython, `command-injection-v0.2`: 51 cảnh báo → 24 đơn vị → 20 ứng viên → 18 trong danh sách rà chính, 2 đã gạn (G1), 7 chỉ hạ ưu tiên. `pipecat` CWE-22: 3 ứng viên, cả 3 đã gạn; `flask-admin` CWE-22: 3 ứng viên, giữ cả 3. Số liệu đánh giá: [thesis/chapter-3-results.md](thesis/chapter-3-results.md) | [experiments/evaluation/](../experiments/evaluation/README.md) |
| 2026-11-14 | như trên | Toàn stack thật, Chromium qua Playwright trên máy chủ, `http://localhost:5173` | [adjudication-demo.mjs](demo/adjudication-demo.mjs) qua mọi bước kiểm: ba công cụ báo một lời gọi thành một đơn vị; lời gọi chỉ Bandit báo được giữ kèm lý do; danh sách "Đã gạn" có 2 đơn vị, mở lại được cùng cảnh báo gốc và bằng chứng; báo cáo trước–sau hiển thị 51/20/18/2; tệp JSON và SARIF tải về đúng (SARIF giữ 51 cảnh báo, 6 mang `suppressions`); danh sách đã chọn còn nguyên sau khi tải lại trang; 3 cảnh báo CWE-22 của pipecat nằm ở "Đã gạn" | [demo/README.md](demo/README.md) |
| 2026-11-14 | working tree trên `1d581a6` (thêm quy tắc gạn G3 dùng luật nhánh chết của Semgrep CE, `adjudicate-v0.2`; chưa commit). **Các dòng dưới thay cho bốn dòng ngay trên về số liệu** | Windows, cục bộ | Backend: **460 đạt, 2 bỏ qua** (SQLite), coverage nhánh 95%; ruff, format, mypy sạch. Thực nghiệm: **103 đạt** (`PYTHONUTF8=1`). Frontend `npm run check`: **67 test / 14 file** đạt; E2E Playwright với HTTP giả: **2 đạt**. `build_profile.py --check` sạch; `openapi.json` khớp bản xuất | lần cập nhật tài liệu này |
| 2026-11-14 | như trên | Docker Compose, cục bộ | Service `test` trên PostgreSQL: **462 đạt**, coverage 94,85%; `alembic check` không lệch. Trong image worker, [check.py](../rules/semgrep/command-injection-evidence-v0.1/tests/check.py) với Semgrep 1.178.0 thật: **13/13 ca** đúng kỳ vọng (4 ca bị bác bỏ, 9 ca phải giữ) | lần cập nhật tài liệu này |
| 2026-11-14 | như trên, manifest profile `6993df05…` | Docker Compose, cục bộ; 15 lượt quét thật (dữ liệu phát triển) thu lại bằng image cuối | Cả 15 `completed`. OWASP BenchmarkPython: 51 cảnh báo → 20 ứng viên → 18 trong danh sách chính, 2 đã gạn: `01097` thỏa G3 (Semgrep) và G1 (CodeQL), `01098` thỏa G1. Kịch bản [adjudication-demo.mjs](demo/adjudication-demo.mjs) chạy lại trên các lượt này: qua mọi bước kiểm | [experiments/evaluation/](../experiments/evaluation/README.md) |
| 2026-11-14 | như trên, cùng manifest | Docker Compose, cục bộ; kiểm tra độc lập, mỗi nguồn quét một lần sau khi băm giao thức (13:59 UTC) | `appsecco/dvna`, `stamparm/DSVW`, `snyk-labs/nodejs-goof`: cả ba `completed`; 3/3 vị trí lỗi đã công bố được báo, 0 bị gạn, 2 ở P1 và 1 ở P3. Không tệp nào trong `PREREGISTRATION.json` thay đổi sau khi quét | [independent/](../experiments/evaluation/independent/PROTOCOL.md) |
| 2026-11-14 | như trên, cùng manifest | Docker Compose, cục bộ; kiểm tra độc lập đợt 2, mỗi nguồn quét một lần sau khi băm giao thức (14:22 UTC) | 52 package npm của SecBench.js ngoài inventory đã khóa: **43 `completed`, 3 `partial`** (ESLint không phân tích được một tệp), **6 `failed`** (4: phiên bản không còn trên npm; 2: lỗi `\r\n` của worker, xem mục 4). Trên 43 lượt hoàn tất: hợp mọi nguồn báo 32 vị trí lỗi đã công bố, CodeQL riêng 27, ESLint riêng 27, Semgrep riêng 12; 0 bị gạn. Script chấm đã băm dừng ở một trường chẩn đoán và được sửa một dòng sau khi quét; sai lệch ghi ở [DEVIATIONS.md](../experiments/evaluation/independent-secbench/DEVIATIONS.md) | [independent-secbench/](../experiments/evaluation/independent-secbench/PROTOCOL.md) |
| 2026-11-14 | như trên, cùng manifest | Docker Compose, cục bộ; kiểm tra độc lập đợt 3, băm lúc 14:30 UTC, quét sau khi đợt 2 xong | Ba ứng dụng Python: cả ba `completed`; 6/6 vị trí được báo, 0 bị gạn, 5 ở P1 và 1 ở P2. Ở 4 vị trí truy vấn bằng chứng CodeQL đã xét luồng và giữ ứng viên (`evidence_query_still_reports_flow`). Kết quả chấm bằng script đã băm và bằng script sau khi sửa trùng từng byte | [independent-python/](../experiments/evaluation/independent-python/PROTOCOL.md) |
| 2026-11-14 | working tree trên `1d581a6` (thêm sửa lỗi `\r\n` trong `acquisition.py`, hai đợt kiểm tra độc lập, bộ chấm `pairs-v1`, bản thảo ba chương; chưa commit) | Windows, cục bộ | Backend: **461 đạt, 2 bỏ qua** (SQLite), coverage nhánh 94,69%; ruff, format, mypy sạch. Thực nghiệm: **113 đạt** (`PYTHONUTF8=1`). `build_profile.py --check` và `build_labels.py --check` sạch. Frontend (không đổi) `npm run check`: **67 test / 14 file** đạt; E2E Playwright không chạy lại | lần cập nhật tài liệu này |
| 2026-11-14 | như trên | Docker Compose, cục bộ | Service `test` trên PostgreSQL: **463 đạt**, coverage 94,85%. Image worker dựng lại với bản sửa; quét lại hai nguồn từng lỗi (ngoài bảng đã đăng ký): `ts-process-promises@1.0.2` `completed`, vị trí lỗi được báo ở P2; `buns@1.1.6` `partial`, vị trí lỗi không được báo | [posthoc-after-fix/](../experiments/evaluation/independent-secbench/posthoc-after-fix/result.json) |
| 2026-11-14 | như trên, cùng manifest; worker đã có bản sửa `\r\n` | Docker Compose, cục bộ; kiểm tra độc lập đợt 4, băm lúc 15:08 UTC, một lượt quét | `semgrep/semgrep-rules@a84ff9c`: **`failed`**, `SyntaxError … (python37.py, line 13)`: một tệp Python sai cú pháp làm bộ định vị lời gọi dừng cả lượt quét (xem mục 4). Không có ứng viên; kết quả đã đăng ký là TP = 0 trên 135 vị trí có lỗi | [independent-labeled/DEVIATIONS.md](../experiments/evaluation/independent-labeled/DEVIATIONS.md) |
| 2026-11-14 | working tree trên `1d581a6` (thêm sửa lỗi bộ định vị Python trong `analysis.py`, đợt 4, đối chiếu tài liệu tham khảo; chưa commit) | Windows, cục bộ | Backend: **462 đạt, 2 bỏ qua** (SQLite), coverage nhánh 94,71%; ruff, format, mypy sạch. Thực nghiệm: **120 đạt** (`PYTHONUTF8=1`) | lần cập nhật tài liệu này |
| 2026-11-14 | như trên | Docker Compose, cục bộ | Service `test` trên PostgreSQL: **464 đạt**, coverage 94,87%. Image worker dựng lại; quét lại `semgrep-rules` một lần (ngoài kết quả đã đăng ký): `partial` (bước định vị Python bỏ qua tệp sai cú pháp; CodeQL JavaScript chạy dở), 552 cảnh báo → 345 ứng viên, 0 đã gạn. Tệp nén được quét trùng SHA-256 với tệp dùng để dựng nhãn. Trên 210 vị trí có nhãn: hợp mọi nguồn P 0,66 / R 0,71 / F1 0,69 | [results/posthoc-after-fix.json](../experiments/evaluation/independent-labeled/results/posthoc-after-fix.json) |
| 2026-11-14 | như trên, cùng manifest; worker có cả hai bản sửa của ngày này | Docker Compose, cục bộ; kiểm tra độc lập đợt 5, băm lúc 15:25 UTC, mỗi nguồn quét một lần | 20 công cụ dòng lệnh Python chọn bằng một truy vấn tìm kiếm cố định: **18 `completed`, 1 `partial`, 1 `failed`** (ứng dụng từ chối tệp nén có mục `bin/bash` không an toàn). Ở 18 lượt hoàn tất: 145 ứng viên, **19 đã gạn**, tất cả theo G2; lượt `partial` không gạn gì. Đây là lần đầu quy tắc G2 gạn ứng viên trên lượt quét thật | [independent-filter/READING.md](../experiments/evaluation/independent-filter/READING.md) |
| 2026-11-15 | như trên; không đổi mã | Windows, cục bộ | Phép kiểm độc lập đã đăng ký trên 19 ứng viên bị gạn (đọc tệp ở commit đã ghim): 17 `constant_command`, 2 `not_constant`. Đọc lại hai ca sau: lệnh là chuỗi hằng bọc trong `int()`/`bool()`; phép kiểm viết trước đã xét cả lời gọi bọc ngoài. Thực nghiệm: **126 đạt** (`PYTHONUTF8=1`) | lần cập nhật tài liệu này |
| 2026-11-15 | `f1e7c0c` (Amendment 06, cấu hình v0.2 đóng băng) | Docker Compose, cục bộ; tập phát triển của `pairs-v1`, mỗi cặp quét bản có lỗi một lần | 34 lượt: **30 `completed`, 4 `partial`**; cả 34 nguồn có đúng SHA-256 đã khóa; `freeze.py check` không đổi sau lượt cuối. Hợp mọi nguồn báo 21/22 vị trí đã biết ở lượt hoàn tất, 0 bị gạn. 71 ứng viên chưa có nhãn bị gạn theo G2, cả 71 được phép kiểm độc lập xác nhận là lệnh hằng. Kết quả commit ở `bb1eaac`; **tập giữ lại chưa quét** | [pairs-v1/](../experiments/evaluation/pairs-v1/README.md) |
| 2026-11-15 | working tree trên `bb1eaac` (profile `command-injection-v0.3`: phạm vi tệp Semgrep, bộ định vị v1, quy tắc G4; chưa commit) | Windows, cục bộ | Backend: **483 đạt, 2 bỏ qua** (SQLite), coverage nhánh 94,60%; ruff, format, mypy sạch. Thực nghiệm: **138 đạt** (`PYTHONUTF8=1`). Frontend `npm run check`: **67 test / 14 file** đạt; E2E Playwright với HTTP giả: **2 đạt**. `build_profile.py --check` sạch (v0.2 không đổi); `openapi.json` xuất lại | lần cập nhật tài liệu này |
| 2026-11-15 | như trên | Docker Compose, cục bộ | Service `test` trên PostgreSQL: **485 đạt**, coverage 94,75%. Trong image worker với Semgrep 1.178.0 thật: bộ định vị v1 **19/19 ca**, luật bằng chứng lệnh hằng **20/20 ca**. 84 package npm quét lại bằng v0.3 (cùng một manifest `1b3b824a…`): 78 `completed`, 6 `partial`; hàng U 37 → 14 ứng viên, 23 cảnh báo gộp thêm, 0 ghép nhầm; 1 ứng viên bị gạn theo G4. Nhãn đối chứng độc lập (`espree`, 19/19 ca tổng hợp) trên 120 ứng viên gọi `exec`/`execSync`: 1 lệnh hằng, G4 gạn đúng 1/1 và gạn nhầm 0/116 | [js-matching-v0.3/](../experiments/evaluation/js-matching-v0.3/READING.md) |
| 2026-11-15 | như trên | Toàn stack thật, Chromium qua Playwright trên máy chủ, `http://localhost:5173` | [js-matching-demo.mjs](demo/js-matching-demo.mjs): qua mọi bước. `kill-process-by-name`: hai lời gọi, mỗi lời gọi gộp cảnh báo của CodeQL và ESLint, ở danh sách rà chính. `arpping`: một ứng viên ở "Đã gạn" với quy tắc G4, bằng chứng và cảnh báo gốc. Lần chạy đầu thất bại vì container frontend còn giữ địa chỉ cũ của API (502); chạy lại sau khi dựng lại frontend | [demo/README.md](demo/README.md) |
| 2026-11-15 | `3feb328` | Docker Compose, cục bộ; quét lại `semgrep/semgrep-rules@a84ff9c` bằng profile `command-injection-v0.3` (dữ liệu phát triển) | `partial` (bước định vị Python bỏ qua tệp sai cú pháp; CodeQL JavaScript chạy dở), 552 cảnh báo → 335 ứng viên, 0 đã gạn. 25 vị trí JavaScript có nhãn, hợp mọi nguồn: v0.2 TP 6, FP 0 (F1 0,57) → v0.3 TP 12, FP 2 (F1 0,83); 185 vị trí Python không đổi | [independent-labeled/DEVIATIONS.md](../experiments/evaluation/independent-labeled/DEVIATIONS.md) |
| 2026-11-15 | `9150679` → `b06553e` | Docker Compose, cục bộ; chạy thử `command-injection-v0.3` trên 9 cặp Python của tập phát triển `pairs-v1` (Amendment 08) | 7 `completed`, 2 `partial`, 0 `failed`; cả 9 nguồn đúng SHA-256 đã khóa; 5 vị trí lỗi đã biết được báo như ở v0.2, 0 bị gạn. `freeze.py write`: 48 tệp; commit `b06553e` | [pairs-v1/](../experiments/evaluation/pairs-v1/README.md) |
| 2026-11-15 | `1158f71` (bản ghi `freeze.py gate`: mọi tệp đóng băng không đổi tại `b06553e`) | Docker Compose, cục bộ; **tập giữ lại của `pairs-v1`**, mỗi cặp quét bản có lỗi một lần bằng `command-injection-v0.3` | 16 lượt: **12 `completed`, 4 `partial`, 0 `failed`**; cả 16 nguồn đúng SHA-256 đã khóa; `freeze.py check` không đổi sau lượt cuối. Hợp mọi nguồn báo **7/7** vị trí lỗi đã biết ở lượt hoàn tất (CodeQL riêng 6, Semgrep riêng 3, ESLint riêng 4) và **9/9** tính cả lượt chạy dở; 0 bị gạn; 6/7 ở P1+P2; 156 ứng viên chưa có nhãn, 0 đã gạn. Thực nghiệm sau đó: 141 kiểm thử đạt | [held_out/result.json](../experiments/evaluation/pairs-v1/held_out/result.json) |
| 2026-11-15 | working tree trên `e5e454f` | Không quét; chấm đầu ra v0.3 đã lưu của 84 package npm bằng nhãn ứng viên JavaScript (62 nhãn CVE, 78 nhãn do trợ lý AI gán, chưa được người kiểm) | 140 đơn vị: 109 có lỗi, 14 an toàn, 17 chưa xác định. Hợp mọi nguồn: TP 109, FP 14, độ chính xác 0,89; sau gạn FP 13; 0 ứng viên có lỗi bị gạn. `score_labels.py` sửa một khóa sắp xếp sau lần chạy đầu (ghi trong README). Thực nghiệm: 147 kiểm thử đạt | [js-labels-v0.3/](../experiments/evaluation/js-labels-v0.3/README.md) |
| 2026-11-15 | working tree trên `0b37bb8` | Không quét; chủ đề án rà từng ca 31 nhãn JavaScript (mọi nhãn an toàn và chưa xác định) kèm đoạn mã, sửa 12; chấm lại đầu ra v0.3 đã lưu | 140 đơn vị: 116 có lỗi, 11 an toàn, 13 chưa xác định. Hợp mọi nguồn: TP 116, FP 11, độ chính xác 0,91; sau gạn FP 10; 0 ứng viên có lỗi bị gạn. 47 nhãn "có lỗi" chưa được người kiểm. Thực nghiệm: 148 kiểm thử đạt | [js-labels-v0.3/](../experiments/evaluation/js-labels-v0.3/README.md) |
| 2026-11-15 | working tree trên `9442486` | Không quét; chủ đề án rà 47 nhãn JavaScript "có lỗi" trong tệp rà (đồng ý 44; 3 ca quyết định sau khi đối chiếu dòng bắt đầu của cảnh báo trong báo cáo đã lưu, một ca tách thành bảy đơn vị); chấm lại đầu ra v0.3 đã lưu | Cả 84 nhãn có bản ghi rà. 146 đơn vị: 122 có lỗi, 11 an toàn, 13 chưa xác định. Hợp mọi nguồn: TP 122, FP 11, độ chính xác 0,92; sau gạn FP 10; 0 ứng viên có lỗi bị gạn. Thực nghiệm: 149 kiểm thử đạt | [js-labels-v0.3/](../experiments/evaluation/js-labels-v0.3/README.md) |

**Chưa xác minh:**

- CI của nhánh `feat/research-safety-evidence` và `feat/cwe22-triage`, vì máy không có `gh`.
- Toàn stack Docker trên các commit ngày 27/10 (`2344e5b` đã được kiểm, xem bảng trên).
- Image `experiments/Dockerfile` và các job CI dùng nó sau khi `install-scanners.sh` cài thêm
  Bandit, Node.js và ESLint: chưa dựng lại ở máy cục bộ.
- Bước truy vấn bằng chứng thất bại trên lượt quét thật: mới có test. (Lượt quét chạy dở đã gặp
  trên lượt quét thật ngày 2026-11-14: không ứng viên nào bị gạn, đúng thiết kế.)
- Quy tắc gạn G1 và G3 trên dữ liệu độc lập: chưa có lượt quét độc lập nào có ứng viên đủ bằng
  chứng cho hai quy tắc này. (G2 đã gạn 19 ứng viên trên lượt quét thật ngày 2026-11-14.)

## 3. Lỗi đã biết

- **Script bị khóa trên Windows:** code chưa khóa đọc/ghi bằng UTF-8. Các script bị khóa (v0.3,
  owasp-bp-pilot, wave-c, `known_locations.py`, `patch_hunks.py`…) vẫn dùng bảng mã mặc định và
  không được sửa; trên Windows phải chạy chúng với `PYTHONUTF8=1`. Trên Linux (CI) không bị
  ảnh hưởng.
- **Cài lại `node_modules` trên Windows:** `npm ci` có thể lỗi `EPERM` nếu VS Code đang giữ
  native binding của oxlint. Khi đó đóng tiến trình đang giữ file, hoặc dùng `npm install`.
- **Bộ định vị lời gọi JavaScript bỏ qua một số cách khai báo `child_process`** (phát hiện
  2026-11-14; sửa trong profile `command-injection-v0.3` ngày 2026-11-15, profile v0.1 và v0.2
  giữ nguyên hành vi cũ). Ví dụ `var exec = childProcess.exec; exec(...)` trong
  `kill-process-by-name@1.0.5` và `child_process.exec(...)` trong `umount@1.1.6`: luật
  `sink-locator-v0` không định vị lời gọi, nên cảnh báo đúng dòng lỗi của CodeQL và ESLint
  thành ứng viên `unmatched_location` ở hàng U thay vì được gộp. Trên đợt kiểm tra độc lập
  thứ hai có 4 ca trong 43 lượt quét hoàn tất. Sửa cần phiên bản bộ định vị và profile mới.
- **Thông báo lỗi khi phiên bản npm không tồn tại** (phát hiện 2026-11-14, chưa sửa): registry
  trả `"version not found"`, lượt quét thất bại đúng nhưng ghi `Malformed registry metadata`.

- **Mã bị quét quyết định được phạm vi tệp của Semgrep** (phát hiện 2026-11-15). Một tệp
  `.semgrepignore` trong mã bị quét, kể cả ở thư mục con, làm Semgrep bỏ qua tệp tùy ý; khi
  không có tệp đó Semgrep tự bỏ qua `build/`, `dist/`, `test/`… Ảnh hưởng luật phát hiện, luật
  định vị và luật bằng chứng. **Đã sửa cùng ngày cho mọi profile:** worker xóa các tệp
  `.semgrepignore` do mã bị quét mang theo trước khi chạy công cụ. Profile
  `command-injection-v0.3` còn ghi tệp của riêng worker; các profile khác giữ phạm vi mặc định
  của Semgrep (vẫn bỏ qua `build/`, `dist/`, `test/`…), nên kết quả của chúng chỉ đổi với
  nguồn có mang tệp đó. Có kiểm thử; đã thử trong worker với Semgrep 1.178.0 trên `kill-process-by-name@1.0.5` có kèm một tệp `.semgrepignore` chứa `*.js`: trước khi xóa, luật định vị thấy 0 lời gọi; sau khi xóa, 2 lời gọi. Backend sau bản sửa: 484 đạt (SQLite), 486 đạt (Docker/PostgreSQL).

## 4. Lỗi đã sửa

- **CodeQL không trích xuất được kho có TypeScript (sửa 2026-11-14).** Bộ trích xuất JavaScript
  của CodeQL gọi `node` trên PATH để đọc file `.ts`; image worker trước đó không có Node.js, nên
  bước tạo database thất bại với mọi kho có file TypeScript, ở mọi profile. Phát hiện khi quét
  `paperless-ngx@d4a5720` ("Could not start Node.js. It is required for TypeScript
  extraction"). `install-scanners.sh` nay đưa Node.js đã ghim lên PATH; quét lại cùng commit cho
  `completed` ở cả hai ngôn ngữ. Lượt quét JavaScript thuần (như `curling`) không bị ảnh hưởng.

- **Tệp nguồn có `\r\n` làm hỏng lượt quét JavaScript (sửa 2026-11-14).** Worker đọc tệp nguồn ở
  chế độ văn bản, nên `\r\n` thành `\n` và vị trí byte do luật định vị của Semgrep trả về bị
  lệch. Bộ định vị cắt sai đoạn mã và dừng với `Located JavaScript sink is not a call
  expression`, làm cả lượt quét `failed`; khi đoạn cắt sai tình cờ vẫn chứa dấu `(`, đối số
  của lời gọi bị ghi sai mà không báo lỗi. Phát hiện ở `buns@1.1.6` và
  `ts-process-promises@1.0.2` của đợt kiểm tra độc lập thứ hai. `load_source_texts` nay giữ
  nguyên ký tự xuống dòng; có kiểm thử hồi quy với tệp `\r\n`. Các lượt quét đã lưu trước đó
  của kho có tệp `\r\n` có thể mang vùng đối số sai và không được quét lại.

- **Một tệp Python sai cú pháp làm hỏng cả lượt quét (sửa 2026-11-14).** Bộ định vị lời gọi
  Python gọi `ast.parse` cho từng tệp và không bắt `SyntaxError`, nên một tệp viết cho Python 2
  hoặc cố ý sai cú pháp làm lượt quét `failed`. Phát hiện ở lượt quét đã đăng ký của đợt kiểm
  tra độc lập thứ tư (`semgrep-rules`). Nay tệp đó bị bỏ qua ở bước định vị, bước ghi `partial`
  kèm số tệp, lượt quét của ngôn ngữ thành `partial` và bước gạn không gạn gì
  (`run_incomplete`); cảnh báo trong tệp đó thành ứng viên `unmatched_location`. Có kiểm thử hồi
  quy. Hệ quả cần biết: một tệp không phân tích được tắt bước gạn của cả lượt quét.

## 5. Lịch sử

Các mốc kiểm chứng trước 2026-10-08 (CI đầu tiên của nền ứng dụng, pilot curling, bộ dựng
review, chẩn đoán alias) được ghi theo ngày trong [RESEARCH_LOG.md](../experiments/RESEARCH_LOG.md)
và [experiments/reports/](../experiments/reports/). Số đo hiệu năng: [performance.md](performance.md).
