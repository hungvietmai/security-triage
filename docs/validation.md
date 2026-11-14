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

**Chưa xác minh:**

- CI của nhánh `feat/research-safety-evidence` và `feat/cwe22-triage`, vì máy không có `gh`.
- Toàn stack Docker trên các commit ngày 27/10 (`2344e5b` đã được kiểm, xem bảng trên).
- Giao diện với đơn vị của profile `path-traversal-v0.2` trong trình duyệt thật: chỉ mới kiểm
  API trả `200` cho danh sách và chi tiết đơn vị.
- E2E Playwright ở máy cục bộ (chưa cài Chromium).

## 3. Lỗi đã biết

- **Script bị khóa trên Windows:** code chưa khóa đọc/ghi bằng UTF-8. Các script bị khóa (v0.3,
  owasp-bp-pilot, wave-c, `known_locations.py`, `patch_hunks.py`…) vẫn dùng bảng mã mặc định và
  không được sửa; trên Windows phải chạy chúng với `PYTHONUTF8=1`. Trên Linux (CI) không bị
  ảnh hưởng.
- **Cài lại `node_modules` trên Windows:** `npm ci` có thể lỗi `EPERM` nếu VS Code đang giữ
  native binding của oxlint. Khi đó đóng tiến trình đang giữ file, hoặc dùng `npm install`.

## 4. Lịch sử

Các mốc kiểm chứng trước 2026-10-08 (CI đầu tiên của nền ứng dụng, pilot curling, bộ dựng
review, chẩn đoán alias) được ghi theo ngày trong [RESEARCH_LOG.md](../experiments/RESEARCH_LOG.md)
và [experiments/reports/](../experiments/reports/). Số đo hiệu năng: [performance.md](performance.md).
