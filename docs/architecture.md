# Kiến trúc ứng dụng

Mô tả ứng dụng web như đã cài đặt, cập nhật ngày 2026-10-27. Trạng thái và kết quả nghiên cứu
nằm ở [research.md](research.md); cách chạy stack nằm ở [README](../README.md).

## 1. Ứng dụng làm gì

Người dùng tạo dự án, rồi yêu cầu quét **một package npm theo version chính xác** hoặc
**một commit GitHub** (40 ký tự). Worker tải mã nguồn và chạy Semgrep cùng CodeQL theo một
scan profile đã ghim hash. Sau đó worker gộp cảnh báo theo vị trí sink và xếp mỗi đơn vị
vào một mức ưu tiên rà soát. Giao diện hiển thị trạng thái lượt quét, hàng đợi P1→P4 và
bằng chứng của từng đơn vị.

Người dùng chọn một trong hai profile khi tạo lượt quét:

| Profile | Phạm vi | Cách xếp hàng đợi |
|---|---|---|
| `command-injection-v0.1` (mặc định) | CWE-78; JavaScript và Python; Semgrep và CodeQL | Gộp cảnh báo theo sink, xếp P1–P4/U theo chính sách ưu tiên v0.1 |
| `path-traversal-v0.2` | CWE-22; Python; chỉ CodeQL | Cảnh báo của truy vấn baseline. Nếu truy vấn có bằng chứng an toàn v0.2 vẫn báo thì ở **P1**; nếu bằng chứng đã loại mọi luồng thì xuống **P4**. Không xóa cảnh báo nào |

Profile `path-traversal-v0.2` dùng đúng pack đã đánh giá trong nghiên cứu
([rules/codeql/path-traversal-v0.2/](../rules/codeql/path-traversal-v0.2/README.md)), trùng từng
byte với bản đóng băng. v0.3 chưa được tích hợp.

## 2. Thành phần

| Service (Compose) | Vai trò |
|---|---|
| `frontend` | React + TypeScript, phục vụ bằng Nginx; chuyển `/api` vào FastAPI |
| `api` | FastAPI; ghi trạng thái rồi trả ngay, không chạy việc dài trong request |
| `worker` | Celery; image riêng cài Semgrep và CodeQL theo [tools/pins.env](../tools/pins.env) |
| `postgres` | Metadata, cảnh báo đã chuẩn hóa, đơn vị, đánh giá, provenance |
| `redis` | Broker của Celery |
| `seaweedfs` | Object store S3: archive mã nguồn, SARIF thô, log, artifact |
| `migrate`, `storage-init` | Chạy một lần: Alembic upgrade và tạo bucket |
| `test` (profile `test`) | Chạy pytest/ruff/mypy/pip-audit trong container |

Mọi cổng chỉ bind `127.0.0.1`. Ứng dụng dành cho **một người dùng cục bộ, không có đăng nhập**.

## 3. Luồng một lượt quét

1. `POST /api/v1/projects/{id}/scans` nhận `{"source": {"kind": "npm", …}}` hoặc
   `{"kind": "github", …}`. Server tự dựng URL tới `registry.npmjs.org` hoặc
   `codeload.github.com` và không theo redirect. API tạo bản ghi snapshot và scan, đẩy task
   `run_scan` vào hàng đợi, rồi trả `202`.
2. **Thu nhận nguồn** (`workflows/scans/snapshots.py`):
   - Với npm, tarball được kiểm bằng `dist.integrity` của registry (provenance `publisher_verified`).
   - Với GitHub, archive theo commit được tin ở lần tải đầu (`tofu`).
   - Archive được lưu vào S3 để các lần quét lại dùng đúng các byte đó.
   - Khi giải nén: tối đa 50 MiB tải về, 200 MiB giải nén, 20.000 mục. Từ chối path traversal
     và symlink trỏ ra ngoài; symlink trỏ vào trong archive thì bỏ qua.
3. **Quét** (`workflows/scans/analysis.py`, `app/scanners/`):
   - Lúc khởi động, worker kiểm hash của mọi file trong mọi profile và phiên bản scanner;
     sai lệch thì từ chối chạy. Mỗi lượt quét nạp lại profile mà nó đã chọn.
   - Các ngôn ngữ chạy tuần tự. Trong một ngôn ngữ, Semgrep và CodeQL có thể chạy song song
     (`SCANNER_WORKERS`, mặc định 2).
4. **Thẩm định** (`app/triage/`), theo loại profile:
   - **Profile ưu tiên** (`command-injection-v0.1`):
     - định vị sink bằng AST;
     - `reconcile-v0.1` gộp cảnh báo thành đơn vị theo `snapshot + đường dẫn + sink + vai trò
       đối số` (CWE không nằm trong khóa);
     - `priority v0.1` gán P1–P4 hoặc U kèm mã quyết định và lý do.
   - **Profile bằng chứng an toàn** (`path-traversal-v0.2`, `app/triage/safety_evidence.py`):
     - mỗi vị trí cảnh báo của truy vấn baseline là một đơn vị;
     - so với truy vấn có bằng chứng: còn báo thì P1, không còn thì P4;
     - truy vấn bằng chứng báo ở vị trí ngoài baseline là lỗi, và lượt quét thất bại;
     - lượt quét chạy dở (`partial`) không xếp hạng gì, để tránh hiển thị cảnh báo đang giữ
       thành cảnh báo bị ẩn.
   - Mức ưu tiên **không xóa cảnh báo** và không phải nhãn đúng/sai.
5. **Lưu** (`workflows/scans/persist.py`): kết quả của lượt quét được thay trong một
   transaction. Artifact được upload song song (`ARTIFACT_UPLOAD_WORKERS`, mặc định 4) dưới
   `scans/{scan_id}/…`, kèm SHA-256.
6. **Đọc kết quả:** `GET /api/v1/scans/{id}`, `/scans/{id}/units` (có phân trang, lọc theo
   công cụ) và `/scans/{id}/units/{unit_id}` (bằng chứng đầy đủ, gồm vết luồng dữ liệu).

Lõi quét (`app/scanners`) và lõi thẩm định (`app/triage`) được dùng chung với CLI thực nghiệm
[run_pilot.py](../experiments/run_pilot.py). Job CI `scan-parity` quét `curling@0.2.0` qua cả
hai đường và yêu cầu kết quả giống nhau.

## 4. Dữ liệu

| Bảng | Nội dung |
|---|---|
| `projects` | Dự án |
| `source_snapshots` | Archive bất biến: tọa độ nguồn, SHA-256, provenance |
| `scans` | Trạng thái lượt quét, phiên bản scanner/profile, artifact |
| `tool_runs` | Một lần chạy của một công cụ cho một ngôn ngữ |
| `findings` | Cảnh báo thô đã chuẩn hóa, giữ nguyên `raw_result` |
| `location_units`, `unit_findings` | Đơn vị vị trí và liên kết tới cảnh báo |
| `unit_assessments` | Mức ưu tiên, quyết định, lý do và hash của chính sách |

Migration nằm ở `backend/migrations/versions/` (0001–0006) và không được sửa sau khi merge.
Xóa theo cascade: project → snapshot → scan → tool_run → finding.

## 5. API

| Phương thức | Đường dẫn (tiền tố `/api/v1`) | Ghi chú |
|---|---|---|
| GET | `/health/live`, `/health/ready` | Readiness kiểm PostgreSQL/schema, Redis và S3 |
| POST, GET | `/projects` | Tạo; liệt kê có phân trang, sắp xếp, tìm kiếm |
| GET | `/projects/{id}` | Chi tiết dự án |
| POST | `/projects/{id}/scans` | Tạo lượt quét npm hoặc GitHub |
| GET | `/scans/{id}`, `/scans/{id}/units`, `/scans/{id}/units/{unit_id}` | Trạng thái, hàng đợi, bằng chứng |

Hợp đồng HTTP nằm trong [frontend/openapi.json](../frontend/openapi.json). Kiểu dữ liệu
TypeScript được sinh từ file này, và CI kiểm tra hai bên khớp nhau.

## 6. Giao diện

Các trang:

- Tổng quan;
- Dự án (danh sách và chi tiết có tab);
- Lượt quét (hướng dẫn tạo từ dự án);
- Chi tiết lượt quét (trạng thái tự làm mới, hàng đợi theo mức, bảng bằng chứng);
- Cảnh báo, Hệ thống, 404.

Tính năng mà backend chưa hỗ trợ được ghi rõ là "Chưa triển khai"; giao diện không hiển thị
dữ liệu mẫu hay kết quả giả. Cấu trúc và quy tắc của frontend: [frontend/AGENTS.md](../frontend/AGENTS.md).

## 7. Chưa có

- Upload archive hoặc thư mục từ máy người dùng.
- API liệt kê mọi lượt quét, và trang cảnh báo tổng hợp toàn hệ thống.
- Với profile CWE-22: hiển thị bảng bằng chứng (`Evidence.ql`: cơ chế, guard, dòng mã), quy
  trình rà theo phiếu và v0.3.
- Đăng nhập, phân quyền, TLS, quản lý secret, hạn mức tài nguyên và worker quét cô lập.
  Đây là điều kiện bắt buộc trước mọi triển khai dùng chung.

Docker không làm cho việc quét mã nguồn tùy ý trở nên an toàn. Ứng dụng không bao giờ thực thi
mã nguồn được quét hay cài dependency của nó.

## 8. Lưu trữ

- **PostgreSQL:** metadata, cảnh báo đã chuẩn hóa, trạng thái, provenance.
- **SeaweedFS:** archive mã nguồn, SARIF thô, log, manifest.
- **Thư mục tạm của worker:** mã nguồn đã giải nén và CodeQL database; xóa sau mỗi lượt quét.
- **Git:** mã nguồn, rule/query, migration, manifest và fixture nhỏ. Không commit mã nguồn
  người dùng, dữ liệu object store hay CodeQL database.

Số đo hiệu năng của bộ gộp, truy vấn và upload: [performance.md](performance.md).
