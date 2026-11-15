# Kiến trúc ứng dụng

Mô tả ứng dụng web như đã cài đặt, cập nhật ngày 2026-10-27. Trạng thái và kết quả nghiên cứu
nằm ở [research.md](research.md); cách chạy stack nằm ở [README](../README.md).

## 1. Ứng dụng làm gì

Người dùng tạo dự án, rồi yêu cầu quét **một package npm theo version chính xác** hoặc
**một commit GitHub** (40 ký tự). Worker tải mã nguồn và chạy các công cụ quét theo một
scan profile đã ghim hash. Sau đó worker gộp cảnh báo theo vị trí sink và xếp mỗi đơn vị
vào một mức ưu tiên rà soát. Bước thẩm định gộp các đơn vị cùng một lời gọi thành một ứng
viên rà soát và gạn những ứng viên có bằng chứng cụ thể là cảnh báo sai. Giao diện hiển thị
trạng thái lượt quét, danh sách rà chính và danh sách đã gạn theo hàng đợi P1→P4, bằng chứng
của từng đơn vị và báo cáo trước–sau.

Người dùng chọn một trong bốn profile khi tạo lượt quét:

| Profile | Phạm vi | Cách xếp hàng đợi |
|---|---|---|
| `command-injection-v0.1` (mặc định) | CWE-78; JavaScript và Python; Semgrep và CodeQL | Gộp cảnh báo theo sink, xếp P1–P4/U theo chính sách ưu tiên v0.1 |
| `command-injection-v0.2` | CWE-78; JavaScript/TypeScript và Python. Sàng lọc: Semgrep cùng Bandit (Python) hoặc ESLint với eslint-plugin-security (JavaScript/TypeScript). Thẩm định: CodeQL | Như v0.1, theo chính sách ưu tiên v0.2: "đồng thuận" là CodeQL cùng ít nhất một công cụ sàng lọc. **Chưa được đánh giá** |
| `command-injection-v0.3` | Như v0.2 | Như v0.2, với ba điểm khác: worker quyết định phạm vi tệp của Semgrep (mã bị quét không tự ẩn tệp được); bộ định vị lời gọi JavaScript v1 nhận thêm bí danh hai bước, destructuring, `promisify`, `require` nội tuyến; quy tắc gạn G4 cho lời gọi `exec`/`execSync` có lệnh hằng. Đã đo trên dữ liệu phát triển và trên tập giữ lại của `pairs-v1` (9 vị trí lỗi đã biết, chỉ nhãn dương tính) |
| `path-traversal-v0.2` | CWE-22; Python; chỉ CodeQL | Cảnh báo của truy vấn baseline. Nếu truy vấn có bằng chứng an toàn v0.2 vẫn báo thì ở **P1**; nếu bằng chứng đã loại mọi luồng thì xuống **P4**. Không xóa cảnh báo nào |

Profile `path-traversal-v0.2` dùng đúng pack đã đánh giá trong nghiên cứu
([rules/codeql/path-traversal-v0.2/](../rules/codeql/path-traversal-v0.2/README.md)), trùng từng
byte với bản đóng băng. v0.3 chưa được tích hợp.

Profile `command-injection-v0.2` cài đặt đúng hai giai đoạn của đề cương: sàng lọc nhanh bằng
Semgrep và một công cụ bổ trợ theo ngôn ngữ, rồi thẩm định bằng CodeQL. Rule của công cụ bổ
trợ, thay đổi so với v0.1 và các giới hạn đã biết nằm trong
[PRIORITY_V0_2.md](../profiles/command-injection-v0.2/PRIORITY_V0_2.md).

## 2. Thành phần

| Service (Compose) | Vai trò |
|---|---|
| `frontend` | React + TypeScript, phục vụ bằng Nginx; chuyển `/api` vào FastAPI |
| `api` | FastAPI; ghi trạng thái rồi trả ngay, không chạy việc dài trong request |
| `worker` | Celery; image riêng cài Semgrep, CodeQL, Bandit và ESLint theo [tools/pins.env](../tools/pins.env). Node.js đã ghim nằm trên PATH vì ESLint chạy trên nó và bộ trích xuất JavaScript của CodeQL cần nó để đọc TypeScript |
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
   - Các ngôn ngữ chạy tuần tự. Trong một ngôn ngữ, tối đa hai công cụ chạy song song
     (`SCANNER_WORKERS`, mặc định 2).
   - Bandit và ESLint chạy với cấu hình đã ghim của worker, không đọc cấu hình trong mã bị
     quét: Bandit nhận `--ini` đã ghim và `--ignore-nosec`; ESLint nhận file cấu hình và
     formatter SARIF bằng đường dẫn tuyệt đối, tắt chú thích `eslint-disable`. File mà ESLint
     không phân tích được khiến lượt chạy ESLint ở trạng thái `partial`.
4. **Thẩm định** (`app/triage/`), theo loại profile:
   - **Profile ưu tiên** (`command-injection-v0.1`, `command-injection-v0.2`):
     - định vị sink bằng AST;
     - `reconcile-v0.1` gộp cảnh báo thành đơn vị theo `snapshot + đường dẫn + sink + vai trò
       đối số` (CWE không nằm trong khóa);
     - chính sách ưu tiên của profile (v0.1 hoặc v0.2) gán P1–P4 hoặc U kèm mã quyết định
       và lý do. Hai phiên bản dùng chung danh sách quyết định; v0.2 chỉ mở rộng tín hiệu
       đồng thuận và bảng rule-claims.
   - **Profile bằng chứng an toàn** (`path-traversal-v0.2`, `app/triage/safety_evidence.py`):
     - mỗi vị trí cảnh báo của truy vấn baseline là một đơn vị;
     - so với truy vấn có bằng chứng: còn báo thì P1, không còn thì P4;
     - truy vấn bằng chứng báo ở vị trí ngoài baseline là lỗi, và lượt quét thất bại;
     - lượt quét chạy dở (`partial`) không xếp hạng gì, để tránh hiển thị cảnh báo đang giữ
       thành cảnh báo bị ẩn.
   - Mức ưu tiên **không xóa cảnh báo** và không phải nhãn đúng/sai.
   - **Gạn** (`app/triage/adjudicate.py`, `adjudicate-v0.2`), sau khi xếp ưu tiên:
     - các đơn vị cùng một lời gọi thành một **ứng viên rà soát**;
     - ứng viên chuyển sang danh sách "Đã gạn" chỉ khi có bằng chứng cụ thể: Semgrep chứng
       minh dữ liệu request chỉ tới lệnh qua phép gán nằm trong nhánh không bao giờ chạy và
       mọi đường đi công cụ khác báo đều qua nhánh đó (G3); truy vấn bằng chứng an toàn của
       CodeQL không còn báo luồng mà truy vấn gốc đã báo (G1); hoặc lệnh là chuỗi hằng theo
       cả chứng minh của hệ thống lẫn phân loại của Bandit (G2). Mọi quy tắc đã thỏa đều
       được ghi lại;
     - thiếu bằng chứng, có công cụ khác khẳng định luồng, bước bằng chứng thất bại hay
       lượt quét chạy dở thì giữ ứng viên, kèm mã lý do;
     - ứng viên đã gạn giữ nguyên cảnh báo gốc, mức ưu tiên, quy tắc và bằng chứng.
   - Với profile `command-injection-v0.2` trên Python, hai bước bằng chứng chạy sau bước phát
     hiện: Semgrep chạy gói luật nhánh chết đã ghim (bước `semgrep-evidence`), và CodeQL chạy
     các truy vấn bằng chứng CWE-78 trên chính database đã tạo (bước `codeql-evidence`), không
     trích xuất lại. Kết quả của hai bước là bằng chứng, không phải cảnh báo; bước nào thất
     bại thì quy tắc tương ứng không gạn gì và lượt quét vẫn giữ trạng thái của nó.
5. **Lưu** (`workflows/scans/persist.py`): kết quả của lượt quét được thay trong một
   transaction. Artifact được upload song song (`ARTIFACT_UPLOAD_WORKERS`, mặc định 4) dưới
   `scans/{scan_id}/…`, kèm SHA-256.
6. **Đọc kết quả:** `GET /api/v1/scans/{id}`, `/scans/{id}/units` (có phân trang, lọc theo
   mức, công cụ và danh sách `disposition=review|filtered`) và `/scans/{id}/units/{unit_id}`
   (bằng chứng đầy đủ, vết luồng dữ liệu, quyết định gạn và ứng viên).
7. **Báo cáo:** `GET /api/v1/scans/{id}/report` trả báo cáo trước–sau (cảnh báo thô, đơn
   vị, ứng viên, danh sách rà chính, đã gạn, chỉ hạ ưu tiên; đóng góp từng công cụ; thời gian
   từng bước). `GET /api/v1/scans/{id}/report.sarif` trả SARIF 2.1.0 gồm mọi cảnh báo gốc;
   cảnh báo của ứng viên đã gạn mang `suppressions` kèm lý do.

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
| `location_units`, `unit_findings` | Đơn vị vị trí, khóa ứng viên (`candidate_key`) và liên kết tới cảnh báo |
| `unit_assessments` | Mức ưu tiên, quyết định, lý do, hash của chính sách, `disposition` (`review`/`filtered`) và bản ghi gạn trong `evidence` |

Migration nằm ở `backend/migrations/versions/` (0001–0007) và không được sửa sau khi merge.
Xóa theo cascade: project → snapshot → scan → tool_run → finding.

## 5. API

| Phương thức | Đường dẫn (tiền tố `/api/v1`) | Ghi chú |
|---|---|---|
| GET | `/health/live`, `/health/ready` | Readiness kiểm PostgreSQL/schema, Redis và S3 |
| POST, GET | `/projects` | Tạo; liệt kê có phân trang, sắp xếp, tìm kiếm |
| GET | `/projects/{id}` | Chi tiết dự án |
| POST | `/projects/{id}/scans` | Tạo lượt quét npm hoặc GitHub |
| GET | `/scans/{id}`, `/scans/{id}/units`, `/scans/{id}/units/{unit_id}` | Trạng thái, hàng đợi, bằng chứng |
| GET | `/scans/{id}/report`, `/scans/{id}/report.sarif` | Báo cáo trước–sau; SARIF hợp nhất |

Hợp đồng HTTP nằm trong [frontend/openapi.json](../frontend/openapi.json). Kiểu dữ liệu
TypeScript được sinh từ file này, và CI kiểm tra hai bên khớp nhau.

## 6. Giao diện

Các trang:

- Tổng quan;
- Dự án (danh sách và chi tiết có tab);
- Lượt quét (hướng dẫn tạo từ dự án);
- Chi tiết lượt quét (trạng thái tự làm mới, hàng đợi theo mức, danh sách rà chính và đã
  gạn, bảng bằng chứng, khối thẩm định, báo cáo trước–sau có nút tải JSON và SARIF);
- Cảnh báo, Hệ thống, 404.

Tính năng mà backend chưa hỗ trợ được ghi rõ là "Chưa triển khai"; giao diện không hiển thị
dữ liệu mẫu hay kết quả giả. Cấu trúc và quy tắc của frontend: [frontend/AGENTS.md](../frontend/AGENTS.md).

## 7. Chưa có

- Upload archive hoặc thư mục từ máy người dùng.
- API liệt kê mọi lượt quét, và trang cảnh báo tổng hợp toàn hệ thống.
- Với profile CWE-22: hiển thị bảng bằng chứng (`Evidence.ql`: cơ chế, guard, dòng mã) và
  v0.3.
- Phiếu rà soát: người rà chưa ghi được kết luận đúng/sai cho từng ứng viên.
- Gói bằng chứng cho JavaScript/TypeScript; đối chiếu hai lượt quét của cùng một nguồn.
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
