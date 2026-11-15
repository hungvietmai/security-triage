# Security Triage

Đề án nghiên cứu cách **giảm cảnh báo sai (FP) của phân tích tĩnh bảo mật**, dùng Semgrep
và CodeQL. Repository gồm hai phần:

- **Nghiên cứu** ([experiments/](experiments/)): hiện tập trung vào **bằng chứng an toàn viết
  trong CodeQL cho CWE-22 trên Python**. Trên benchmark tổng hợp, v0.2 loại 92,5% FP mà không
  mất TP. Trên mã thật, theo nhãn đã được chủ đề án xác minh, v0.2 vẫn không loại nhầm TP nào
  nhưng chỉ loại được khoảng 9% FP (4/43), còn v0.3 không loại thêm FP nào.
  Trạng thái đầy đủ: **[docs/research.md](docs/research.md)**.
- **Ứng dụng web** ([frontend/](frontend/), [backend/](backend/)): quét một package npm hoặc
  một commit GitHub, chọn một trong sáu profile:
  - `command-injection-v0.1`: CWE-78, JavaScript/Python, Semgrep và CodeQL, gộp cảnh báo theo
    sink và xếp hàng đợi P1→P4;
  - `command-injection-v0.2`: như trên, thêm công cụ bổ trợ vào bước phát hiện (Bandit cho
    Python, eslint-plugin-security cho JavaScript/TypeScript); CodeQL thẩm định bằng truy
    vấn bằng chứng an toàn và ứng viên có bằng chứng là cảnh báo sai được gạn sang danh
    sách riêng. Đã đo trên dữ liệu phát triển, trên các đợt mã chưa từng xem và trên tập phát
    triển của `pairs-v1`
    ([docs/thesis/chuong-3-thuc-nghiem.md](docs/thesis/chuong-3-thuc-nghiem.md));
  - `command-injection-v0.3`: như v0.2, thêm bộ định vị lời gọi JavaScript v1, phạm vi tệp của
    Semgrep do worker quyết định, và quy tắc gạn lệnh hằng cho JavaScript/TypeScript. Đã đo trên
    dữ liệu phát triển và, với cấu hình đóng băng trước, trên tập giữ lại của `pairs-v1`: 9/9 vị
    trí lỗi đã biết được báo, không vị trí nào bị gạn; chỉ có nhãn dương tính
    ([pairs-v1](experiments/evaluation/pairs-v1/README.md));
  - `path-traversal-v0.2`: CWE-22, Python, CodeQL với bằng chứng an toàn v0.2. Cảnh báo có
    bằng chứng an toàn xuống cuối hàng đợi, không bị xóa.
  - `multi-cwe-v0.1`: quét CWE-78 và CWE-22 trong **một lượt**, ghép `command-injection-v0.3`
    với `path-traversal-v0.2` trên cùng một database CodeQL. Mỗi cảnh báo thuộc đúng một nhóm
    CWE và được thẩm định bằng profile của nhóm đó. Mới kiểm chứng kỹ thuật trên dữ liệu phát
    triển ([docs/plans/multi-cwe.md](docs/plans/multi-cwe.md)); cách dùng ở
    [mục dưới](#quét-nhiều-cwe-trong-một-lượt).
  - `multi-cwe-v0.2`: như `multi-cwe-v0.1`, thêm nhóm **SQL injection (CWE-89)** cho Python và
    JavaScript/TypeScript bằng truy vấn chuẩn của CodeQL trên cùng database. Ở phiên bản này CWE-89
    **chỉ được phát hiện và giữ**: chưa có chính sách xếp hạng, chưa có điều kiện gạn, mọi cảnh báo
    ở danh sách rà chính. Mới kiểm chứng kỹ thuật trên dữ liệu phát triển.
  Chi tiết: **[docs/architecture.md](docs/architecture.md)**.

## Tài liệu

| Tài liệu | Nội dung |
|---|---|
| [docs/research.md](docs/research.md) | Câu hỏi nghiên cứu, diễn tiến, kết quả, việc còn mở, quy ước tài liệu |
| [docs/architecture.md](docs/architecture.md) | Kiến trúc ứng dụng, luồng quét, dữ liệu, API, những gì chưa có |
| [docs/validation.md](docs/validation.md) | Hook, CI, kết quả kiểm chứng đã ghi nhận, lỗi đã biết |
| [docs/plans/multi-cwe.md](docs/plans/multi-cwe.md) | Kế hoạch (chưa triển khai): kiến trúc đa CWE, đặc tả bất biến, đầu việc P1a/P1b |
| [docs/thesis/](docs/thesis/README.md) | Hồ sơ đề án: bản thảo ba chương và Kết luận, đối chiếu cam kết đề cương, bảng tiêu chí, hướng dẫn trình diễn, tiến độ |
| [docs/performance.md](docs/performance.md) | Số đo hiệu năng backend (2026-10-07) |
| [docs/demo/](docs/demo/README.md) | Demo toàn stack quét `curling@0.2.0` (2026-10-08) |
| [experiments/README.md](experiments/README.md) | Bản đồ thư mục thực nghiệm, cách chạy, danh sách tài liệu bị khóa |
| [AGENTS.md](AGENTS.md), [backend/AGENTS.md](backend/AGENTS.md), [frontend/AGENTS.md](frontend/AGENTS.md), [experiments/AGENTS.md](experiments/AGENTS.md) | Quy ước code, commit, test (tiếng Anh) |

[SECURITY_TRIAGE_AGENT_HANDOFF_2026-10-20.md](SECURITY_TRIAGE_AGENT_HANDOFF_2026-10-20.md) là ảnh
chụp ngày 20/10, đã bị khóa bởi đợt C nên không cập nhật nữa. Trạng thái hiện tại xem ở
[docs/research.md](docs/research.md).

## Chạy toàn bộ bằng Docker

Yêu cầu duy nhất: Docker Desktop hoặc Docker Engine kèm **Compose >= 2.24.4**.
Không cần cài Node.js, Python, PostgreSQL hay Redis trên máy.

```bash
docker compose up --build -d
docker compose ps -a
```

Lần đầu cần tải image và build dependencies; image worker tải thêm bundle CodeQL đã pin. `migrate` và `storage-init` tự chạy;
hai service này kết thúc với `Exited (0)` là bình thường. API chờ migration, bucket
và Redis sẵn sàng; FE/worker chờ API healthy.

- Giao diện: <http://localhost:5173>
- Swagger: <http://localhost:8000/api/docs>
- Readiness: <http://localhost:8000/api/v1/health/ready>

Tạo một dự án trên FE; dữ liệu được lưu thật trong PostgreSQL.

```bash
docker compose logs -f api worker
docker compose stop
docker compose start
docker compose down
```

Các service chạy lâu dài dùng `restart: unless-stopped`, tự khởi động lại khi crash
hoặc khi Docker khởi động lại (trừ khi bạn đã `stop`/`down`).
`down` giữ các named volume. Chỉ dùng `down --volumes` khi chủ động muốn xóa dữ liệu local.
Chạy lại `docker compose up --build -d` sau khi thay đổi dependencies hoặc migration.

## Quét nhiều CWE trong một lượt

1. Mở một dự án, bấm **Tạo scan**, chọn profile **"CWE-78 + CWE-22 · Đa CWE trong một lượt
   quét"** (`multi-cwe-v0.1`), rồi nhập package npm hoặc commit GitHub như thường lệ.
2. Trang lượt quét tự cập nhật. Khi quét xong, bảng **Nhóm phân tích (CWE)** cho biết với từng
   nhóm: profile nào đã thẩm định, lượt chạy của nhóm kết thúc ra sao, các bước bằng chứng của
   nhóm ở trạng thái nào, và có bao nhiêu đơn vị ở danh sách rà chính, đã gạn, hoặc được giữ lại
   vì chưa xếp hạng được.
3. Bấm tên một nhóm để lọc đơn vị theo CWE; bộ lọc nằm trong URL (`?family=path-traversal`) và kết
   hợp được với mức ưu tiên, công cụ và danh sách "Đã gạn".
4. Trong bảng đơn vị, cột **Thẩm định** là quyết định gạn, cột **Bằng chứng** là trạng thái bằng
   chứng. Hai cột này khác nhau có chủ ý: thiếu bằng chứng, bằng chứng mâu thuẫn hay lượt quét
   chạy dở đều giữ cảnh báo ở danh sách rà chính.
5. Mở một đơn vị để xem nhóm, lý do giữ hoặc gạn, bằng chứng, và với từng cảnh báo gốc: nhãn CWE
   do công cụ báo, CWE theo rule đã ghim và lượt chạy đã sinh ra nó.
6. Cuối trang, **Báo cáo trước–sau** có bảng theo từng nhóm; tải báo cáo JSON hoặc SARIF hợp nhất
   (mỗi cảnh báo mang nhóm và CWE; cảnh báo đã gạn có `suppressions`, không bị xóa).

Profile **"CWE-78 + CWE-22 + CWE-89 · Đa CWE, SQL injection chỉ phát hiện và giữ"**
(`multi-cwe-v0.2`) dùng y như trên và có thêm nhóm `sql-injection`. Đơn vị của nhóm này luôn ở mức
U ("chưa xếp hạng"), luôn ở danh sách rà chính, cột **Bằng chứng** ghi "Chưa đủ bằng chứng" và
SARIF không bao giờ gắn `suppressions` cho chúng. Với JavaScript/TypeScript, một cảnh báo của
`js/sql-injection` mang cả ba CWE mà rule ánh xạ tới (CWE-89, CWE-90, CWE-943).

Giới hạn: CWE-22 chỉ có trên Python; CWE-89 mới chỉ dùng CodeQL (chưa có Semgrep, Bandit) và chưa
gộp cảnh báo theo lời gọi; lượt quét ghép chạy lâu hơn một profile đơn nhưng chỉ tạo database CodeQL
một lần. Profile đơn và `multi-cwe-v0.1` vẫn dùng được như trước.

## Phát triển trong Docker, tự tải lại code

```bash
docker compose -f compose.yaml -f compose.dev.yaml up --build -d
```

FE dùng Vite HMR, API dùng Uvicorn reload. `app/`, `migrations/`, `scripts/` (và `tests/`
cho service test) được mount từ máy nên không cần build lại khi sửa. Sửa task Celery thì restart worker:

```bash
docker compose -f compose.yaml -f compose.dev.yaml restart worker
```

Vẫn truy cập FE tại cổng 5173. Chế độ dev mở thêm PostgreSQL tại localhost:5432
và S3 tại localhost:8333. Dependencies nằm trong image, không mount node_modules
hoặc Python venv từ máy Windows vào Linux container.
Nếu Docker Desktop không nhận thay đổi file, đặt repo trong filesystem WSL2.

## Cấu hình

Mặc định chạy ngay, không cần file `.env`. Muốn đổi cổng hoặc thông tin local,
copy `.env.example` thành `.env` ở thư mục gốc. Đây là cấu hình **local một người dùng**,
chưa có đăng nhập; tất cả cổng public của Compose chỉ bind 127.0.0.1.
Không đưa thông tin S3/DB vào FE.

Chạy backend ngoài Docker (ví dụ `uv run uvicorn app.main:app` trong `backend/`) cũng đọc
`.env` ở thư mục gốc: nếu không đặt `DATABASE_URL`/`S3_ENDPOINT_URL`, URL localhost được
suy ra từ `POSTGRES_PASSWORD`, `POSTGRES_PORT` và `S3_PORT` (khớp cổng mở trong chế độ dev).

Tên host bên trong Docker: `postgres`, `redis`, `seaweedfs`, `api`.
Trình duyệt gọi `/api`; Nginx/Vite chuyển tiếp vào FastAPI.
API gọi SeaweedFS S3 bằng boto3. Dữ liệu filer và volume SeaweedFS cùng được giữ
trong `seaweed_data`. Cấu hình S3 mặc định là thông tin dev, không phải secret production.
Sau khi đã tạo volume PostgreSQL, đổi POSTGRES_PASSWORD trong `.env` không tự đổi
mật khẩu role trong DB; cần đổi role tương ứng rồi cập nhật cấu hình.

## Git hooks (Husky)

Cần Node.js >= 22.22.1 và [uv](https://docs.astral.sh/uv/) trên máy. Cài một lần ở thư mục gốc:

```bash
npm install                          # bật Husky (core.hooksPath = .husky/_)
npm --prefix frontend install
(cd backend && uv sync)
```

- **pre-commit**: lint-staged theo từng package: FE chạy Prettier + oxlint cho file đã stage
  rồi `tsc`; BE chạy `ruff format` + `ruff check --fix` rồi `mypy`.
- **pre-push**: toàn bộ test FE (Vitest) và BE (pytest, ngưỡng coverage 90%).
- **commit-msg**: commitlint theo [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
  (`commitlint.config.mjs`), đồng thời chặn mọi `Co-authored-by` và dòng ghi công AI.
  Quy ước type/scope và ví dụ: [AGENTS.md](AGENTS.md#commits).

Hook kiểm tra đúng phần *đã stage*. CI vẫn chạy lại mọi bước, hook chỉ giúp phát hiện sớm.

## Kiểm tra

```bash
docker compose --profile test run --build --rm test
docker compose --profile test run --rm --no-deps test ruff check .
docker compose --profile test run --rm --no-deps test ruff format --check .
docker compose --profile test run --rm --no-deps test mypy
docker compose --profile test run --rm --no-deps test pip-audit
docker compose exec api alembic check
docker compose exec worker celery -A app.workers.celery_app:celery_app inspect ping
```

Test API dùng PostgreSQL với schema UUID riêng cho mỗi test; không xóa bảng dự án.
Chạy `uv run pytest` ngoài Docker mà không đặt `TEST_DATABASE_URL` thì test dùng SQLite:
nhanh nhưng không kiểm tra hành vi riêng của PostgreSQL. Muốn kiểm tra đầy đủ, dùng
service `test` ở trên. CI còn chạy `alembic downgrade base` rồi `upgrade head` để kiểm tra migration hai chiều.
GitHub Actions có lint/build FE và kiểm tra toàn bộ stack Docker, readiness, proxy,
worker, schema drift và test API. Trạng thái CI chỉ xác nhận được sau khi repo được push.
Danh sách job và các kết quả đã ghi nhận: [docs/validation.md](docs/validation.md).

## Cấu trúc

| Thư mục | Vai trò |
|---|---|
| `frontend/` | React + TypeScript + Vite, shadcn/ui, TanStack Query/Router; Nginx cho bản build |
| `backend/app/` | FastAPI theo domain: `core/` (config, DB, S3, lỗi), `features/<domain>/`, Celery. Xem [backend/AGENTS.md](backend/AGENTS.md) |
| `backend/app/scanners/`, `backend/app/triage/` | Lõi quét và thẩm định, dùng chung giữa worker và CLI thực nghiệm |
| `backend/migrations/` | Alembic, migration 0001–0007 |
| `backend/tests/` | Test theo cấu trúc `app/`, gồm test kiến trúc |
| `infra/` | Cấu hình SeaweedFS |
| `rules/codeql/python-evidence/` | Query chẩn đoán guard số nguyên (giai đoạn CWE-78) |
| `rules/codeql/path-traversal-v0.2/` | Pack CWE-22 v0.2 mà worker chạy, trùng từng byte với bản nghiên cứu. Các phiên bản query CWE-22 khác nằm trong `experiments/` |
| `rules/codeql/command-injection-evidence-v0.2/`, `rules/semgrep/command-injection-evidence-v0.1/` | Hai gói bằng chứng cho bước gạn CWE-78: truy vấn CodeQL chạy lại trên database đã tạo, và luật nhánh chết của Semgrep CE kèm các ca kiểm tra |
| `profiles/` | Scan profile của worker: manifest ghim hash các config, rule, rule-claims và policy |
| `tools/` | Ghim phiên bản Semgrep, CodeQL, Bandit, Node.js và ESLint; script cài dùng chung cho các image scanner; cấu hình đã ghim của Bandit (`bandit/`) và ESLint (`eslint/`) |
| `experiments/` | Toàn bộ nghiên cứu: dữ liệu, query, runner, kết quả, khóa. Xem [experiments/README.md](experiments/README.md) |
| `docs/` | Tài liệu tổng quan (xem [Tài liệu](#tài-liệu)) |

## Frontend

React + TypeScript (strict) + Vite, tổ chức theo [bulletproof-react](https://github.com/alan2207/bulletproof-react):
shadcn/ui + Tailwind CSS v4, TanStack Query/Router, React Hook Form + zod,
Vitest + Testing Library + MSW. Kiểu dữ liệu API sinh từ OpenAPI của backend.

Cấu trúc, quy tắc kiến trúc (được kiểm tra bằng test), mẫu API, cách viết test và
checklist thêm feature: **[frontend/AGENTS.md](frontend/AGENTS.md)**.

```bash
cd frontend
npm run check      # typecheck + lint + format + test
npm run gen:api    # sau khi xuất lại openapi.json từ backend
```

Trang hiện có: Tổng quan, Dự án (`?page=`), Chi tiết dự án (`?tab=`), Lượt quét,
Chi tiết lượt quét (hàng đợi P1→P4, danh sách rà chính và đã gạn, bằng chứng, báo cáo
trước–sau), Cảnh báo, Hệ thống, 404. Tính năng mà
backend chưa có được hiển thị rõ là "Chưa triển khai"; giao diện không dùng dữ liệu mẫu
hay kết quả quét giả.

## Scanner trong worker

Image worker ([`backend/Dockerfile.worker`](backend/Dockerfile.worker)) cài Semgrep, CodeQL,
Bandit và ESLint theo [`tools/pins.env`](tools/pins.env), kèm sáu scan profile:
[`command-injection-v0.1`](profiles/command-injection-v0.1/profile.json),
[`command-injection-v0.2`](profiles/command-injection-v0.2/profile.json),
[`command-injection-v0.3`](profiles/command-injection-v0.3/profile.json),
[`path-traversal-v0.2`](profiles/path-traversal-v0.2/profile.json) (pack CodeQL ở
[`rules/codeql/path-traversal-v0.2/`](rules/codeql/path-traversal-v0.2/README.md)) và hai profile ghép
[`multi-cwe-v0.1`](profiles/multi-cwe-v0.1/profile.json) và
[`multi-cwe-v0.2`](profiles/multi-cwe-v0.2/profile.json), vốn chỉ ghim manifest của các profile
thành viên. Thành viên [`sql-injection-v0.1`](profiles/sql-injection-v0.1/profile.json) chỉ chạy
bên trong `multi-cwe-v0.2`. Worker từ chối
khởi động nếu hash của bất kỳ profile nào hoặc phiên bản scanner lệch so với bản đã ghim. Image API không
kèm scanner. Không commit mã nguồn người dùng, dữ liệu object store hay CodeQL database vào Git.

Các việc còn mở của cả ứng dụng và nghiên cứu được theo dõi ở
[docs/research.md §5](docs/research.md#5-việc-còn-mở) và
[docs/architecture.md §7](docs/architecture.md#7-chưa-có).

## Tài liệu chính thức

- [FastAPI](https://fastapi.tiangolo.com/)
- [Vite](https://vite.dev/guide/)
- [Compose](https://docs.docker.com/compose/)
- [SeaweedFS S3 credentials](https://github.com/seaweedfs/seaweedfs/wiki/S3-Credentials)
- [Celery](https://docs.celeryq.dev/en/stable/)
