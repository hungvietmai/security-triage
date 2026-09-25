# Security Triage

Bộ khung đề án sàng lọc và thẩm định cảnh báo lỗ hổng kết hợp **Semgrep + CodeQL**,
hướng tới **JavaScript/TypeScript và Python**.

**Trạng thái:** đã có FE/BE quản lý dự án, 5 bảng dữ liệu, worker và kết nối hạ tầng.
Upload, chạy Semgrep/CodeQL và thuật toán thẩm định **chưa được triển khai**.

## Chạy toàn bộ bằng Docker

Yêu cầu duy nhất: Docker Desktop hoặc Docker Engine kèm **Compose >= 2.24.4**.
Không cần cài Node.js, Python, PostgreSQL hay Redis trên máy.

```bash
docker compose up --build -d
docker compose ps -a
```

Lần đầu cần tải image và build dependencies. `migrate` và `storage-init` tự chạy;
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

## Cấu trúc

| Thư mục | Vai trò |
|---|---|
| `frontend/` | React + TypeScript + Vite, shadcn/ui, TanStack Query/Router; Nginx cho bản build |
| `backend/app/` | FastAPI theo domain: `core/` (config, DB, S3, lỗi), `features/<domain>/`, Celery. Xem [backend/AGENTS.md](backend/AGENTS.md) |
| `backend/migrations/` | Alembic, migration 0001–0002 |
| `backend/tests/` | Test theo cấu trúc `app/`, gồm test kiến trúc |
| `infra/` | Cấu hình SeaweedFS |
| `rules/` | Vị trí dành cho rule Semgrep và query CodeQL |
| `experiments/` | Quy ước dữ liệu và đánh giá |
| `docs/architecture.md` | Phạm vi đã làm, ranh giới kiến trúc và bước tiếp theo |

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
Cảnh báo, Hệ thống, 404. Tính năng backend chưa có hiển thị rõ "Chưa triển khai";
không có dữ liệu mẫu hay kết quả quét giả.

## Bước tiếp theo

Triển khai **chọn thư mục → xem/lọc file → tự ZIP → upload → lưu source snapshot**.
Sau đó tích hợp Semgrep trước, CodeQL sau. Không cần thay cấu trúc FE/BE.

Chưa kèm CodeQL CLI, scanner runtime hay bộ dữ liệu lỗ hổng trong image.
Không commit mã nguồn người dùng, object-store data hoặc CodeQL database vào Git.

## Tài liệu chính thức

- [FastAPI](https://fastapi.tiangolo.com/)
- [Vite](https://vite.dev/guide/)
- [Compose](https://docs.docker.com/compose/)
- [SeaweedFS S3 credentials](https://github.com/seaweedfs/seaweedfs/wiki/S3-Credentials)
- [Celery](https://docs.celeryq.dev/en/stable/)
