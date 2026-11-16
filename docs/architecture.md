# Kiến trúc ứng dụng

Mô tả ứng dụng web như đã cài đặt, cập nhật ngày 2026-11-15. Trạng thái và kết quả nghiên cứu
nằm ở [research.md](research.md); cách chạy stack nằm ở [README](../README.md).

## 1. Ứng dụng làm gì

Người dùng tạo dự án, rồi yêu cầu quét **một package npm theo version chính xác** hoặc
**một commit GitHub** (40 ký tự). Worker tải mã nguồn và chạy các công cụ quét theo một
scan profile đã ghim hash. Sau đó worker gộp cảnh báo theo vị trí sink và xếp mỗi đơn vị
vào một mức ưu tiên rà soát. Bước thẩm định gộp các đơn vị cùng một lời gọi thành một ứng
viên rà soát và gạn những ứng viên có bằng chứng cụ thể là cảnh báo sai. Giao diện hiển thị
trạng thái lượt quét, danh sách rà chính và danh sách đã gạn theo hàng đợi P1→P4, bằng chứng
của từng đơn vị và báo cáo trước–sau.

Người dùng chọn một trong chín profile khi tạo lượt quét. Bốn profile đầu quét một nhóm CWE;
`multi-cwe-v0.1` ghép hai profile có sẵn vào một lượt quét, `multi-cwe-v0.2` thêm nhóm CWE-89,
`multi-cwe-v0.3` cho nhóm CWE-89 chạy ba công cụ, `multi-cwe-v0.4` (thử nghiệm) gộp thêm cảnh báo
Bandit ở dòng dựng câu SQL với lời gọi thực thi nó, và `multi-cwe-v0.5` (thử nghiệm) thêm nhóm
CWE-79 cho JavaScript/TypeScript:

| Profile | Phạm vi | Cách xếp hàng đợi |
|---|---|---|
| `command-injection-v0.1` (mặc định) | CWE-78; JavaScript và Python; Semgrep và CodeQL | Gộp cảnh báo theo sink, xếp P1–P4/U theo chính sách ưu tiên v0.1 |
| `command-injection-v0.2` | CWE-78; JavaScript/TypeScript và Python. Sàng lọc: Semgrep cùng Bandit (Python) hoặc ESLint với eslint-plugin-security (JavaScript/TypeScript). Thẩm định: CodeQL | Như v0.1, theo chính sách ưu tiên v0.2: "đồng thuận" là CodeQL cùng ít nhất một công cụ sàng lọc. **Chưa được đánh giá** |
| `command-injection-v0.3` | Như v0.2 | Như v0.2, với ba điểm khác: worker quyết định phạm vi tệp của Semgrep (mã bị quét không tự ẩn tệp được); bộ định vị lời gọi JavaScript v1 nhận thêm bí danh hai bước, destructuring, `promisify`, `require` nội tuyến; quy tắc gạn G4 cho lời gọi `exec`/`execSync` có lệnh hằng. Đã đo trên dữ liệu phát triển và trên tập giữ lại của `pairs-v1` (9 vị trí lỗi đã biết, chỉ nhãn dương tính) |
| `path-traversal-v0.2` | CWE-22; Python; chỉ CodeQL | Cảnh báo của truy vấn baseline. Nếu truy vấn có bằng chứng an toàn v0.2 vẫn báo thì ở **P1**; nếu bằng chứng đã loại mọi luồng thì xuống **P4**. Không xóa cảnh báo nào |
| `multi-cwe-v0.1` | CWE-78 (JavaScript/TypeScript và Python) và CWE-22 (Python) trong một lượt quét; ghim manifest của `command-injection-v0.3` và `path-traversal-v0.2` | Mỗi cảnh báo thuộc đúng một nhóm phân tích và được xếp hạng, gạn bằng đúng profile thành viên của nhóm đó. Cảnh báo không xác định được nhóm, hoặc thuộc nhóm chưa xếp hạng được, ở mức **U** trong danh sách rà. Mới kiểm chứng kỹ thuật trên dữ liệu phát triển, chưa có số liệu đánh giá riêng |
| `multi-cwe-v0.2` | Như `multi-cwe-v0.1`, thêm CWE-89 (Python và JavaScript/TypeScript; chỉ CodeQL); ghim thêm manifest của `sql-injection-v0.1` | Hai nhóm đầu như `multi-cwe-v0.1`. Nhóm `sql-injection` **chỉ phát hiện và giữ**: mỗi vị trí CodeQL báo là một đơn vị mức **U** ("chưa xếp hạng") ở danh sách rà chính; không có chính sách xếp hạng và không có điều kiện gạn |
| `multi-cwe-v0.3` | Như `multi-cwe-v0.2`, nhưng CWE-89 dùng Semgrep (Python và JavaScript/TypeScript; 37 file luật thượng nguồn nguyên văn), Bandit (Python; `B608`, `B610`, `B611`) và CodeQL; ghim manifest của `sql-injection-v0.2` | Hai nhóm đầu như `multi-cwe-v0.1`. Nhóm `sql-injection` chỉ phát hiện và giữ, mức **U**; cảnh báo của nhiều công cụ chỉ thành một đơn vị khi cùng nằm trong một lời gọi thực thi truy vấn SQL của Python, còn lại mỗi vị trí của mỗi công cụ là một đơn vị. Đã đo trên dữ liệu phát triển có nhãn: [plans/multi-cwe.md §21](plans/multi-cwe.md#21-trạng-thái-p2b-2026-11-16) |
| `multi-cwe-v0.4` (thử nghiệm) | Như `multi-cwe-v0.3`, cùng công cụ và luật; ghim manifest của `sql-injection-v0.3` | Như `multi-cwe-v0.3`, thêm: cảnh báo Bandit B608 ở câu gán `tên = <chuỗi SQL>` vào đơn vị của lời gọi thực thi duy nhất đọc `tên`, nếu lời gọi đó có cảnh báo CodeQL hoặc Semgrep và biến chỉ được gán một lần. Đo bằng cách chạy lại trên SARIF đã lưu: [plans/multi-cwe.md §23](plans/multi-cwe.md#23-phép-gộp-bandit-với-lời-gọi-sql-và-giá-trị-bandit-sau-gộp-2026-11-16) |
| `multi-cwe-v0.5` (thử nghiệm) | Ba nhóm của `multi-cwe-v0.4` (cùng manifest), thêm CWE-79 (JavaScript/TypeScript; bảy truy vấn CodeQL trong `Security/CWE-079/`); ghim thêm manifest của `cross-site-scripting-v0.1` | Ba nhóm đầu như `multi-cwe-v0.4`. Nhóm `cross-site-scripting` **chỉ phát hiện và giữ**: mỗi vị trí CodeQL báo là một đơn vị mức **U** ở danh sách rà chính; không có chính sách xếp hạng, không có điều kiện gạn. Đối chứng và đo: [plans/multi-cwe.md §24](plans/multi-cwe.md) |

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

   Báo cáo tách hai loại kết quả đã lưu khỏi số cảnh báo. `evidence_results` là kết quả của
   truy vấn bằng chứng mà profile `path-traversal-v0.2` lưu kèm đơn vị; chúng không phải cảnh
   báo riêng, nên cột "trước" dùng `detection_alerts` (= `raw_alerts` − `evidence_results`).
   `unranked_alerts` là kết quả đã lưu mà không nằm trong đơn vị nào: chỉ còn ở dữ liệu ghi trước
   khi cảnh báo chưa xếp hạng được giữ thành đơn vị; chúng được đếm ở báo cáo và có trong SARIF
   với `ranked: false`. Mỗi kết quả SARIF mang `resultRole` (`detection`, `evidence_query` hoặc
   `unknown`).

   Không lượt quét mới nào để cảnh báo ngoài đơn vị. Lượt quét ghép giữ cảnh báo của nhóm chưa
   xếp hạng thành đơn vị `F10_FAMILY_NOT_RANKED`; lượt quét profile đơn làm đúng như vậy qua
   `families.hold_unranked` khi profile không xếp hạng gì (ví dụ `path-traversal-v0.2` chạy dở):
   mỗi vị trí được báo là một đơn vị mức U ở danh sách rà, không bao giờ bị gạn.

Lõi quét (`app/scanners`) và lõi thẩm định (`app/triage`) được dùng chung với CLI thực nghiệm
[run_pilot.py](../experiments/run_pilot.py). Job CI `scan-parity` quét `curling@0.2.0` qua cả
hai đường và yêu cầu kết quả giống nhau.

### 3.1 Lượt quét nhiều nhóm CWE (profile `multi-cwe-v0.1`, `multi-cwe-v0.2` và `multi-cwe-v0.3`)

Profile ghép không có luật hay chính sách riêng: manifest của nó ghim manifest của các profile
thành viên theo hash, mỗi thành viên ứng với một **nhóm phân tích**
(`command-injection` → CWE-78, `path-traversal` → CWE-22). Đặc tả:
[COMPOSITION.md](../profiles/multi-cwe-v0.1/COMPOSITION.md).

1. **Chạy công cụ một lần** (`app/workflows/scans/families.py`): công cụ sàng lọc và CodeQL của
   thành viên đứng đầu chạy như ở profile đơn, tạo **một** database CodeQL cho mỗi ngôn ngữ. Gói
   truy vấn của thành viên CWE-22 được phân tích trên chính database đó, trong một lượt riêng
   (`codeql-path-traversal`) có SARIF, log, thời gian và `tool_run` riêng. Hai gói truy vấn không
   bao giờ đi chung một lệnh.
2. **Phân loại** (`classification.py`): mỗi cảnh báo giữ ba dữ kiện tách biệt — `reported_cwes`
   (nhãn công cụ, nguyên văn), `mapped_cwes` (CWE của định nghĩa rule đã ghim, có thể nhiều) và
   `analysis_family`. Nhóm chỉ được gán khi xác định được đúng một nhóm.
3. **Định tuyến trước khi gộp:** cảnh báo của mỗi nhóm được đưa cho đúng hàm đánh giá của profile
   thành viên (`scan_language` hoặc `scan_language_evidence`). Cảnh báo của nhóm này không bao giờ
   vào bộ gộp của nhóm kia. Với cùng snapshot, đơn vị và đánh giá của một nhóm bằng kết quả quét
   riêng profile thành viên.
4. **Không cảnh báo nào nằm ngoài một đơn vị.** Lớp ghép tạo hai loại đơn vị, luôn ở mức U, luôn ở
   danh sách rà, không bao giờ bị gạn: `F00_FAMILY_UNRESOLVED` (không xác định được nhóm, ghi nhóm
   `unassigned`) và `F10_FAMILY_NOT_RANKED` (nhóm chạy dở hoặc bước đánh giá của nhóm thất bại nên
   thành viên không xếp hạng gì).
5. **Ba trạng thái tách biệt:** trạng thái lượt quét và lượt chạy của từng nhóm
   (`completed/partial/failed`); trạng thái bằng chứng của từng đơn vị (`evidence_state`: bị bác
   bỏ, đã đối chiếu mà không bác bỏ, chưa đủ, không lấy được, không áp dụng, chưa thẩm định); và
   quyết định gạn (`disposition`). Chỉ "bị bác bỏ" mới dẫn tới "đã gạn". Lỗi của lượt chạy chỉ phục
   vụ một nhóm không làm đổi kết quả của nhóm khác.
6. **Không có điều kiện gạn dùng chung.** G1–G4 thuộc nhóm lệnh; điều kiện của pack v0.2 thuộc nhóm
   đường dẫn. Profile ghép không thêm hay nới điều kiện nào.
7. **Nhóm chỉ phát hiện và giữ** (`multi-cwe-v0.2`, nhóm `sql-injection` → CWE-89). Thành viên
   `sql-injection-v0.1` là một profile kiểu `detection`
   ([DETECTION.md](../profiles/sql-injection-v0.1/DETECTION.md)): nó ghim theo hash truy vấn
   `Security/CWE-089/SqlInjection.ql` của gói truy vấn chuẩn CodeQL cho Python và
   JavaScript/TypeScript, và khai trong manifest các CWE mà mỗi rule ánh xạ tới (`js/sql-injection`
   ánh xạ tới ba CWE). Truy vấn chạy trong lượt riêng `codeql-sql-injection` trên database dùng
   chung. `app/workflows/scans/detection.py` biến mỗi vị trí được báo thành một đơn vị mức U
   (`K10_DETECTED_KEPT`) ở danh sách rà, với lý do giữ `no_filter_condition_for_family` và trạng
   thái bằng chứng "chưa đủ". Không có bộ định vị sink, không gộp theo lời gọi, không xếp hạng,
   không gạn. Lượt chạy dở giữ các cảnh báo đã báo và ghi `run_incomplete`; lượt chạy thất bại mà
   đã ghi kết quả, hoặc cảnh báo của một rule không được ghim, được lớp ghép giữ thành đơn vị
   `F10_FAMILY_NOT_RANKED`. Hai nhóm kia của `multi-cwe-v0.2` cho đúng kết quả của
   `multi-cwe-v0.1`.
8. **Nhóm CWE-89 nhiều công cụ** (`multi-cwe-v0.3`, thành viên `sql-injection-v0.2`, manifest
   `detection` schema 2, [DETECTION.md](../profiles/sql-injection-v0.2/DETECTION.md)). Thành viên
   chạy thêm hai lượt có tên trên cùng nguồn, `semgrep-sql-injection` (luật ở
   [rules/semgrep/sql-injection-v0.1/](../rules/semgrep/sql-injection-v0.1/README.md), mỗi file dàn
   vào thư mục `r<index>` riêng để ID luật Semgrep báo truy được về đúng file đã ghim) và
   `bandit-sql-injection`, trước lượt `codeql-sql-injection` (`app/scanners/passes.py`). Bộ định vị
   `sql-call-site-v1` (`app/workflows/scans/sql_sites.py`) tìm các lời gọi thực thi truy vấn của
   Python bằng cây cú pháp; `detection.keep_detected_v2` chỉ gộp cảnh báo của các công cụ khi vùng
   được báo của mỗi cảnh báo nằm trọn trong cùng một lời gọi (lời gọi trong cùng khi lồng nhau).
   Không định vị được, hay ở JavaScript/TypeScript: mỗi vị trí được báo của mỗi công cụ là một đơn
   vị. `rule_id` của cảnh báo Semgrep là ID thượng nguồn; ID gốc giữ ở `raw_rule_id`. Một lượt hỏng
   hay chạy dở làm nhóm ở ngôn ngữ đó "chạy dở": cảnh báo của các lượt còn lại vẫn thành đơn vị với
   `run_incomplete`. Hai nhóm kia của `multi-cwe-v0.3` cho đúng kết quả của `multi-cwe-v0.2`.
9. **Nối cảnh báo Bandit với lời gọi SQL** (`multi-cwe-v0.4`, thành viên `sql-injection-v0.3`,
   [DETECTION.md](../profiles/sql-injection-v0.3/DETECTION.md), đơn vị `detection-units-v3`).
   - **Bước 1:** như `sql-call-site-v1`.
   - **Bước 2:** `sql_sites.locate_sql_strings` tìm các câu gán `tên = <biểu thức chuỗi>` (nối `+`, `%`,
     `.format()`, f-string) mà `tên` chỉ được gán một lần trong phạm vi của nó, không xuất hiện ở
     phạm vi lồng nhau, và chỉ được đọc một lần, làm đối số đầu của một lời gọi thực thi sau đó.
   - **Nối:** `detection.link_decisions` nối một cảnh báo Bandit B608 có vùng báo trùng một chuỗi
     literal của câu gán đó vào đơn vị của lời gọi, nếu lời gọi có cảnh báo CodeQL hoặc Semgrep.
   - **Truy vết:** cảnh báo được nối có `match_rule` là `explicit_link` và `linked_by` trong bằng
     chứng. Mọi B608 không nối được có lý do, ghi trong bản ghi chạy lại.
   - **Phạm vi:** JavaScript/TypeScript và hai nhóm kia không đổi so với `multi-cwe-v0.3`.
10. **Nhóm cross-site scripting** (`multi-cwe-v0.5`, thành viên `cross-site-scripting-v0.1`,
   [DETECTION.md](../profiles/cross-site-scripting-v0.1/DETECTION.md)). Một profile `detection`
   schema 1 chỉ có cấu hình JavaScript: lượt `codeql-cross-site-scripting` chạy bảy truy vấn chuẩn
   trong `Security/CWE-079/` của `codeql/javascript-queries` 2.4.6 trên database JavaScript dùng
   chung, một luồng, giới hạn 600 giây. `detection.keep_detected` làm mỗi vị trí được báo thành một
   đơn vị mức U ở danh sách rà; hai truy vấn báo cùng vùng chung một đơn vị, mỗi cảnh báo giữ rule
   và nhãn CWE riêng. Mã đơn vị có tên nhóm, nên cảnh báo XSS trùng vị trí với cảnh báo CWE-78 hay
   CWE-89 vẫn là đơn vị riêng. Lượt Python không có nhóm này. Ba nhóm kia cho đúng kết quả của
   `multi-cwe-v0.4`. Giới hạn thời gian mềm của tác vụ tăng lên 12 600 giây để chứa lượt thêm này.

Công cụ dòng lệnh `backend/scripts/scan_families.py` chạy cùng lớp ghép này mà không qua cơ sở dữ
liệu, và so lượt quét ghép với lượt quét riêng từng profile. Thiết kế, bất biến và kết quả kiểm
chứng: [plans/multi-cwe.md](plans/multi-cwe.md).

## 4. Dữ liệu

| Bảng | Nội dung |
|---|---|
| `projects` | Dự án |
| `source_snapshots` | Archive bất biến: tọa độ nguồn, SHA-256, provenance |
| `scans` | Trạng thái lượt quét, phiên bản scanner/profile, artifact |
| `tool_runs` | Một lần chạy của một công cụ cho một ngôn ngữ |
| `findings` | Cảnh báo thô đã chuẩn hóa, giữ nguyên `raw_result` và nhãn CWE của công cụ (`cwe_ids`). Lượt quét ghép ghi thêm bản ghi phân loại vào `evidence.classification` và cơ sở gán nhóm vào `classification_source`, không ghi đè nhãn gốc |
| `location_units`, `unit_findings` | Đơn vị vị trí, khóa ứng viên (`candidate_key`), nhóm phân tích (`analysis_family`, chỉ lượt quét ghép ghi) và liên kết tới cảnh báo |
| `unit_assessments` | Mức ưu tiên, quyết định, lý do, hash của chính sách, `disposition` (`review`/`filtered`) và bản ghi gạn trong `evidence` |

Lượt quét ghép ghi vào `scans.config` phiên bản cách ghép, manifest và hash của từng thành viên,
và việc từng nhóm đã làm ở mỗi ngôn ngữ; đơn vị và đánh giá của mỗi nhóm mang phiên bản bộ gộp và
chính sách của chính nhóm đó. Lượt quét bằng profile đơn không ghi gì mới: nhóm của nó được suy
ra từ profile khi đọc, nên dữ liệu cũ không bị viết lại.

Migration nằm ở `backend/migrations/versions/` (0001–0008) và không được sửa sau khi merge.
`0008` thêm cột `location_units.analysis_family` (cho phép rỗng).
Xóa theo cascade: project → snapshot → scan → tool_run → finding.

## 5. API

| Phương thức | Đường dẫn (tiền tố `/api/v1`) | Ghi chú |
|---|---|---|
| GET | `/health/live`, `/health/ready` | Readiness kiểm PostgreSQL/schema, Redis và S3 |
| POST, GET | `/projects` | Tạo; liệt kê có phân trang, sắp xếp, tìm kiếm |
| GET | `/projects/{id}` | Chi tiết dự án |
| POST | `/projects/{id}/scans` | Tạo lượt quét npm hoặc GitHub |
| GET | `/scans/{id}`, `/scans/{id}/units`, `/scans/{id}/units/{unit_id}` | Trạng thái, các nhóm phân tích (`families`), hàng đợi, bằng chứng. `/units` lọc được theo `family`, `tier`, `tool`, `disposition`; mỗi đơn vị có `analysis_family`, `cwe`, `evidence_state`, `kept_because` |
| GET | `/scans/{id}/report`, `/scans/{id}/report.sarif` | Báo cáo trước–sau, có số liệu theo từng nhóm; SARIF hợp nhất, mỗi cảnh báo mang nhóm, CWE của nhóm, nhãn CWE công cụ báo và CWE theo rule đã ghim |

Hợp đồng HTTP nằm trong [frontend/openapi.json](../frontend/openapi.json). Kiểu dữ liệu
TypeScript được sinh từ file này, và CI kiểm tra hai bên khớp nhau.

## 6. Giao diện

Các trang:

- Tổng quan;
- Dự án (danh sách và chi tiết có tab);
- Lượt quét (hướng dẫn tạo từ dự án);
- Chi tiết lượt quét (trạng thái tự làm mới, bảng nhóm phân tích theo CWE kèm trạng thái lượt
  chạy và bước bằng chứng của từng nhóm, lọc theo nhóm/mức/công cụ/danh sách, cột trạng thái bằng
  chứng, hàng đợi theo mức, danh sách rà chính và đã gạn, bảng bằng chứng, khối thẩm định, báo cáo
  trước–sau theo nhóm có nút tải JSON và SARIF);
- Cảnh báo, Hệ thống, 404.

Tính năng mà backend chưa hỗ trợ được ghi rõ là "Chưa triển khai"; giao diện không hiển thị
dữ liệu mẫu hay kết quả giả. Cấu trúc và quy tắc của frontend: [frontend/AGENTS.md](../frontend/AGENTS.md).

## 7. Chưa có

- Upload archive hoặc thư mục từ máy người dùng.
- API liệt kê mọi lượt quét, và trang cảnh báo tổng hợp toàn hệ thống.
- Với profile CWE-22: hiển thị bảng bằng chứng (`Evidence.ql`: cơ chế, guard, dòng mã) và
  v0.3.
- Nhóm CWE ngoài CWE-78 và CWE-22; CWE-22 cho JavaScript/TypeScript; lượt chạy công cụ phục vụ
  nhiều nhóm (nên trạng thái "chưa xác định nhóm" chưa gặp trên dữ liệu thật); điều kiện gạn cho
  bất kỳ nhóm mới nào.
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
