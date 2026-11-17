# Kiến trúc đa CWE — thiết kế P0 và kế hoạch P1

Tài liệu thiết kế, viết ngày 2026-11-15 trên nhánh `feat/cwe22-triage`. Đây là **kế hoạch**, chưa có
dòng mã ứng dụng nào được sửa. Trạng thái ứng dụng như đã cài đặt vẫn nằm ở
[architecture.md](../architecture.md); trạng thái nghiên cứu ở [research.md](../research.md).

- **Mục tiêu dài hạn:** một kiến trúc phân tích tĩnh đa CWE (CWE-22, 78, 89, 79, 918) cho Python và
  JavaScript/TypeScript, thay cho hai đường xử lý chuyên biệt hiện nay.
- **Phạm vi của tài liệu này (P0):** truy vết hiện trạng, chọn kiến trúc, đặc tả các bất biến và chia
  P1 thành đầu việc. Không sửa backend/frontend, không quét dữ liệu mới, không thêm CWE, không sửa
  hiện vật nghiên cứu đã khóa.
- **Bản này là bản đã chỉnh** sau khi chủ đề án rà bản kế hoạch đầu; các điểm thay đổi và lý do nằm ở
  [mục 7](#7-quyết-định-và-lý-do).
- **Cập nhật cùng ngày:** P1a đã được triển khai trên nhánh `feat/multi-cwe-core`; mã, kiểm thử và
  kết quả lượt quét thật nằm ở [mục 16](#16-trạng-thái-p1a-2026-11-15). P1b (tích hợp vào ứng dụng
  web) nằm ở [mục 17](#17-trạng-thái-p1b-2026-11-15). Các mục 1–15 giữ nguyên là bản thiết kế; chỗ
  nào thực tế khác kế hoạch thì được ghi ngay tại chỗ và ở mục 16, 17. Lần rà nghiệm thu kỹ thuật
  P1 nằm ở [mục 18](#18-nghiệm-thu-kỹ-thuật-p1-2026-11-15); thẩm định và thiết kế tối thiểu cho
  CWE-89 ở [mục 19](#19-p2--thẩm-định-và-thiết-kế-tối-thiểu-cho-cwe-89-2026-11-15); P2a (profile
  `multi-cwe-v0.2`, CWE-89 chỉ phát hiện và giữ) ở [mục 20](#20-trạng-thái-p2a-2026-11-15); P2b
  (profile `multi-cwe-v0.3`, CWE-89 bằng Semgrep, Bandit và CodeQL, có số đo trên dữ liệu phát triển
  có nhãn) ở [mục 21](#21-trạng-thái-p2b-2026-11-16); đợt đánh giá để đề xuất cấu hình CWE-89
  (truy vết cảnh báo Semgrep JS/TS của Juice Shop, lợi ích của phép gộp JS/TS, Bandit trên tập
  Python độc lập SVEN) ở [mục 22](#22-đánh-giá-cấu-hình-cwe-89-cho-python-và-jsts-2026-11-16);
  profile thử nghiệm `multi-cwe-v0.4` (nối cảnh báo Bandit với lời gọi SQL) và giá trị Bandit sau gộp
  ở [mục 23](#23-phép-gộp-bandit-với-lời-gọi-sql-và-giá-trị-bandit-sau-gộp-2026-11-16); profile thử
  nghiệm `multi-cwe-v0.5` (thêm CWE-79 cho JavaScript/TypeScript bằng CodeQL, đối chứng với `v0.4` và
  đo trên OSSF CVE Benchmark) ở [mục 24](#24-nhóm-cwe-79-cho-javascripttypescript-profile-multi-cwe-v05-2026-11-16);
  phép đo Semgrep cho CWE-79 trên tập nhãn độc lập với CodeQL và quyết định giữ CodeQL ở
  [mục 25](#25-semgrep-cho-cwe-79-đo-trên-tập-nhãn-độc-lập-với-codeql-2026-11-16); profile thử
  nghiệm `multi-cwe-v0.6` (thêm CWE-918 cho Python và JavaScript/TypeScript bằng CodeQL, đối chứng
  với `v0.5`, bảng năm nhóm CWE) ở
  [mục 26](#26-nhóm-cwe-918-cho-python-và-javascripttypescript-profile-multi-cwe-v06-2026-11-17); đánh giá
  độc lập CWE-918 trên 64 advisory GHSA và bảng năm nhóm CWE cập nhật ở
  [mục 27](#27-đánh-giá-độc-lập-cwe-918-trên-advisory-ghsa-pip-và-npm-multi-cwe-v06-2026-11-17).

## 1. Kết luận ngắn

1. Kiến trúc được chọn là **lượt quét ghép**: một snapshot, một cơ sở dữ liệu CodeQL cho mỗi ngôn
   ngữ, nhiều **nhóm phân tích** (analysis family). Mỗi cảnh báo được định tuyến tới đúng một nhóm
   hoặc ở trạng thái "chưa xác định nhóm"; mỗi nhóm được xử lý bằng **chính mã và profile đã ghim
   hiện có** của nó.
2. Thứ phải trừu tượng hóa ngay rất ít: mô hình phân loại ba trường, khả năng chạy nhiều lượt
   phân tích CodeQL trên một database, và một lớp ghép kết quả theo nhóm. Mọi thứ khác (bộ gộp,
   bằng chứng, chính sách, bước gạn, đường CWE-22) **giữ nguyên**.
3. Chống gộp nhầm CWE bằng **định tuyến trước khi gộp**, không bằng cách đổi khóa đơn vị. Vì vậy
   `unit_id` của các profile cũ không đổi.
4. Không có quy tắc gạn chung cho mọi CWE. Nhóm mới mặc định **chỉ phát hiện và giữ cảnh báo**.
5. P1 chia hai chặng: **P1a** chỉ thêm mã mới và chứng minh bằng một lượt quét ghép thật trên dữ liệu
   phát triển; **P1b** (profile schema, lưu trữ, API, giao diện, hiệu năng) chỉ mở khi P1a đạt.

## 2. Trạng thái Git khi viết (đã kiểm tra, không thay đổi gì)

| Mục | Kết quả |
|---|---|
| Nhánh, HEAD | `feat/cwe22-triage`, `837c53d700dae0ab0686598c49ad444f61b10c76` |
| Nhánh trên origin (`git ls-remote`, đọc trực tiếp từ remote) | `feat/cwe22-triage` ở `ac014a2` |
| Chênh lệch | Local đi trước **1 commit**, origin không có commit nào local thiếu (`ac014a2` là tổ tiên của HEAD) |
| Commit chưa push | `837c53d docs: align the conclusion and chapter 3 wording with the measured results` (2 file dưới `docs/thesis/`) |
| Working tree | Sạch, trừ PDF đề cương chưa theo dõi (không được stage) |
| Khác | Không có nhánh `main` cục bộ (`origin/main` ở `b35413d`); có một worktree khác ở `.kilo/worktrees/cloud-argon` (HEAD tách rời `9299543`) — không đụng tới |

Hệ quả: mọi tham chiếu "HEAD `837c53d`" trong tài liệu này là **commit chỉ có ở máy cục bộ**. Việc
push là quyết định của chủ đề án; không reset, không ghi đè.

## 3. Hiện trạng đã truy vết

Truy vết trên mã nguồn, không theo README. Đường dẫn tương đối tính từ `backend/app/` trừ khi ghi khác.

### 3.1 Luồng hiện tại

```mermaid
flowchart TD
  A["POST /projects/:id/scans"] --> B["snapshots.py: tải, kiểm hash, giải nén"]
  B --> C{"Loại profile (task.py)"}
  C -- "ScanProfile (command-injection-v0.x)" --> D["run_pipeline: Semgrep, Bandit/ESLint, CodeQL"]
  D --> D2["Bước bằng chứng: semgrep-evidence, codeql-evidence"]
  D2 --> E["Định vị sink (chỉ lời gọi thực thi lệnh)"]
  E --> F["reconcile-v0.1: mọi cảnh báo so với mọi sink"]
  F --> G["claims + evidence + chính sách P1-P4/U"]
  G --> H["adjudicate: ứng viên, G1-G4"]
  C -- "EvidenceProfile (path-traversal-v0.2)" --> I["run_pipeline: chỉ CodeQL, pack riêng (none + all)"]
  I --> J["assess_with_evidence: đơn vị = vị trí baseline, P1/P4"]
  H --> K["persist.py: một transaction"]
  J --> K
  K --> L["API: units, report, report.sarif"]
```

### 3.2 Từng bước và file

| Bước | File và hàm | Phụ thuộc CWE |
|---|---|---|
| Thu nhận nguồn | `workflows/scans/snapshots.py`, `scanners/sources.py`, `scanners/acquisition.py` | Không. Ngôn ngữ theo `SOURCE_EXTENSIONS` (python; javascript gồm cả TS) |
| Chạy công cụ | `scanners/pipeline.py::run_pipeline`; `semgrep.py`, `codeql.py`, `bandit.py`, `eslint.py` | Không: rule và truy vấn đến từ profile. Giới hạn cấu trúc: một pack CodeQL chính (`query_pack_for_language`), **một** bước `codeql-evidence`, **một** file luật `semgrep-evidence` |
| Chuẩn hóa SARIF | `scanners/sarif.py::sarif_findings` | Không. Giữ nguyên `raw_result`; `reported_cwes` lấy bằng regex từ metadata rule |
| Định vị sink | `triage/sinks_python.py`, `triage/sinks_javascript.py`, `scanners/semgrep.py::run_sink_locator`, `experiments/locators/sink-locator-v{0,1}-javascript.yaml` | Chỉ CWE-78 |
| Đối chiếu | `triage/reconcile.py::reconcile_findings` | Lẫn lộn (mục 3.3, 3.5) |
| Phân loại rule | `triage/claims.py::classify_claims`, `triage/assess.py::verified_definitions` | Cơ chế chung, có hai chỗ viết cứng |
| Bằng chứng theo đơn vị | `triage/evidence.py::EvidenceIndex` | Lẫn lộn |
| Chính sách ưu tiên | `triage/policy.py` | Bộ máy chung, bộ vị từ cố định |
| Gạn | `triage/adjudicate.py::adjudicate` | Lẫn lộn |
| Đường CWE-22 | `triage/safety_evidence.py::assess_with_evidence`, `workflows/scans/analysis.py::scan_language_evidence`, `scanners/profile.py::load_evidence_profile` | Riêng CWE-22 |
| Điều phối | `workflows/scans/analysis.py::scan_language`, `workflows/scans/task.py::scan_snapshot` | Rẽ nhánh `isinstance(profile, EvidenceProfile)` |
| Lưu | `workflows/scans/persist.py`, `features/triage/models.py`, `features/findings/models.py` | Chung, có ràng buộc mang từ vựng CWE-78 |
| Báo cáo, API | `workflows/scans/report.py`, `service.py`, `schemas.py` | Chung, không có chiều CWE |
| CLI nghiên cứu | `experiments/run_pilot.py` | Dùng chung `app.scanners` và `app.triage`; gắn với chính sách v0.1 |

### 3.3 Thành phần viết cứng cho CWE-78

| File | Ký hiệu | Nội dung |
|---|---|---|
| `triage/assess.py` | `_CODEQL_RULES`, `codeql_rule_id` | Chỉ biết hai truy vấn `Security/CWE-078/*.ql`; truy vấn khác ném `ValueError` |
| `triage/claims.py` | `classify_claims` | `candidate_status: "cwe78_candidate"` |
| `triage/reconcile.py` | `SHELL_COMMAND_KINDS`, `_JS_PROCESS_KINDS`, `shell_state`, `argument_role`, `_related_shell_location` | Vai trò đối số `shell_command` / `executable` / `argument_list`; liên kết `[shell command](n)` trong thông điệp CodeQL. `argument_role` nằm trong khóa đơn vị |
| `triage/evidence.py` | `_argument_span`, `_literal_proof`, `_safe_command`, `_INTERPRETERS`, `_SUBPROCESS`, `_JS_SPAWN`; trong `_trace` và `EvidenceIndex.build` | Điểm cuối hợp lệ của vết luồng là vai trò lệnh; chứng minh "toàn bộ lệnh là hằng"; vị từ `shell_semantics`; các trường `shell_state`, `command_literal` |
| `triage/policy.py` | `PREDICATES`, `apply_policy` | Đúng mười vị từ, kiểm "exactly ten" |
| `triage/adjudicate.py` | `_BANDIT_LITERAL_TESTS`, `_SHELL_STRING_SINKS`, `_literal_rule` (G2), `_constant_rule` (G4), `_REASONS`; chữ ký `adjudicate` | G2 và G4 là ngữ nghĩa lệnh; ba tham số bằng chứng cố định (`codeql_evidence`, `semgrep_evidence`, `constant_evidence`) |
| `triage/sinks_python.py` | `_SUPPORTED_MODULES`, `_canonical_supported` | `os`, `subprocess`, `asyncio`, `pty` |
| `triage/sinks_javascript.py` | `_CHILD_METHODS`, `_direct_child_aliases`, `_canonical_kind` | `child_process`, `shelljs` |
| `workflows/scans/analysis.py` | `_locate_sinks`, `_codeql_evidence`, `_semgrep_evidence`, `_constant_evidence` | Một khối `adjudication` cho mỗi ngôn ngữ |
| `features/triage/models.py` | `ck_location_unit_argument_role` | CHECK chỉ cho ba vai trò lệnh |
| `workflows/scans/schemas.py` | `ScanCreate.profile`, `UnitDetail.shell_state`, `UnitDetail.blocker_proof` | Danh sách profile là `Literal`; trường chi tiết mang ngữ nghĩa lệnh |
| `frontend/src/features/scans/` | `api/create-scan.ts`, `components/units-table.tsx`, `components/unit-detail-sheet.tsx` | Nhãn profile; cột `argument_role`; khối `shell_state`, `blocker_proof` |
| `experiments/run_pilot.py` | `LOCATOR_RULE`, `POLICY_FILE`, `CLAIMS_FILE` | Gắn với locator v0, chính sách v0.1, rule-claims-v2; chỉ nhận Semgrep và CodeQL |

### 3.4 Thành phần riêng của CWE-22

- `scanners/profile.py`: `EvidenceProfile`, `load_evidence_profile` (bắt buộc `scanners == ["codeql"]`,
  không có luật Semgrep, mọi truy vấn nằm trong pack của profile).
- `workflows/scans/analysis.py::scan_language_evidence`: dùng pack của profile làm pack chính, chỉ đánh
  giá khi lượt quét `completed`.
- `triage/safety_evidence.py::assess_with_evidence`: mỗi vị trí cảnh báo của truy vấn baseline
  (`st/cwe-22/none`) là một đơn vị; khóa đơn vị gồm `baseline_rule`; còn bị truy vấn bằng chứng
  (`st/cwe-22/all`) báo thì P1, không còn thì P4 và `filtered`; rule lạ hoặc cảnh báo bằng chứng nằm
  ngoài baseline ném `ValueError`. Không có bộ định vị sink, không rule-claims, không file chính sách.
- Khác với CWE-78: kết quả của truy vấn bằng chứng **được lưu như cảnh báo** và gắn vào đơn vị;
  ở CWE-78 kết quả bước bằng chứng không bao giờ là cảnh báo.
- Pack [rules/codeql/path-traversal-v0.2/](../../rules/codeql/path-traversal-v0.2/README.md), trùng
  từng byte với bản nghiên cứu đã đóng băng.

### 3.5 Thành phần tái sử dụng được nguyên trạng

- Toàn bộ thu nhận nguồn; `run_pipeline` (chạy song song, lỗi độc lập từng công cụ, trạng thái
  `completed/partial/failed`); `process.invoke`; `provenance`; kiểm hash profile (`_verified`, `_pinned`).
- `sarif_findings`; `assert_finding_conservation`; cơ chế phân loại rule theo hash định nghĩa.
- Kỹ thuật **thu thập và đối chiếu bằng chứng**: `codeql.py::run_codeql_evidence` (chạy truy vấn đã
  ghim trên chính database của lượt quét, có `--rerun`), `adjudicate.py::codeql_evidence_index`,
  `semgrep_evidence_index`, `_trace_lines`.
- Bộ máy chính sách (`matches`, `validate_policy`, `apply_policy`), cách nhóm ứng viên, bộ mã lý do giữ.
- `persist.py`, `report.py`, xuất SARIF hợp nhất.
- Thư viện `SafetyEvidence.qll` của nghiên cứu đã được tham số hóa theo CWE cho Python
  (`experiments/owasp-bp-pilot/ql_v02/gen.py` sinh truy vấn cho 22, 78, 79, 643). Đây là hiện vật đã
  khóa; chỉ là điểm xuất phát cho các nhóm sau này, không dùng trong P1.

### 3.6 Quan sát phụ khi truy vết

Ghi lại để không bị quên; **không** sửa trong P1a.

1. `reported_cwes` không được chuẩn hóa: cùng một CWE có thể xuất hiện là `cwe-78`, `cwe-078` hay
   `CWE-78` tùy công cụ (`backend/tests/scanners/test_sarif.py` khẳng định dạng `cwe-78`). Hiện không
   quyết định nào dùng trường này; nó chỉ được lưu vào `findings.cwe_ids`.
2. `workflows/scans/results.py::LOCATOR_VERSION = "sink-locator-v0"` là giá trị mặc định mà
   `scan_language` không ghi đè, nên lượt quét bằng `command-injection-v0.3` (dùng locator v1) vẫn lưu
   `locator_version = "sink-locator-v0"`.
3. `workflows/scans/task.py::SCANNER_STEPS = 5` đếm Semgrep, Bandit/ESLint, CodeQL create, CodeQL
   analyze và sink locator; hai bước `semgrep-evidence` và `codeql-evidence` không nằm trong ngân sách
   thời gian của Celery.
4. Hai gói bằng chứng CodeQL hiện có khai **cùng tên pack** `security-triage/python-safety-evidence`
   (cùng hash `qlpack.yml`), nên không được giả định là có thể đưa chung vào một lệnh `analyze`.

### 3.7 Ràng buộc khóa đã xác minh

- Bốn manifest `profiles/*/profile.json` và mọi file chúng ghim là tài liệu khóa.
- Các `PREREGISTRATION.json` của `experiments/evaluation/independent*` ghim hash của
  `triage/reconcile.py`, `triage/adjudicate.py`, `scanners/acquisition.py` và
  `workflows/scans/analysis.py`. `FROZEN_CONFIGURATION*.json` của `pairs-v1` ghim thêm toàn bộ
  `triage/*.py` và `scanners/semgrep.py`.
- `experiments/tests/test_evaluation.py::_assert_registered` đọc từng file theo đường dẫn: file phải
  còn ở chỗ cũ, và nếu byte khác thì phải có bản ghi trong
  [PIPELINE_CHANGES.json](../../experiments/evaluation/PIPELINE_CHANGES.json). Hiện có hai bản ghi
  (`adjudicate.py`, `analysis.py`).
- `experiments/run_pilot.py::runner_files_sha256` và `pairs-v1/freeze.py` liệt kê `triage/*.py` bằng
  glob không đệ quy: file mới trong `app/triage/` sẽ làm đổi tập file mà các bản ghi đó mô tả.
- Không file nào trong `scanners/codeql.py`, `scanners/pipeline.py`, `scanners/sarif.py`,
  `scanners/profile.py` bị ghim bởi một bản đăng ký nào.

## 4. Đánh giá lại: trừu tượng hóa gì ngay, giữ nguyên gì

Câu hỏi kiểm tra cho mỗi thành phần: *để một snapshot được quét cho hai nhóm CWE sẵn có và cho kết
quả đúng, có bắt buộc phải sửa nó không?*

| Thành phần | Quyết định | Lý do |
|---|---|---|
| Mô hình phân loại cảnh báo (nhãn gốc, ánh xạ, nhóm xử lý) | **Làm ngay**, module mới | Hiện không có khái niệm "cảnh báo này thuộc nhóm nào"; đây là điều kiện để không gộp nhầm |
| Nhiều lượt phân tích CodeQL trên một database, mỗi lượt có tên riêng | **Làm ngay**, một tham số bổ sung | Hai nhóm dùng hai pack khác nhau; không thì phải trích xuất hai lần |
| Lớp ghép: chạy công cụ một lần, định tuyến, gọi bộ xử lý từng nhóm, kiểm bảo toàn toàn cục | **Làm ngay**, module mới | Thay cho rẽ nhánh theo loại profile, nhưng ở P1a chỉ là đường mới chạy song song |
| Bộ xử lý nhóm CWE-78 và CWE-22 | **Làm ngay**, dạng vỏ mỏng | Gọi lại đúng `_assess_pipeline` và `assess_with_evidence` hiện có |
| `reconcile.py`, `evidence.py`, `policy.py`, `adjudicate.py`, `claims.py`, `assess.py`, `sinks_*.py` | **Giữ nguyên** | Chỉ nhận cảnh báo của nhóm lệnh nên phần viết cứng CWE-78 vẫn đúng chỗ. Tách chúng ra chỉ cần khi có nhóm thứ hai đi qua bộ gộp |
| `safety_evidence.py` | **Giữ nguyên** | Là điều kiện gạn đã đo của CWE-22; viết lại sẽ làm mất liên hệ với kết quả đã đánh giá |
| Khóa đơn vị, khóa ứng viên, `RECONCILIATION_VERSION` | **Giữ nguyên** | Định tuyến trước khi gộp đã đủ ngăn gộp nhầm (mục 5.3); hai nhóm có khóa khác cấu trúc nên không trùng |
| Bộ vị từ chính sách | **Giữ nguyên** | Mỗi nhóm vẫn dùng chính sách riêng đã ghim của nó |
| Loader profile, manifest | **Giữ nguyên ở P1a** | Lượt quét ghép được dựng từ hai profile đã ghim; schema mới để P1b |
| Bảng dữ liệu, API, giao diện | **Giữ nguyên ở P1a** | P1a chứng minh ở mức hiện vật của lượt quét (JSON), không qua cơ sở dữ liệu |
| `run_pilot.py`, mọi thứ dưới `experiments/` | **Giữ nguyên** | Thực nghiệm lịch sử không phụ thuộc đường mới |

Kết quả: P1a sửa đúng **một** file ứng dụng hiện có (`scanners/codeql.py`, thêm một tham số có giá
trị mặc định), còn lại là file mới và kiểm thử.

## 5. Kiến trúc đích

### 5.1 Nguyên tắc tương đương

> Với cùng snapshot và cùng công cụ đã ghim, kết quả của mỗi nhóm trong lượt quét ghép phải bằng kết
> quả của việc quét riêng nhóm đó bằng profile hiện có của nó, trừ các khác biệt được liệt kê tường
> minh.

Nguyên tắc này vừa là tiêu chí nghiệm thu, vừa là lý do dùng lại mã cũ: nhóm lệnh và nhóm đường dẫn
trong lượt quét ghép chạy đúng các hàm mà hai profile hiện tại đang chạy.

Khác biệt được phép (và phải có kiểm thử khẳng định đúng danh sách này):

| Khác biệt | Lý do |
|---|---|
| `raw_id` của cảnh báo từ lượt phân tích pack CWE-22 mang tiền tố tên lượt (`codeql-path-traversal:…` thay cho `codeql:…`), kéo theo `raw_finding_ids`, `mappings[].raw_id`, `refuted_raw_ids` | Hai lượt phân tích CodeQL trong cùng một ngôn ngữ sẽ trùng `codeql:0:n` nếu không tách; `raw_id` phải duy nhất để kiểm bảo toàn |
| Tên bước: lượt pack CWE-22 là `codeql-path-traversal`, dùng chung `codeql-create` | Một database cho cả hai nhóm |
| Tiền tố trong mã rule của Semgrep (`out.run-01.composite.python.subprocess-shell-true`) | Semgrep ghép đường dẫn thư mục chứa file luật đã stage vào mã rule; hai lượt quét ghi ra hai thư mục. Không phải khác biệt của lượt ghép: hai lượt quét riêng bất kỳ cũng khác nhau ở đây. Phát hiện ở lượt quét thật (mục 16) |
| `index` của artifact trong `raw_result` của CodeQL | Là vị trí trong bảng artifact của riêng một lượt chạy; đường dẫn artifact không đổi. Phát hiện ở lượt quét thật (mục 16) |

Cảnh báo của nhóm lệnh đến từ cùng một lời gọi `run_pipeline` như khi quét riêng nên `raw_id` của
chúng không đổi; khóa đơn vị của nhóm đường dẫn không chứa `raw_id`. Vì vậy `unit_id`, khóa ứng viên, mức ưu tiên, `decision_id`, lý do, `disposition`, hash chính sách và phiên
bản (`reconcile-v0.1`, `adjudicate-v0.3`, `safety-evidence-units-v1`) không được khác.

### 5.2 Luồng đa CWE

```mermaid
flowchart TD
  A["Snapshot đã kiểm hash"] --> B["Công cụ phát hiện chạy một lần mỗi ngôn ngữ: Semgrep, Bandit/ESLint"]
  A --> C["CodeQL: database create (một lần)"]
  C --> D1["Lượt phát hiện: pack upstream, truy vấn của nhóm lệnh"]
  C --> D2["Lượt pack path-traversal-v0.2: none (phát hiện) + all (bằng chứng)"]
  C --> D3["Lượt bằng chứng: pack command-injection-evidence-v0.2"]
  B --> E["Chuẩn hóa SARIF: giữ raw_result và reported_cwes"]
  D1 --> E
  D2 --> E
  D3 --> X["Kết quả bằng chứng: không bao giờ là cảnh báo"]
  E --> F["Phân loại: reported_cwes, mapped_cwes, analysis_family"]
  F --> G1["Nhóm command-injection"]
  F --> G2["Nhóm path-traversal"]
  F --> G3["Chưa xác định nhóm"]
  G1 --> H1["Mã hiện có: định vị sink, reconcile-v0.1, chính sách v0.2, G1-G4"]
  X --> H1
  G2 --> H2["Mã hiện có: assess_with_evidence, P1/P4"]
  G3 --> H3["Đơn vị riêng, mức U, luôn ở danh sách rà"]
  H1 --> I["Ghép kết quả: kiểm bảo toàn toàn cục, trạng thái theo nhóm, chi phí từng bước"]
  H2 --> I
  H3 --> I
  I --> J["Hiện vật lượt quét (P1a) / lưu, API, báo cáo (P1b)"]
```

### 5.3 Mô hình phân loại

Ba trường tách biệt, không trường nào thay thế trường nào:

| Trường | Ý nghĩa | Nguồn | Được sửa bởi hệ thống? |
|---|---|---|---|
| `reported_cwes` | Nhãn nguyên bản công cụ gắn cho rule | SARIF, như `sarif_findings` đọc hôm nay | Không bao giờ; kể cả không chuẩn hóa tại chỗ |
| `mapped_cwes` | Danh sách CWE có căn cứ của rule; một rule **có thể có nhiều** CWE (ví dụ `py/command-line-injection` → CWE-78, CWE-88) | Trường `mapped_cwes` của rule-claims đã ghim, chỉ khi định nghĩa rule khớp hash; với pack CWE-22 là id truy vấn đã ghim trong manifest và README của pack | Không; rỗng nếu không có căn cứ, kèm `mapped_cwes_basis` |
| `analysis_family` | Nhóm ngữ nghĩa dùng để xử lý: `command-injection`, `path-traversal`, hoặc `null` | Quy tắc định tuyến bên dưới | Không; kèm `family_status`, `family_basis`, `unresolved_reason` |

Quy tắc định tuyến, theo thứ tự:

1. **Theo lượt chạy.** Nếu lượt chạy công cụ sinh ra cảnh báo chỉ phục vụ một thành viên (chỉ chạy
   rule/truy vấn đã ghim của profile đó) thì nhóm là nhóm của thành viên đó
   (`family_basis: "pass_provenance"`). Ở P1a mọi lượt chạy đều thuộc loại này.
2. **Theo rule đã ghim.** Nếu một lượt chạy phục vụ nhiều thành viên, nhóm là thành viên duy nhất
   khai rule đó với định nghĩa khớp hash (`family_basis: "pinned_rule_set"`).
3. **Chưa xác định.** Không thành viên nào khai rule (`rule_not_claimed`), định nghĩa không khớp hash
   (`definition_unverified`) hoặc nhiều hơn một thành viên khai (`ambiguous_family`) thì
   `analysis_family = null`, `family_status = "unresolved"`.

Cảnh báo chưa xác định nhóm: giữ nguyên mọi nhãn, thành một đơn vị riêng theo vị trí báo, mức `U`,
`disposition = review`, không quy tắc gạn nào được áp dụng, không gộp với đơn vị của nhóm nào.

Hai trạng thái không được nhập làm một: *chưa xác định nhóm* (ở tầng định tuyến) và
`classification_unresolved` (rule không khớp rule-claims, đã có sẵn trong nhóm lệnh và được chính
sách của nhóm đó đưa về `U`).

Vì sao định tuyến đủ để chống gộp nhầm: bộ gộp `reconcile-v0.1` so mọi cảnh báo nó nhận với mọi sink
lệnh và chọn sink trong cùng chứa vùng báo. Nếu cảnh báo CWE-22 ở đối số `open(p)` nằm trong
`os.system("cat " + open(p).read())` được đưa vào bộ gộp này, nó sẽ bị nhập vào đơn vị của lời gọi
`os.system`. Khi cảnh báo đó không bao giờ tới bộ gộp của nhóm lệnh, lỗi này không thể xảy ra, và
không cần đổi khóa đơn vị.

### 5.4 Bộ xử lý nhóm

Một bộ xử lý là một hàm có cùng chữ ký: nhận cảnh báo đã định tuyến của nhóm, kết quả các lượt chạy
mà nhóm phụ thuộc và profile đã ghim của nhóm; trả về đơn vị, đánh giá, phiên bản và trạng thái.
Đăng ký bằng một `dict`; không có lớp cơ sở, không plugin.

| Nhóm | Thành viên (profile đã ghim) | Bộ xử lý gọi | Chính sách | Điều kiện gạn |
|---|---|---|---|---|
| `command-injection` | `command-injection-v0.3` (hoặc v0.1, v0.2) | `analysis._assess_pipeline` hiện có | `priority-v0.2` đã ghim | G1–G4 như hiện có |
| `path-traversal` | `path-traversal-v0.2` | `safety_evidence.assess_with_evidence` hiện có | P1/P4 của profile | Truy vấn `st/cwe-22/all` không còn báo vị trí baseline |
| (chưa xác định) | — | Đơn vị dự phòng qua `reconcile_findings` với danh sách sink rỗng | `U` cố định | Không có |

Phần ngữ nghĩa CWE-78 trong `reconcile.py`, `evidence.py`, `adjudicate.py` **không** được tách thành
giao diện nhiều hàm ở P1. Hợp đồng chi tiết hơn (định vị sink, vai trò đối số, điểm cuối vết luồng,
vị từ riêng) chỉ được thiết kế khi có nhóm thứ hai cần đi qua bộ gộp; xem [mục 12](#12-chưa-nên-triển-khai).

### 5.5 Quản lý CodeQL

- **Một database cho mỗi ngôn ngữ.** `run_codeql` tạo database như hôm nay; các lượt sau dùng lại nó,
  đúng kỹ thuật mà bước `codeql-evidence` đang dùng.
- **Không ép gộp pack.** Mỗi pack là một lượt `database analyze` riêng, có tên bước, file SARIF, log,
  thời gian và số kết quả riêng. Hai pack tự viết trùng tên pack nên càng không được đưa chung một lệnh.
- **Phân biệt phát hiện với bằng chứng** ở mức kết quả:

  | Lượt | Pack | Vai trò kết quả |
  |---|---|---|
  | `codeql` | `codeql/python-queries` đã ghim | Phát hiện (cảnh báo của nhóm lệnh) |
  | `codeql-path-traversal` | `rules/codeql/path-traversal-v0.2` | `cwe22_none`: phát hiện; `cwe22_all`: bằng chứng, nhưng được lưu như cảnh báo gắn vào đơn vị, đúng hành vi của profile hiện tại |
  | `codeql-evidence` | `rules/codeql/command-injection-evidence-v0.2` | Bằng chứng; không bao giờ là cảnh báo |

- **Ghi chi phí thực tế.** Mỗi bước giữ `seconds` (đã có trong `ProcessRecord`); `run.json` của lượt
  quét ghép ghi thêm bước đó phục vụ nhóm nào và thuộc loại nào. Lượt `codeql-path-traversal` chạy hai
  truy vấn trong một lệnh như profile hiện tại, nên chi phí phát hiện và chi phí bằng chứng của nó
  không tách được nếu không đổi cách chạy pack; tài liệu kết quả phải nói rõ điều này.
- **Điều kiện ghép.** Các thành viên phải cùng phiên bản CodeQL và cùng ngôn ngữ; nếu không, lượt quét
  ghép từ chối chạy thay vì âm thầm chọn một phiên bản.
- **Không tối ưu ở P1a.** Các lượt chạy tuần tự; song song hóa và giới hạn thời gian của Celery thuộc P1b.

### 5.6 Thẩm định và gạn theo nhóm

Lõi chung chỉ cung cấp **kỹ thuật**: chạy truy vấn/luật bằng chứng đã ghim, lập chỉ mục vị trí của
truy vấn đối chứng và truy vấn bằng chứng, đối chiếu vết luồng với các dòng mã. Lõi **không** chứa
điều kiện gạn nào áp dụng cho mọi nhóm. Mỗi điều kiện gạn thuộc về một nhóm, gắn với một gói bằng
chứng cụ thể và với kết quả kiểm chứng của chính nó:

| Điều kiện | Nhóm | Bằng chứng đã có (nguồn: [research.md](../research.md), [thesis/commitments.md](../thesis/commitments.md)) |
|---|---|---|
| G1 — truy vấn bằng chứng CodeQL không còn báo luồng | `command-injection`, Python | OWASP BenchmarkPython (dữ liệu phát triển): gạn 2/7 cảnh báo sai, 0/13 cảnh báo đúng |
| G2 — lệnh là hằng, Bandit xác nhận | `command-injection`, Python | Đợt độc lập 5 (không có nhãn): gạn 19/145 ứng viên; phép kiểm đã đăng ký chấp nhận 17, hai ca còn lại khi đọc lại là lệnh hằng bọc trong lời gọi khác |
| G3 — luồng chỉ qua nhánh không bao giờ chạy | `command-injection`, Python | OWASP (phát triển): 1/7 cảnh báo sai |
| G4 — chuỗi lệnh `exec`/`execSync` là hằng | `command-injection`, JS/TS | 84 package (phát triển): 1/11 cảnh báo sai, 0/122 cảnh báo đúng |
| Pack v0.2 loại mọi luồng tới vị trí baseline | `path-traversal`, Python | Benchmark: 49/53 cảnh báo sai ở nửa kiểm tra; mã thật: 4/43 cảnh báo sai, 0/7 cảnh báo đúng (một người rà, không mù) |

Quy tắc cho nhóm mới: **mặc định không có điều kiện gạn** — phát hiện, gộp nếu có căn cứ, xếp ưu
tiên, giữ mọi ứng viên ở danh sách rà. Một điều kiện gạn chỉ được bật cho một nhóm sau khi có gói
bằng chứng ghim hash, bộ phản ví dụ, và một lượt đo theo giao thức được ghi trước khi quét. Tên G1
hay G3 không tự chuyển sang nhóm khác: cùng kỹ thuật trên nhóm khác là một điều kiện mới, có mã
riêng và phải được đo riêng.

### 5.7 Trạng thái và lỗi công cụ

- Mức độ hoàn tất được tính **theo nhóm**, trên các lượt chạy mà nhóm đó phụ thuộc. Lỗi của lượt chỉ
  phục vụ nhóm B không làm đổi kết quả của nhóm A so với khi quét riêng A.
- Lỗi của bước dùng chung (ví dụ `codeql-create`) ảnh hưởng mọi nhóm phụ thuộc, đúng như khi quét riêng:
  nhóm lệnh vẫn được đánh giá bằng cảnh báo của công cụ sàng lọc nhưng không gạn gì; nhóm đường dẫn
  không xếp hạng gì.
- Một nhóm có bộ xử lý ném lỗi (ví dụ rule lạ trong lượt pack CWE-22) được ghi là thất bại kèm lỗi;
  cảnh báo thô của nó vẫn nằm trong `findings.json`; các nhóm khác tiếp tục.
- Trạng thái lượt quét theo đúng quy tắc hiện có của `task._overall`, áp dụng trên trạng thái các nhóm.

## 6. Đặc tả bất biến

### 6.1 Bảo toàn cảnh báo gốc

| # | Bất biến | Kiểm bằng |
|---|---|---|
| B1 | Mỗi kết quả SARIF của lượt phát hiện xuất hiện đúng một lần trong `findings.json`, với `raw_result` và `reported_cwes` y nguyên | So số kết quả từng file SARIF với số cảnh báo theo lượt |
| B2 | Mỗi cảnh báo thuộc đúng một đơn vị của đúng một nhóm, hoặc đúng một đơn vị "chưa xác định nhóm" | Mở rộng `assert_finding_conservation` trên hợp các nhóm |
| B3 | `raw_id` duy nhất trong một ngôn ngữ của lượt quét | Kiểm khi ghép; trùng là lỗi, không tự đổi tên |
| B4 | Kết quả của bước bằng chứng thuần túy không bao giờ thành cảnh báo hay đơn vị | Như hiện nay (`evidence_findings` tách riêng) |
| B5 | Phân loại là bản ghi bổ sung theo `raw_id`; không ghi đè trường nào của cảnh báo | So `findings.json` trước và sau phân loại |
| B6 | Gạn chỉ đổi `disposition`; đơn vị, cảnh báo, bằng chứng và lý do vẫn còn | Như hiện nay |
| B7 | Nhóm thất bại không làm mất cảnh báo thô của nó | Kiểm thử lỗi công cụ |

### 6.2 Chống gộp nhầm CWE

- Bộ gộp và bộ đánh giá của một nhóm chỉ nhận cảnh báo đã định tuyến cho nhóm đó.
- Không đơn vị nào chứa cảnh báo của hai nhóm; không ứng viên nào chứa đơn vị của hai nhóm.
- Điều kiện gạn của nhóm W chỉ đọc cảnh báo và bằng chứng của W. Cảnh báo của nhóm khác ở cùng vị
  trí không chặn, cũng không kích hoạt việc gạn.
- Cảnh báo chưa xác định nhóm không được dùng làm "xác nhận độc lập" cho nhóm nào.

### 6.3 Thiếu bằng chứng

Nguyên tắc chung giữ nguyên: thiếu bằng chứng thì giữ; **vắng cảnh báo không phải là bằng chứng**.

| Tình huống | Hành động | Mã lý do |
|---|---|---|
| Lượt chạy mà nhóm phụ thuộc bị `partial` hoặc `failed` | Nhóm lệnh: không gạn gì. Nhóm đường dẫn: không xếp hạng gì (như profile hiện tại) | `run_incomplete` (đã có) |
| Bước bằng chứng thất bại | Điều kiện dùng bước đó không gạn | `evidence_step_failed` (đã có) |
| Truy vấn đối chứng không báo đúng cảnh báo này | Giữ | `evidence_baseline_does_not_report_this_alert` (đã có) |
| Công cụ khác khẳng định luồng mà không có vết | Giữ | `flow_claim_without_a_trace_to_check` (đã có) |
| Nhóm không có gói bằng chứng | Giữ mọi ứng viên | `no_refuting_evidence` (đã có) |
| Rule không khớp rule-claims | Mức `U` theo chính sách của nhóm | `classification_unresolved` (đã có) |
| Không định vị được sink | Đơn vị dự phòng, mức `U` | `unmapped` (đã có) |
| Không xác định được nhóm | Đơn vị riêng, mức `U`, luôn ở danh sách rà | `rule_not_claimed`, `definition_unverified`, `ambiguous_family` (mới, chỉ ở đường mới) |
| Truy vấn bằng chứng báo vị trí ngoài baseline | Nhóm thất bại, không xếp hạng | Lỗi của `assess_with_evidence` (đã có) |

### 6.4 Hành vi của bốn profile hiện tại

- Bốn manifest và mọi file chúng ghim không đổi một byte.
- Ở P1a, đường thực thi của bốn profile (`scan_language`, `scan_language_evidence`, `task.scan_snapshot`)
  không bị sửa; thay đổi duy nhất chạm tới mã chúng gọi là tham số bổ sung có giá trị mặc định ở
  `run_codeql_evidence`.
- Kiểm thử hồi quy "golden" ([mục 11](#11-kiểm-thử-bảo-đảm-không-phá-hành-vi-cũ)) phát hiện mọi thay
  đổi ngoài ý muốn ở đơn vị, đánh giá và bản ghi cảnh báo.
- Job CI `scan-parity` (CLI và API cho cùng kết quả trên `curling@0.2.0`) phải tiếp tục qua mà không
  sửa `experiments/run_pilot.py`.

## 7. Quyết định và lý do

| # | Quyết định | Lý do | Phương án bị loại |
|---|---|---|---|
| D1 | Phân loại bằng ba trường `reported_cwes`, `mapped_cwes`, `analysis_family`; có trạng thái chưa xác định nhóm | Một rule có thể mang nhiều CWE; nhãn của công cụ không đủ tin để định tuyến nhưng không được mất | Buộc mỗi rule đúng một CWE; lấy CWE từ `reported_cwes` |
| D2 | Chống gộp nhầm bằng định tuyến trước khi gộp; không đổi khóa đơn vị | Giữ nguyên `unit_id` đã dùng trong các đánh giá; không cần sửa `reconcile.py` (bị ghim) | `reconcile-v0.2` có nhóm trong khóa |
| D3 | Lượt quét ghép dựng từ các **profile đã ghim hiện có** | Mỗi nhóm chạy đúng cấu hình đã được đánh giá; không cần schema mới để chứng minh | Profile schema 2 ngay từ đầu |
| D4 | Bộ xử lý nhóm là vỏ mỏng gọi mã hiện có | Thay đổi ít nhất; nguyên tắc tương đương kiểm được | Giao diện nhiều hàm và di chuyển mã CWE-78 |
| D5 | Không có điều kiện gạn chung; nhóm mới mặc định chỉ phát hiện và giữ | Mỗi điều kiện gạn chỉ có căn cứ trên nhóm và dữ liệu nó đã được đo | G1/G3 thành quy tắc lõi cho mọi CWE |
| D6 | Một database CodeQL, mỗi pack một lượt phân tích có tên; phân biệt phát hiện và bằng chứng; ghi chi phí | Hai pack hiện có trùng tên; chi phí trích xuất là phần dùng chung được | Gộp mọi truy vấn vào một lệnh `analyze` |
| D7 | P1a chỉ thêm mã; không sửa file bị ghim bởi một bản đăng ký | Thực nghiệm lịch sử và bốn profile không bị ảnh hưởng theo cấu trúc, không cần "hợp thức hóa" | Tái cấu trúc `triage/*.py` và ghi vào `PIPELINE_CHANGES.json` |
| D8 | Mã mới đặt ở `app/workflows/scans/`, không ở `app/triage/` | Tập file `triage/*.py` mà `freeze.py` và `run_pilot.py` liệt kê không đổi | Gói con `app/triage/weaknesses/` |

**Thay đổi so với bản kế hoạch đầu** (đã bị rà và không được duyệt nguyên trạng):

| Bản đầu | Bản này | Vì sao |
|---|---|---|
| Mỗi rule khai đúng một `weakness` | Ba trường, nhiều CWE cho một rule, có trạng thái chưa xác định | Yêu cầu 1 của lượt rà |
| G1 và G3 là quy tắc gạn của lõi chung | Lõi chỉ có kỹ thuật thu thập/đối chiếu; điều kiện gạn theo nhóm | Yêu cầu 2 |
| P1 gồm 11 đầu việc liền mạch, có schema, DB, API, UI | P1a (chứng minh) rồi mới P1b (mở rộng) | Yêu cầu 3 |
| Tách ngữ nghĩa CWE-78 thành bộ xử lý nhiều hàm, đổi khóa đơn vị, vị từ mở rộng | Hoãn; bộ xử lý là vỏ mỏng | Đánh giá lại ở mục 4: không cần để chứng minh |
| Sửa `triage/*.py` tại chỗ và ghi `PIPELINE_CHANGES.json` | Không sửa file bị ghim ở P1a; không ghi tự động | Yêu cầu 5 |
| Bước bằng chứng thành danh sách trong `run_pipeline` | Một tham số tên lượt ở `run_codeql_evidence` | Đủ cho hai nhóm; không sửa `pipeline.py` |

## 8. Nghiên cứu đã đóng băng và quản lý phiên bản

1. **P1a không chạm** file nào bị ghim: không sửa `triage/*.py`, `scanners/semgrep.py`,
   `scanners/acquisition.py`, `workflows/scans/analysis.py`, không sửa gì dưới `experiments/`,
   `profiles/`, `rules/`, `tools/`. Do đó `experiments/tests/test_evaluation.py`,
   `test_research_freeze.py`, `test_product_pack.py` và `test_profile.py` phải qua **mà không sửa bất
   kỳ sổ đăng ký nào**; đây là một tiêu chí nghiệm thu của từng đầu việc.
2. **`PIPELINE_CHANGES.json` không được cập nhật tự động.** Sổ này ghi một thay đổi đã xảy ra với lý
   do cụ thể; nó không phải cách làm cho kiểm thử xanh. Nếu một đầu việc về sau (P1b-7) buộc phải sửa
   file bị ghim, trình tự là: (a) nêu file, hash đã đăng ký và lý do trong đề xuất; (b) chủ đề án
   quyết định; (c) kiểm thử golden chứng minh hành vi của các profile đã đăng ký không đổi; (d) bản
   ghi được viết tay trong cùng commit với thay đổi.
3. **Phiên bản.** Đường mới mang định danh riêng trong hiện vật của nó (ví dụ
   `composition_version: "family-composition-v0.1"`); nó không đổi `RECONCILIATION_VERSION`,
   `ADJUDICATION_VERSION`, `EVIDENCE_UNIT_VERSION` hay phiên bản chính sách nào. Một hành vi mới của
   nhóm đã có luôn là phiên bản mới với profile mới, không phải sửa phiên bản cũ.
4. **Tái lập thực nghiệm lịch sử.** Mỗi lượt chạy đã đăng ký ghi commit của nó (`configuration_commit`
   trong `run.json`, `HELD_OUT_GATE.json`); tái lập là checkout đúng commit đó, không phụ thuộc mã ở
   đầu nhánh. `FROZEN_CONFIGURATION_v0.3.json` là bản ghi của một lượt đã xong: không chạy lại
   `freeze.py write`.
5. **Tách nhánh.** Đề xuất triển khai P1a trên một nhánh mới tách từ commit chứa tài liệu này (ví dụ
   `feat/multi-cwe-core`), để `feat/cwe22-triage` tiếp tục là nhánh của hồ sơ đề án và thực nghiệm.
   Trước đó cần quyết định về commit `837c53d` chưa push (mục 2). Việc tạo nhánh và push do chủ đề
   án thực hiện hoặc yêu cầu.
6. **Dữ liệu.** Lượt quét tích hợp của P1a chỉ dùng dữ liệu phát triển đã xem; không quét
   `pairs-v1`, không quét lại nguồn của các đợt kiểm tra độc lập, không dùng nhãn nào. Kết quả của nó
   là kiểm chứng kỹ thuật, không phải số liệu đánh giá.

## 9. Kế hoạch P1a — chứng minh lõi đa CWE

Mỗi đầu việc là một commit qua được hook. Lệnh kiểm tra chung cho backend (từ `backend/`):
`uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest --cov`; cho
thực nghiệm: lệnh `unittest discover` trong [experiments/AGENTS.md](../../experiments/AGENTS.md).

### P1a-1 — Kiểm thử hồi quy golden cho bốn profile

- **Phạm vi:** chỉ kiểm thử. Chạy `scan_snapshot` với pipeline giả cho từng profile và kịch bản, so
  `units.json`, `assessments.json`, `findings.json` và các hàng đã lưu với file golden đã commit.
- **File:** `backend/tests/workflows/scans/test_legacy_golden.py` (mới),
  `backend/tests/golden/<profile>/<kịch bản>.json` (mới), bổ sung nhỏ ở
  `backend/tests/workflows/scans/fakes.py` nếu archive giả chưa tất định.
- **Kịch bản tối thiểu:** v0.1 (Python và JavaScript); v0.2 (Bandit, G1 gạn, G2 gạn, G3 gạn, bước
  bằng chứng lỗi, lượt quét `partial`); v0.3 (G4 gạn, locator v1); `path-traversal-v0.2` (một vị trí
  giữ, một vị trí hạ, lượt `partial` không xếp hạng).
- **Nghiệm thu:** golden sinh từ mã ở commit chưa có thay đổi ứng dụng nào; bộ kiểm thử qua; một
  thay đổi cố ý ở máy cục bộ (ví dụ đổi mức của một quyết định) làm kiểm thử đỏ và được ghi lại là đã
  thử; không file ứng dụng nào thay đổi.

### P1a-2 — Mô hình phân loại

- **Phạm vi:** hàm thuần túy tính bản ghi phân loại cho từng cảnh báo theo mục 5.3.
- **File:** `backend/app/workflows/scans/classification.py` (mới),
  `backend/tests/workflows/scans/test_classification.py` (mới).
- **Kiểm thử:** rule có nhiều CWE giữ đủ danh sách; `reported_cwes` dạng `cwe-078` không bị sửa; lượt
  chạy một thành viên → `pass_provenance`; lượt chạy hai thành viên với rule của đúng một bên →
  `pinned_rule_set`; rule không ai khai, sai hash, hai bên cùng khai → ba lý do chưa xác định; cảnh
  báo đầu vào không bị thay đổi.
- **Nghiệm thu:** các kiểm thử trên qua; golden P1a-1 không đổi.

### P1a-3 — Lượt phân tích CodeQL có tên trên database sẵn có

- **Phạm vi:** `run_codeql_evidence` nhận thêm `name` (mặc định `"codeql-evidence"`) quyết định tên
  bước, tên file SARIF và tiền tố `raw_id`.
- **File:** `backend/app/scanners/codeql.py`, `backend/tests/scanners/test_codeql.py`.
- **Kiểm thử:** lời gọi không truyền `name` cho đúng argv, tên file và `raw_id` như trước (các kiểm thử
  hiện có không sửa); với tên khác, hai lượt trên cùng database không ghi đè nhau và `raw_id` không trùng.
- **Nghiệm thu:** golden không đổi; đây là thay đổi duy nhất ở file ứng dụng hiện có trong P1a.

### P1a-4 — Bộ xử lý nhóm và lớp ghép

- **Phạm vi:** hai bộ xử lý vỏ mỏng (mục 5.4), xử lý cảnh báo chưa xác định nhóm, hàm ghép cho một
  ngôn ngữ: chạy pipeline của thành viên lệnh, chạy lượt pack của thành viên đường dẫn trên cùng
  database, phân loại, định tuyến, đánh giá từng nhóm, kiểm B1–B7, tính trạng thái theo nhóm, ghi hiện vật.
- **File:** `backend/app/workflows/scans/families.py` (mới),
  `backend/tests/workflows/scans/test_families.py` (mới), fixture nguồn tổng hợp trong thư mục kiểm thử.
- **Ghi chú (đã đổi khi triển khai):** bản kế hoạch định gọi tên riêng tư
  `analysis._assess_pipeline`. Cách đã làm đơn giản hơn và không cần tên riêng tư nào: lớp ghép gọi
  thẳng hai hàm công khai `scan_language` và `scan_language_evidence`, và truyền cho mỗi hàm một
  `run_pipeline_fn` phục vụ kết quả từ lần chạy công cụ dùng chung. Mỗi nhóm vì thế chạy đúng
  đường mã của profile đơn, kể cả phần ghi `run.json`, `units.json`, `assessments.json`.
- **Kiểm thử:** toàn bộ ma trận mức A ở [mục 11.2](#112-kiểm-thử-tích-hợp-của-lượt-quét-ghép).
- **Nghiệm thu:** ma trận qua; golden không đổi; kiểm thử thực nghiệm qua mà không sửa sổ đăng ký.

### P1a-5 — Công cụ dòng lệnh phát triển cho lượt quét ghép

- **Phạm vi:** một CLI chạy trong image worker, không dùng cơ sở dữ liệu hay API: nhận một manifest
  nguồn đã ghim, danh sách thành viên và chế độ `composite` hoặc `separate`; ghi hiện vật vào thư mục
  đầu ra; có lệnh so sánh sinh `comparison.json` theo nguyên tắc tương đương.
- **File:** `backend/scripts/scan_families.py` (mới), kiểm thử trong `backend/tests/test_scripts.py`
  hoặc file mới cạnh đó.
- **Nghiệm thu:** chạy được với pipeline giả trong kiểm thử; chế độ `separate` đi qua đúng
  `scan_language` và `scan_language_evidence` hiện có; đầu ra không chứa mã nguồn được quét.

### P1a-6 — Lượt quét tích hợp thật trên dữ liệu phát triển

- **Phạm vi:** ba lượt trên cùng một snapshot Python có cả hai nhóm: riêng nhóm lệnh, riêng nhóm đường
  dẫn, và ghép. Cần chủ đề án đồng ý trước khi chạy.
- **Snapshot đề xuất:** OWASP BenchmarkPython ở commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`
  (manifest [owasp-benchmarkpython-cwe78-v01.json](../../experiments/cases/owasp-benchmarkpython-cwe78-v01.json),
  `split: development`; đã được dùng làm dữ liệu phát triển cho cả CWE-78 và CWE-22).
- **Thành viên:** `command-injection-v0.3` (Python) và `path-traversal-v0.2`.
- **Ghi nhận:** `comparison.json`, bảng thời gian từng bước (create, từng lượt analyze, tổng; ghép so
  với tổng hai lượt riêng), lệnh đã chạy và kết quả vào [validation.md](../validation.md).
- **Nghiệm thu:**
  1. mỗi nhóm trong lượt ghép bằng lượt riêng của nó, chỉ khác đúng danh sách ở mục 5.1;
  2. B1–B7 đúng; số đơn vị chứa cảnh báo của hai nhóm bằng 0;
  3. chính sách của mỗi nhóm đúng là chính sách đã ghim của nó (hash khớp);
  4. có số đo chi phí thật, kể cả khi lượt ghép không nhanh hơn;
  5. mọi sai lệch được ghi lại nguyên trạng, không quét lại để "sửa" kết quả.

**Cổng P1a → P1b:** P1a-1 đến P1a-6 đạt và chủ đề án xác nhận. Nếu nguyên tắc tương đương không giữ
được, dừng ở đây và xem lại kiến trúc trước khi đụng tới schema, lưu trữ hay API.

## 10. Kế hoạch P1b — chỉ mở sau khi P1a đạt

Phạm vi và tiêu chí ở mức phác; mỗi đầu việc được viết chi tiết khi mở.

| # | Đầu việc | Phạm vi | Tiêu chí nghiệm thu |
|---|---|---|---|
| P1b-1 | Profile ghép (schema 2) | Manifest mới ghim **manifest của các thành viên** theo hash; loader, `scripts/check_worker.py`, `core/config.py` | Manifest cũ nạp như trước (kiểm thử `test_profile.py` hiện có không sửa); profile ghép sai hash bị từ chối |
| P1b-2 | Lưu trữ | Migration `0008`: cột nhóm ở `location_units`; bản ghi phân loại của cảnh báo; đọc kết quả của lượt quét có nhiều phiên bản đơn vị/chính sách (hiện `service._results` lọc theo một cặp phiên bản của lượt quét) | Lượt quét cũ đọc ra như trước; `alembic check` và vòng downgrade → upgrade qua |
| P1b-3 | Worker | `scan_snapshot` chạy profile ghép; lượt phân tích bổ sung thành `tool_runs`; ngân sách thời gian tính đủ mọi bước (quan sát 3 ở mục 3.6) | Kiểm thử giới hạn thời gian bao mọi profile; golden không đổi |
| P1b-4 | API và báo cáo | Trường và bộ lọc nhóm ở đơn vị; phân loại ở cảnh báo; báo cáo trước–sau theo nhóm; SARIF mang nhóm; `ScanCreate.profile` | `frontend/openapi.json` và kiểu sinh ra đi cùng commit; phản hồi của lượt quét cũ không đổi dạng |
| P1b-5 | Giao diện | Chọn profile ghép; cột và bộ lọc nhóm; khối chi tiết theo nhóm (`shell_state` chỉ cho nhóm lệnh) | `npm run check` qua; kiểm thử E2E với API giả cho lượt quét hai nhóm |
| P1b-6 | Hiệu năng | Chỉ dựa trên số đo của P1a-6: song song các lượt phân tích, giới hạn tài nguyên | Có số đo trước và sau; kết quả từng nhóm không đổi |
| P1b-7 | Hợp nhất đường cũ (tùy chọn) | Cho profile đơn đi qua lớp ghép như lượt ghép một thành viên; bỏ rẽ nhánh ở `task.py`. Chạm `analysis.py` (bị ghim) | Theo trình tự ở mục 8.2; golden không đổi; chỉ làm khi chủ đề án quyết định |
| P1b-8 | Tài liệu sống | `architecture.md`, `backend/AGENTS.md`, `README.md`, `research.md`, `validation.md` | Mô tả đúng trạng thái sau thay đổi |

## 11. Kiểm thử bảo đảm không phá hành vi cũ

### 11.1 Lưới an toàn cho bốn profile

| Lớp | Kiểm thử | Phát hiện |
|---|---|---|
| Golden theo profile | `test_legacy_golden.py` (P1a-1) | Mọi thay đổi ở `unit_id`, khóa ứng viên, mức, `decision_id`, lý do, `disposition`, bản ghi gạn, phiên bản, hàng cảnh báo |
| Kiểm thử hiện có của lõi | `backend/tests/triage/*`, `backend/tests/scanners/*`, `backend/tests/workflows/scans/test_task.py` | Hồi quy ở từng thành phần; không sửa kiểm thử nào để "cho qua" |
| Sổ đăng ký nghiên cứu | `experiments/tests/test_evaluation.py`, `test_research_freeze.py`, `test_product_pack.py`, `test_profile.py` | File bị ghim đổi byte hoặc đổi chỗ |
| CLI nghiên cứu | `experiments/tests/test_runner.py` | Chữ ký và đầu ra của lõi dùng chung |
| Tương đương CLI–API | Job CI `scan-parity` | Lệch giữa hai đường trên công cụ thật |
| Kiến trúc | `backend/tests/test_architecture.py` | Mã mới phá quy tắc phân tầng (`triage` và `scanners` chỉ dùng thư viện chuẩn) |

Quy tắc: nếu một thay đổi làm golden khác đi, thay đổi đó hoặc là lỗi, hoặc phải được giải thích
trong commit và golden được cập nhật **trong cùng commit** với lý do; không cập nhật golden hàng loạt.

### 11.2 Kiểm thử tích hợp của lượt quét ghép

Hai mức. Mức A chạy trong CI với đầu ra công cụ giả; mức B là lượt quét thật của P1a-6.

**Mức A — fixture tổng hợp có hai nhóm** (ghi rõ là dữ liệu kiểm thử tổng hợp):

| # | Tình huống | Khẳng định |
|---|---|---|
| A1 | Nguồn có sink lệnh và sink đường dẫn ở các lời gọi khác nhau | Mỗi nhóm bằng lượt riêng của nó (trừ danh sách ở mục 5.1) |
| A2 | Cảnh báo CWE-22 nằm **bên trong** vùng của một lời gọi lệnh (`os.system("cat " + open(p).read())`) | Cảnh báo CWE-22 ở đơn vị của nhóm đường dẫn; đơn vị của `os.system` chỉ chứa cảnh báo nhóm lệnh |
| A3 | Hai cảnh báo khác nhóm ở đúng cùng một vùng mã | Hai đơn vị, hai ứng viên, hai chính sách |
| A4 | Bảo toàn | B1–B7; tổng cảnh báo theo nhóm cộng "chưa xác định" bằng tổng cảnh báo |
| A5 | Chính sách riêng | Nhóm lệnh mang `decision_id` và hash của `priority-v0.2`; nhóm đường dẫn mang `EV_KEPT_NO_PROOF` / `EV_HIDDEN_BY_EVIDENCE` |
| A6 | Gạn không lan nhóm | Bằng chứng của nhóm đường dẫn không làm đổi `disposition` của ứng viên nhóm lệnh và ngược lại |
| A7 | Lượt pack CWE-22 thất bại | Nhóm đường dẫn không xếp hạng gì; nhóm lệnh giống hệt lượt riêng; trạng thái chung `partial` |
| A8 | `codeql-create` thất bại | Nhóm lệnh chỉ còn cảnh báo sàng lọc, không gạn; nhóm đường dẫn không có đơn vị; cảnh báo thô còn đủ |
| A9 | Bước bằng chứng nhóm lệnh thất bại | `evidence_step_failed` ở nhóm lệnh; nhóm đường dẫn không đổi |
| A10 | Lượt pack CWE-22 trả về rule lạ | Nhóm đường dẫn thất bại kèm lỗi; nhóm lệnh tiếp tục; cảnh báo thô còn trong `findings.json` |
| A11 | Lượt chạy phục vụ hai thành viên, rule không ai khai / hai bên cùng khai / sai hash | Đơn vị "chưa xác định nhóm", mức `U`, `review`, đủ `reported_cwes` và `mapped_cwes`, không gộp với nhóm nào |
| A12 | Các thành viên khác phiên bản CodeQL | Lượt ghép từ chối chạy, nêu rõ lý do |

**Mức B — một snapshot phát triển, công cụ thật:** ba lượt và `comparison.json` như P1a-6.

## 12. Chưa nên triển khai

Mỗi mục kèm điều kiện mở lại, để không bị làm "tiện tay".

| Việc | Vì sao chưa | Điều kiện mở lại |
|---|---|---|
| Thêm CWE-89, CWE-79, CWE-918; CWE-22 cho JS/TS | Ngoài phạm vi; chưa có lõi đã chứng minh | P1a và P1b đạt; mỗi nhóm một giao thức riêng |
| Giao diện bộ xử lý nhiều hàm (định vị sink, vai trò, điểm cuối, vị từ) và tách mã CWE-78 khỏi `reconcile.py`, `evidence.py`, `adjudicate.py` | Chưa có nhóm thứ hai cần bộ gộp; sửa file bị ghim | Nhóm đầu tiên cần gộp cảnh báo của nhiều công cụ theo sink |
| Bỏ `_CODEQL_RULES` và `cwe78_candidate` viết cứng | Chỉ sai khi nhóm khác đi qua `assess.py`/`claims.py` | Như trên |
| Nhóm trong khóa đơn vị (`reconcile-v0.2`) | Định tuyến đã đủ; đổi khóa làm lệch `unit_id` | Khi một bộ gộp phải nhận cảnh báo của nhiều nhóm |
| Vị từ chính sách mở rộng | Mỗi nhóm đang có chính sách riêng | Khi nhóm mới cần vị từ ngoài mười vị từ hiện có |
| Điều kiện gạn cho nhóm mới; G1/G3 dùng chung | Chưa có gói bằng chứng và số đo cho nhóm đó | Gói bằng chứng ghim hash, phản ví dụ, giao thức ghi trước khi quét |
| Rule-claims có trường `analysis_family`; Semgrep chạy luật của nhiều nhóm trong một lượt | P1a không có lượt chạy phục vụ nhiều thành viên | Khi một công cụ phải chạy luật của hai nhóm |
| Gộp truy vấn của nhiều pack vào một lệnh `analyze` | Hai pack trùng tên; chưa có số đo cho thấy cần | Số đo P1a-6 cho thấy chi phí analyze là nút thắt |
| Phân xử nhóm mơ hồ bằng vị trí sink | Thêm suy luận ở chỗ đang cần sự chắc chắn | Có ca thật lặp lại ở trạng thái `ambiguous_family` |
| Chuẩn hóa `reported_cwes` tại chỗ | Trường này là nhãn nguyên bản | Không mở; nếu cần, thêm trường hiển thị riêng |
| Nới CHECK `argument_role`; sửa `LOCATOR_VERSION`; sửa `SCANNER_STEPS` | Không cần cho P1a | P1b-2, P1b-3 hoặc nhóm có vai trò mới |
| Profile schema 2, cột DB, API, giao diện, song song hóa | Thuộc P1b | Cổng P1a → P1b |
| Sửa `experiments/run_pilot.py`, hiện vật, nhãn, giao thức, sổ đăng ký | Đã khóa hoặc là hồ sơ lịch sử | Không mở trong chương trình này |
| Quét dữ liệu mới hoặc held-out | Không có giao thức | Giao thức được commit trước khi quét |

## 13. Rủi ro

1. **Trôi hành vi của profile cũ và của các đánh giá đã đăng ký.** Giảm bằng: P1a chỉ thêm mã; golden
   trước khi sửa; không chạm file bị ghim; `scan-parity`. Rủi ro tăng lại ở P1b-7, vì vậy đầu việc đó
   là tùy chọn và cần quyết định riêng.
2. **Định tuyến sai nhóm hoặc gộp nhầm.** Hôm nay không có lớp nào ngăn một cảnh báo của CWE khác rơi
   vào bộ gộp lệnh. Giảm bằng: định tuyến theo lượt chạy và rule đã ghim, trạng thái chưa xác định,
   kiểm thử A2, A3, A11. Rủi ro còn lại xuất hiện khi một lượt chạy phục vụ nhiều nhóm (chưa có ở P1a).
3. **Kiến trúc mở rộng được nhưng nhóm mới không có giá trị thẩm định.** Trên mã thật pack CWE-22
   mới loại được khoảng 9% cảnh báo sai; JS/TS chưa có gói bằng chứng CodeQL; 89, 79, 918 chưa có bộ
   định vị, chính sách hay bằng chứng nào; tập held-out của CWE-78 đã dùng hết. Mặc định "chỉ phát
   hiện và giữ" là cách nói thật về điều này, nhưng cũng nghĩa là mỗi nhóm mới là một khối lượng
   nghiên cứu riêng.

Rủi ro nhỏ hơn: chi phí thời gian (nhiều lượt analyze; ngân sách Celery hiện đã thiếu hai bước); khác
biệt số luồng khi tạo database giữa lượt ghép và lượt riêng (xem mục 14).

## 14. Điểm chưa xác minh

Máy phát triển này chỉ có Docker; Semgrep, CodeQL và Bandit nằm trong image worker và chưa được chạy
cho tài liệu này.

- Lượt pack `path-traversal-v0.2` trên database do thành viên lệnh tạo (`jobs: 1`) có cho đúng kết quả
  như database do profile CWE-22 tự tạo (`jobs: 2`) hay không. P1a-6 kiểm điều này; nếu khác, đó là
  một phát hiện phải ghi lại, không phải thứ để điều chỉnh cho khớp.
- Hai pack trùng tên có gây xung đột bộ nhớ đệm khi chạy lần lượt trên cùng database hay không.
  `run_codeql_evidence` đã dùng `--rerun` vì lý do này; chưa đo với ba lượt.
- Đường dẫn và hash của các truy vấn upstream cho CWE-22, 89, 79, 918 trong `python-queries` 1.8.11 và
  `javascript-queries` 2.4.6. Không cần cho P1.
- Archive giả trong `backend/tests/workflows/scans/fakes.py` có tất định hay không (header gzip có thể
  mang thời gian). P1a-1 xác định và xử lý trong mã kiểm thử.
- Chưa chạy bộ kiểm thử nào cho tài liệu này vì không sửa mã.

## 15. Đầu việc đầu tiên sẵn sàng triển khai

**P1a-1 — kiểm thử hồi quy golden cho bốn profile hiện tại.** Chỉ thêm file dưới `backend/tests/`,
không phụ thuộc quyết định nào còn mở, không chạm file bị ghim, và là điều kiện để mọi đầu việc sau
có thể khẳng định "không đổi hành vi cũ". Bước nhỏ nhất bên trong nó: một kịch bản golden cho
`path-traversal-v0.2` (một vị trí giữ, một vị trí hạ) dựa trên `fake_evidence_pipeline` đã có.

> Mục 14 và 15 là trạng thái lúc viết thiết kế. Sau khi P1a được triển khai, xem mục 16: câu hỏi
> đầu tiên của mục 14 đã có câu trả lời trên một snapshot, và đầu việc tiếp theo nằm ở mục 16.7.

## 16. Trạng thái P1a (2026-11-15)

P1a-1 đến P1a-6 được làm trên HEAD `837c53d` và commit vào nhánh `feat/multi-cwe-core` (mục 16.6).
**Chưa push.** Không file nào dưới `experiments/`, `profiles/`, `rules/`, `tools/` hay
`frontend/` thay đổi; không sổ đăng ký nào bị sửa.

### 16.1 Mã đã thêm

| File | Nội dung |
|---|---|
| `backend/app/workflows/scans/classification.py` (mới) | Bản ghi phân loại ba trường cho từng cảnh báo; quy tắc định tuyến; ba lý do "chưa xác định" |
| `backend/app/workflows/scans/families.py` (mới) | `compose`, `scan_language_families`, `check_conservation`; cảnh báo chưa xác định nhóm thành đơn vị riêng ở mức `U` |
| `backend/scripts/scan_families.py` (mới) | CLI phát triển: `run --mode composite` hoặc `separate`, và `compare` |
| `backend/app/scanners/codeql.py` | `run_codeql_evidence(name=...)`, mặc định như cũ. Thay đổi duy nhất ở file ứng dụng đã có |
| `backend/tests/workflows/scans/test_legacy_golden.py`, `backend/tests/golden/legacy/*.json` | 15 kịch bản golden cho bốn profile |
| `backend/tests/workflows/scans/test_classification.py`, `test_families.py`, `backend/tests/test_scan_families_script.py`, bổ sung ở `backend/tests/scanners/test_codeql.py` | Kiểm thử của phần mới |

Đúng như mục 4 dự kiến, `reconcile.py`, `evidence.py`, `policy.py`, `adjudicate.py`,
`safety_evidence.py`, `analysis.py`, `task.py`, các loader profile, bảng dữ liệu và API không đổi.

### 16.2 Khác với kế hoạch

1. Bộ xử lý nhóm không gọi `_assess_pipeline`; lớp ghép cấp kết quả công cụ cho chính
   `scan_language` và `scan_language_evidence` (ghi chú ở P1a-4).
2. Bộ so sánh phải gác lại thêm hai chi tiết chỉ ghi nơi công cụ chạy (hai dòng cuối bảng ở mục
   5.1). Lần so sánh đầu tiên của lượt quét thật trả `equivalent: false` vì lý do này; kết quả đó
   được giữ nguyên ở `run-01/comparison.json`. Chỉ bộ so sánh được sửa, mã quét không đổi, và phép
   so sánh lại chạy trên đúng các đầu ra đã lưu (`run-01/comparison-after-fix.json`).
3. Golden có 15 kịch bản thay vì danh sách ở P1a-1: thêm kịch bản "một lời gọi, ba đơn vị, một ứng
   viên" sau khi phép thử đột biến cho thấy bộ golden ban đầu không phát hiện việc đổi thứ tự mức.

### 16.3 Kiểm thử hồi quy và baseline

Chạy trên Windows, Python 3.12 qua `uv`, SQLite trong bộ nhớ; riêng bộ kiểm thử backend được chạy
thêm trong Docker trên PostgreSQL (`docker compose --profile test run --build --rm test`): 542 qua,
độ phủ 95,41%. Chưa chạy hook, chưa chạy CI.

| Kiểm tra | Baseline (HEAD, trước khi sửa) | Sau P1a |
|---|---|---|
| `uv run pytest --cov` (backend) | 484 qua, 2 bỏ qua | 540 qua, 2 bỏ qua; độ phủ 95,28% |
| `uv run ruff check .`, `ruff format`, `uv run mypy` | — | Sạch (137 file) |
| Bản xuất nguyên trạng của HEAD (`git archive HEAD`, ngoài working tree) | 484 qua, 2 bỏ qua | Cả 486 kiểm thử baseline còn nguyên và cùng kết quả sau P1a; 56 kiểm thử mới đều qua |
| Golden, 15 kịch bản | Sinh từ mã chưa sửa; chạy trên bản xuất nguyên trạng của HEAD (chỉ thêm file kiểm thử golden và file golden): 16/16 kiểm thử qua | 16/16 qua, không file golden nào đổi |
| Phép thử đột biến trên golden (không sửa file nào) | — | Đổi mã quyết định: 1 kiểm thử đỏ; đảo thứ tự mức: 1 đỏ; đổi phiên bản gạn: 12 đỏ |
| Kiểm thử thực nghiệm (`unittest discover`) | — | 153 qua, không sửa sổ đăng ký hay file bị ghim |

Ma trận mức A của mục 11.2 nằm trong `test_families.py`: tương đương với quét riêng (A1), cảnh báo
CWE-22 nằm trong lời gọi lệnh (A2), hai nhóm trên cùng vùng mã (A3), bảo toàn (A4), chính sách riêng
(A5), bằng chứng không lan nhóm (A6), lượt pack CWE-22 hỏng hoặc chạy dở (A7), database hỏng (A8),
bước bằng chứng nhóm lệnh hỏng (A9), rule lạ (A10), cảnh báo chưa xác định nhóm (A11), thành viên
không ghép được (A12), và ngôn ngữ chỉ một thành viên có cấu hình.

### 16.4 Lượt quét thật trên dữ liệu phát triển

- **Snapshot:** OWASP BenchmarkPython, commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`, archive
  SHA-256 `0defda4cce2ea7675fbeae5b059b4d7cca7d49232529367133feb1adfb529096` (khớp manifest
  `experiments/cases/owasp-benchmarkpython-cwe78-v01.json`, `split: development`). Chỉ quét Python.
- **Thành viên:** `command-injection-v0.3` (manifest `1b3b824a…`) và `path-traversal-v0.2`
  (`65f9c800…`).
- **Môi trường:** image `security-triage-worker:latest` đã dựng sẵn, với `backend/` của working tree
  gắn chỉ-đọc vào `/app`; `scripts.check_worker` báo đúng hash bốn profile và Semgrep 1.178.0, CodeQL
  2.27.1, Bandit 1.9.4, ESLint 10.15.0; `SCANNER_WORKERS` mặc định (2).
- **Ba lượt, mỗi lượt một container mới:** `run-01` quét riêng trước rồi quét ghép; `run-02` đảo
  thứ tự; `run-03` lặp lại thứ tự của `run-01` với công cụ đã đóng băng và tiêu chí ghi trước. Đầu ra
  ở `artifacts/multi-cwe-p1a/` (không theo dõi bởi Git).

| | Nhóm lệnh | Nhóm đường dẫn |
|---|---|---|
| Cảnh báo | 51 (Semgrep 18, Bandit 20, CodeQL 13) | 188 (125 của truy vấn đối chứng, 63 của truy vấn bằng chứng) |
| Đơn vị / ứng viên | 24 / 20 | 125 / 125 |
| Mức | P1 9, P2 4, P3 11 | P1 63, P4 62 |
| Đã gạn | 2 đơn vị (một theo G1; một theo G3 và G1) | 62 (truy vấn bằng chứng không còn báo) |
| Giữ, kèm lý do | 15 `evidence_query_still_reports_flow`, 7 `no_refuting_evidence` | 63 `evidence_query_still_reports_flow` |
| Chính sách | `command-injection-priority` 0.2, hash `58718192…` | `cwe22-safety-evidence` 0.2, hash `8c7a6f77…` |
| Ghép so với riêng, cả hai lượt | Đơn vị và đánh giá bằng nhau | Đơn vị và đánh giá bằng nhau |

Kết quả theo tiêu chí nghiệm thu của P1a-6:

1. **Tương đương:** cả hai lượt, mỗi nhóm của lượt ghép bằng lượt quét riêng của nó. Khác biệt khi so
   từng byte: 18 cảnh báo Semgrep khác tiền tố mã rule; 17 (lượt 1) và 8 (lượt 2) cảnh báo CodeQL
   khác chỉ số artifact; thứ tự kết quả của CodeQL giữa hai lần chạy cũng khác, nên cảnh báo được
   khớp theo nội dung chứ không theo số thứ tự.
   Vì bộ so sánh của dự án đã bị sửa sau khi thấy kết quả đầu, phép tương đương còn được kiểm bằng
   một kịch bản độc lập không dùng mã so sánh đó, liệt kê từng giá trị khác nhau trong đầu ra đã lưu
   của cả hai lượt: `units.json` của nhóm lệnh giống nhau từng byte; `assessments.json` của nhóm lệnh
   khác đúng 18 giá trị, tất cả là mã rule Semgrep cùng tên khác tiền tố thư mục; đơn vị và đánh giá
   của nhóm đường dẫn chỉ khác ở `raw_id` (tiền tố lượt và số thứ tự); `raw_result` chỉ khác ở chỉ
   số artifact của SARIF. Không có khác biệt nào ngoài ba loại này; mức, mã quyết định, `disposition`,
   quy tắc gạn, lý do giữ, hash chính sách và câu lý do giống nhau ở mọi đơn vị.
   **Lượt thứ ba với tiêu chí ghi trước** (`run-03`): hash của bộ so sánh, của mã lượt ghép và tiêu
   chí đạt được ghi vào `artifacts/multi-cwe-p1a/run-03-CRITERIA.json` trước khi container khởi động;
   hash đo trong container khớp bản ghi; bộ so sánh được gọi đúng một lần. Kết luận đầu tiên của nó:
   `equivalent: true`, cả hai nhóm `equal: true`, cùng số liệu như hai lượt trước (51 và 188 cảnh báo,
   24 và 125 đơn vị, 2 và 62 đã gạn), mọi điều kiện bảo toàn đạt, 0 đơn vị bị gạn thiếu bằng chứng.
   Kịch bản độc lập cũng không thấy khác biệt nào ngoài ba loại đã nêu. Thời gian: lượt ghép 184,9 s
   (chạy sau), hai lượt riêng 383,0 s (chạy trước).
2. **Bảo toàn và không gộp nhầm:** 239/239 cảnh báo được phân loại, mỗi cảnh báo nằm trong đúng một
   đơn vị; 0 đơn vị chứa cảnh báo của hai nhóm; 0 kết quả bằng chứng thuần túy thành cảnh báo; nhãn
   `reported_cwes` giữ nguyên dạng công cụ viết (`cwe-078`, `cwe-088`; `CWE-22` cùng `cwe-22`).
3. **Không gạn khi thiếu bằng chứng:** 0 đơn vị đã gạn thiếu tên quy tắc hoặc thiếu bản ghi bằng
   chứng; mọi đơn vị không có bằng chứng bác bỏ đều ở danh sách rà.
4. **Database dùng chung:** lượt pack CWE-22 trên database do thành viên lệnh tạo (`jobs: 1`) cho
   đúng 188 cảnh báo và 125 đơn vị như database riêng (`jobs: 2`) — trên snapshot này.
5. **Chi phí** (mỗi số là một lần đo, cùng một máy):

   | | Lượt ghép | Hai lượt riêng cộng lại | Tạo database |
   |---|---:|---:|---|
   | Chạy trước trong container (bộ đệm nguội) | 265,1 s | 385,5 s | 1 lần 104,5 s so với 2 lần 213,5 s |
   | Chạy sau trong container (bộ đệm ấm) | 184,7 s | 312,1 s | 1 lần 103,1 s so với 2 lần 220,0 s |

   Phần tiết kiệm (khoảng 120–127 giây) gần bằng một lần tạo database. Thứ tự chạy ảnh hưởng mạnh
   tới các bước analyze (ví dụ lượt pack CWE-22: 37,8 s khi chạy trước, 13,4 s khi chạy sau), nên
   không được so lượt ghép của một container với lượt riêng của cùng container đó.

### 16.5 Điều lượt quét thật **không** chứng minh

- **Tình huống gộp nhầm không xuất hiện trong dữ liệu này:** BenchmarkPython không có file nào có
  cảnh báo của cả hai nhóm (0 file chung, 0 cảnh báo CWE-22 nằm trong một lời gọi lệnh). Việc chống
  gộp nhầm vì vậy chỉ được kiểm bằng fixture tổng hợp (A2, A3), nơi cũng có một kiểm thử cho thấy bộ
  gộp lệnh sẽ nuốt cảnh báo CWE-22 nếu nhận nó.
- **Không có cảnh báo chưa xác định nhóm, không có lỗi công cụ** trong lượt thật; các nhánh đó chỉ
  có kiểm thử (A7–A11).
- Đây là dữ liệu phát triển tổng hợp, một snapshot, chỉ Python. Không có nhãn nào được dùng; các số
  trên không phải số liệu đánh giá hiệu quả gạn.
- JavaScript/TypeScript của lượt ghép chỉ có kiểm thử với công cụ giả (thành viên đường dẫn không
  có cấu hình JS).

### 16.6 Quyết định của chủ đề án (2026-11-15)

Sáu đầu việc P1a-1 đến P1a-6 đã xong và đạt tiêu chí nghiệm thu của chúng. Sau khi xem kết quả,
chủ đề án quyết định:

- **Cổng P1a → P1b: xác nhận P1a đạt.** P1b vẫn chưa bắt đầu và chỉ bắt đầu khi được yêu cầu riêng.
- **Commit trên nhánh mới `feat/multi-cwe-core`**, tách từ `837c53d`, mỗi đầu việc một commit và
  một commit tài liệu; **không push**. `feat/cwe22-triage` giữ nguyên là nhánh hồ sơ đề án.

Hook pre-push và CI chưa chạy vì chưa push.

### 16.7 Đầu việc tiếp theo

**P1b-1 — profile ghép (schema 2):** một manifest ghim manifest của các thành viên theo hash, để
lượt quét ghép có định danh và hash riêng như bốn profile hiện tại. P1b đã được làm sau đó; xem
mục 17.

## 17. Trạng thái P1b (2026-11-15)

P1b tích hợp lõi của P1a vào ứng dụng web. Làm trên `e8bf32a` và, theo quyết định của chủ đề án,
commit vào `feat/multi-cwe-core` tách theo đầu việc; **chưa push**. **Chủ đề án chấp nhận P1b
ngày 2026-11-15, kèm các giới hạn ở mục 17.5.** Lần rà trước đó trong ngày chủ đề án đánh giá chưa
đạt vì chưa có dự án thật nào có hai nhóm trong cùng một file; quyết định chấp nhận được đưa ra
sau lượt quét bổ sung theo yêu cầu đó (mục 17.4, điểm 10). Không file nào dưới `experiments/`,
`rules/`, `tools/` hay bốn thư mục profile cũ thay đổi; logic G1–G4 và điều kiện an toàn của pack
v0.2 không đổi.

### 17.1 Đã làm theo từng đầu việc

| # | Kết quả | File chính |
|---|---|---|
| P1b-1 | Profile ghép `multi-cwe-v0.1` (`"kind": "composite"`, schema 2) ghim manifest của `command-injection-v0.3` và `path-traversal-v0.2` cùng đặc tả; loader kiểm hash rồi nạp từng thành viên bằng loader của chính nó; worker từ chối khởi động nếu profile ghép khai nhóm mà mã không xử lý | `profiles/multi-cwe-v0.1/`, `backend/app/scanners/profile.py`, `backend/scripts/check_worker.py`, `backend/app/core/config.py` |
| P1b-2 | Migration `0008`: cột `location_units.analysis_family` (cho phép rỗng). Phân loại của cảnh báo lưu ở `findings.evidence.classification`, cạnh nhãn gốc. Đọc kết quả của lượt quét ghép theo `scan_id`, vì mỗi nhóm mang phiên bản riêng | `backend/migrations/versions/0008_unit_analysis_family.py`, `features/triage/models.py`, `workflows/scans/persist.py`, `results.py` |
| P1b-3 | `scan_snapshot` chạy profile ghép; lượt `codeql-path-traversal` thành `tool_run` riêng; giới hạn thời gian tính đủ mọi bước kể cả bước bằng chứng (`worst_case_seconds`), sửa luôn quan sát 3 của mục 3.6 | `workflows/scans/task.py`, `families.py` |
| P1b-4 | API: `families` ở lượt quét; `analysis_family`, `cwe`, `evidence_state`, `kept_because` ở đơn vị; bộ lọc `family`; `mapped_cwes` và nhóm ở từng cảnh báo; báo cáo theo nhóm; SARIF mang nhóm và hai loại nhãn CWE | `workflows/scans/schemas.py`, `service.py`, `report.py`, `router.py`, `frontend/openapi.json` |
| P1b-5 | Giao diện: chọn profile đa CWE; bảng nhóm CWE với trạng thái lượt chạy và bước bằng chứng; lọc theo nhóm qua URL; cột trạng thái bằng chứng; chi tiết đơn vị và báo cáo theo nhóm | `frontend/src/features/scans/`, `frontend/src/app/routes/scans/` |
| P1b-6 | Không tối ưu gì: số đo cho thấy chưa có nút thắt cần xử lý (mục 17.4) | — |
| P1b-7 | **Không làm** (tùy chọn): profile đơn vẫn đi đường cũ, `analysis.py` không đổi | — |
| P1b-8 | `architecture.md`, `README.md` (hướng dẫn sử dụng), hai `AGENTS.md`, `validation.md`, tài liệu này | — |

**Khác với thiết kế ban đầu của P1b:** lớp ghép giờ bảo đảm *mọi* cảnh báo nằm trong đúng một đơn
vị. Ở P1a, cảnh báo của một nhóm chạy dở hoặc thất bại chỉ nằm trong `findings.json` ("unranked").
Trong ứng dụng, như thế chúng sẽ không hiện ở danh sách rà và không vào SARIF. Vì vậy lớp ghép tạo
đơn vị `F10_FAMILY_NOT_RANKED` cho chúng (mức U, luôn ở danh sách rà, không bao giờ gạn). Kết quả
của chính thành viên không đổi, nên nguyên tắc tương đương ở mục 5.1 vẫn giữ. Profile đơn giữ hành
vi cũ: lượt `path-traversal-v0.2` chạy dở vẫn không tạo đơn vị nào.

### 17.2 Ba trạng thái tách biệt

| Thông tin | Trường | Giá trị |
|---|---|---|
| Lượt quét và lượt chạy của từng nhóm | `status` của lượt quét; `families[].runs[].status`; `evidence_steps` | `completed`, `partial`, `failed` |
| Bằng chứng của từng đơn vị | `evidence_state` | `refuted`, `not_refuted`, `insufficient`, `unavailable`, `not_applicable`, `not_assessed` |
| Quyết định gạn | `disposition`, `filter_rule`, `kept_because` | `review`, `filtered` |

Chỉ `refuted` dẫn tới `filtered`. Lượt quét chạy dở, bước bằng chứng lỗi và nhóm chưa xếp hạng cho
`unavailable`; bằng chứng không bác bỏ hoặc mâu thuẫn cho `not_refuted`; cả hai đều giữ cảnh báo.
Không có bằng chứng nào về cảnh báo cho `insufficient`: kể cả khi rule báo luồng chưa có truy vấn
bằng chứng (`flow_rule_without_evidence_query`) hoặc truy vấn đối chứng không báo cảnh báo đó
(`evidence_baseline_does_not_report_this_alert`) — hai lý do này trước lần rà ở mục 18 bị xếp nhầm
vào `not_refuted`, tức "đã đối chiếu", dù không có gì để đối chiếu.

### 17.3 Kiểm thử

| Kiểm tra | Baseline (`e8bf32a`) | Sau P1b |
|---|---|---|
| Backend cục bộ, `uv run pytest --cov` | 540 đạt, 2 bỏ qua | 584 đạt, 2 bỏ qua; độ phủ 95,54% |
| Backend trong Docker trên PostgreSQL | 542 đạt | 586 đạt; độ phủ 95,67% |
| `ruff check`, `ruff format --check`, `mypy` | Sạch | Sạch (141 file) |
| Golden 15 kịch bản của bốn profile | 16/16 | 16/16, không file golden nào đổi |
| Kiểm thử thực nghiệm | 153 đạt | 153 đạt, không sửa sổ đăng ký nào |
| Frontend `npm run check` | 67 đạt | 76 đạt |
| Playwright với HTTP giả | 2 đạt | 2 đạt (kiểm thử stack thật bị bỏ qua khi không có `FULL_STACK_URL`) |

Kiểm thử mới: `backend/tests/scanners/test_composite_profile.py` (loader, manifest sai),
`tests/workflows/scans/test_composite_members.py` (nhóm lạ, kiểm tra khi worker khởi động),
`tests/workflows/scans/test_composite_scan.py` (worker → cơ sở dữ liệu → API → báo cáo → SARIF; lượt
pack chạy dở; rule lạ; database hỏng; cảnh báo chưa xác định nhóm; profile đơn; hàng lịch sử trước
khi có bước gạn; bảng trạng thái bằng chứng), `tests/test_migration_0008.py`,
`frontend/tests/integration/scans/families.test.tsx`, `frontend/tests/e2e/multi-cwe-full-stack.spec.ts`.

**Lỗi do kiểm thử trên dữ liệu thật tìm ra:** truy vấn đếm theo nhóm chạy được trên SQLite nhưng bị
PostgreSQL từ chối (`GROUP BY` theo biểu thức có tham số). Bộ kiểm thử cục bộ không thấy; phép so
lịch sử ở mục 17.4 thấy ngay ở lượt quét đầu tiên. Đã sửa, và bộ kiểm thử trong Docker trên
PostgreSQL bao phủ đúng truy vấn này.

### 17.4 Kiểm chứng trên stack thật

Stack dựng bằng `docker compose up --build`, cơ sở dữ liệu cục bộ đang chứa dữ liệu lịch sử ở
revision `0007`. Đầu ra ở `artifacts/multi-cwe-p1b/` (không theo dõi bởi Git), gồm bản sao lưu
`pg_dump` chụp trước khi nâng cấp.

1. **Migration trên dữ liệu thật.** `0007 → 0008` chạy trên 366 lượt quét, 5.791 cảnh báo, 3.557
   đơn vị. Số hàng và mã băm nội dung của `location_units`, `unit_assessments`, `findings` trước và
   sau giống nhau; cột mới rỗng ở cả 3.557 hàng; `alembic check` không thấy lệch. Vòng
   `base → head → 0007 → head → base → head` chạy trên một cơ sở dữ liệu tạm.
2. **Dữ liệu lịch sử qua API mới.** Mọi lượt quét được đọc qua API của image cũ rồi của image mới
   (`/scans/{id}`, toàn bộ `/units`, ba chi tiết đơn vị đầu, `/report`, `/report.sarif`): 366 lượt
   quét, 3.557 đơn vị, 599 chi tiết, 5.791 kết quả SARIF. **Không giá trị nào API cũ trả về bị đổi
   hay mất**; API mới chỉ thêm trường. Nhóm suy ra đúng theo profile: 3.525 đơn vị CWE-78, 32 đơn vị
   CWE-22.
3. **Luồng đầu-cuối từ giao diện** (`multi-cwe-full-stack.spec.ts`, Chromium, 3,5 phút): tạo lượt
   quét `multi-cwe-v0.1` cho OWASP BenchmarkPython `f129148` bằng biểu mẫu, chờ worker quét bằng
   công cụ thật, lọc theo CWE qua URL, mở chi tiết đơn vị, tải báo cáo JSON và SARIF.

   | | Nhóm lệnh (CWE-78) | Nhóm đường dẫn (CWE-22) |
   |---|---|---|
   | Cảnh báo | 51 | 188 |
   | Đơn vị | 24 | 125 |
   | Danh sách rà chính / đã gạn | 22 / 2 | 63 / 62 |
   | Trạng thái bằng chứng của đơn vị | 2 bị bác bỏ, 15 không bác bỏ, 7 chưa đủ | 62 bị bác bỏ, 63 không bác bỏ |
   | Khóa đơn vị, mức, quyết định so với lượt ghép của P1a | Giống nhau | Giống nhau |

   239 kết quả công cụ, mỗi kết quả liên kết với đúng một đơn vị; SARIF tải về có 239 kết quả, 51 và
   188 theo nhóm; chỉ kết quả của đơn vị đã gạn có `suppressions`. JavaScript của kho này không có
   cảnh báo nào.

   **Cách đọc hai con số này** (rà lại ở mục 18.4): 188 của nhóm đường dẫn gồm 125 cảnh báo phát
   hiện (`st/cwe-22/none`) và 63 kết quả của truy vấn bằng chứng (`st/cwe-22/all`) mà profile
   `path-traversal-v0.2` lưu như cảnh báo gắn vào đơn vị (mục 5.5). Số cảnh báo phát hiện của lượt
   quét là 176 (51 + 125), không phải 239. "Bị bác bỏ" là trạng thái bằng chứng của đơn vị thỏa
   điều kiện gạn của nhóm mình; lượt này không dùng nhãn nào, nên 2 và 62 **không phải số cảnh báo
   sai đã được xác minh**.
4. **Profile ghép trên nguồn chỉ có JavaScript** (`curling@0.2.0`, quét bằng cả hai profile): lượt
   `multi-cwe-v0.1` cho đúng đơn vị, mức, quyết định, lý do và các bước báo cáo của lượt
   `command-injection-v0.3`; chỉ nhóm lệnh tham gia.
5. **Hai nhóm trong cùng một file, công cụ thật.** Vì dữ liệu ở mục 16 không có file nào chứa cả hai
   nhóm, một nguồn phát triển tổng hợp (một file Flask, không bao giờ được thực thi) được lưu thành
   snapshot và quét qua hàng đợi thật bằng ba profile. Ở dòng 29, lời gọi `open(...)` là đối số của
   `os.system(...)`: cảnh báo CWE-22 (cột 64–85) nằm **bên trong** lời gọi CWE-78 (cột 16–94).

   | | Kết quả của `multi-cwe-v0.1` |
   |---|---|
   | Cảnh báo | 12 (Semgrep 2, Bandit 4, CodeQL 2, lượt pack CWE-22 4), mỗi cảnh báo trong đúng một đơn vị |
   | Đơn vị | 3 thuộc CWE-78, 2 thuộc CWE-22; 0 đơn vị chứa cảnh báo của nhóm khác |
   | Dòng 29 | Hai đơn vị: `os.system` (CWE-78, `D20_STRONG`) và vị trí của `open` (CWE-22, `EV_KEPT_NO_PROOF`) |
   | Gạn | 1 đơn vị CWE-78 (lệnh hằng `ls -l`, G2); SARIF có 12 kết quả, 2 kết quả mang `suppressions` |
   | So với quét riêng | Nhóm lệnh bằng lượt `command-injection-v0.3`; nhóm đường dẫn bằng lượt `path-traversal-v0.2` |

6. **Lượt chạy dở, công cụ thật.** Cùng nguồn đó thêm một file Python 2 không phân tích được. Lượt
   `multi-cwe-v0.1` kết thúc `partial`: bộ định vị lời gọi của nhóm lệnh chạy dở, nên cả 3 đơn vị
   CWE-78 ở lại danh sách rà với `run_incomplete` và trạng thái bằng chứng "không lấy được" — kể cả
   đơn vị lệnh hằng mà lượt hoàn tất đã gạn. Nhóm CWE-22 hoàn tất và cho đúng 2 đơn vị như khi quét
   riêng: lỗi của nhóm này không lan sang nhóm kia. 0 đơn vị bị gạn, 12/12 cảnh báo còn trong SARIF.
7. **Lượt quét thất bại tạo từ biểu mẫu** (`curling@99.99.99`, profile đa CWE): trang lượt quét hiện
   "Scan thất bại" kèm lý do của máy chủ và không hiện bảng đơn vị nào.
8. **Ba ca trên được kiểm lại trong giao diện bằng Chromium:** hai hàng ở `app.py:29` thuộc hai nhóm;
   lọc CWE-22 chỉ còn hàng của nhóm đó; trang lượt chạy dở hiện trạng thái từng nhóm, "Đã gạn: 0" và
   lý do giữ trong chi tiết đơn vị.
9. **Lỗi công cụ tiêm ở ranh giới công cụ.** Một worker thứ hai, cùng image, nghe một hàng đợi riêng
   và có một tệp bọc `codeql` đứng trước trên `PATH`; tệp bọc gọi CodeQL thật trừ đúng một lỗi được
   chọn. Mã ứng dụng, profile và CodeQL không đổi. Nguồn là snapshot tổng hợp ở điểm 5.

   | Lỗi tiêm | Lượt quét | Nhóm lệnh | Nhóm đường dẫn | Cảnh báo |
   |---|---|---|---|---|
   | `database create` thất bại | `partial`, nêu lỗi của cả hai lượt CodeQL | Chạy dở: 3 đơn vị từ công cụ sàng lọc, đều `run_incomplete`, 0 gạn | Thất bại, không có cảnh báo nào để giữ | 6/6 trong SARIF |
   | Lượt pack CWE-22 phân tích xong nhưng thoát mã khác 0 | `partial` | Không đổi so với lượt sạch (1 đơn vị gạn theo G2) | Thất bại; 4 cảnh báo thành **2 đơn vị `F10_FAMILY_NOT_RANKED`**, mức U, danh sách rà, bằng chứng "không lấy được" | 12/12 trong SARIF |
   | Truy vấn bằng chứng của nhóm lệnh thất bại | `completed`, bước `codeql-evidence` ghi `failed` | 2 đơn vị có luồng ở lại với `evidence_step_failed`; đơn vị lệnh hằng vẫn gạn theo G2 vì không cần bước này | Không đổi | 12/12 trong SARIF |

   Ở cả ba lượt: mỗi cảnh báo nằm trong đúng một đơn vị và không đơn vị nào lẫn nhóm.
10. **Dự án có thật, tiêu chí ghi trước.** Trước khi quét, tiêu chí và ứng viên duy nhất được ghi vào
    `artifacts/multi-cwe-p1b/real-project-CRITERIA.json`: `adeyosemanputra/pygoat@2aa4cc1` (dữ liệu
    phát triển; từng bị loại trước khi quét ở đợt kiểm tra độc lập đầu tiên, nên chưa bao giờ thuộc
    một lượt quét đã đăng ký). Kết quả: một lượt quét có cả hai nhóm — 4 đơn vị CWE-78, 3 đơn vị
    CWE-22, 14 cảnh báo mỗi cái trong đúng một đơn vị, 0 đơn vị lẫn nhóm, mỗi nhóm bằng lượt quét
    riêng. **Tiêu chí "có file chứa đơn vị của cả hai nhóm" không đạt:** hai nhóm nằm ở các file khác
    nhau. Theo đúng điều đã ghi trước, không thử thêm kho nào.
    Sau khi xem kết quả này, chủ đề án đánh giá P1b chưa đạt và yêu cầu tìm thêm dự án có thật.
    Ứng viên thứ hai được chọn **bằng cách đọc mã nguồn**, không dựa vào đầu ra công cụ quét, và
    tiêu chí cùng quy tắc dừng được ghi trước ở `real-project-2-CRITERIA.json`: `sgabe/DSVPWA@961f86d`,
    file `dsvpwa/handlers.py` (bốn kho khác bị loại khi đọc vì thiếu một trong hai loại sink).
    **Tiêu chí đạt:** trong lượt `multi-cwe-v0.1`, `dsvpwa/handlers.py` có 1 đơn vị CWE-78 (dòng 205,
    `subprocess.check_output`, `D20_STRONG`) và 2 đơn vị CWE-22 (dòng 134 và 137, `EV_KEPT_NO_PROOF`).
    10 cảnh báo, mỗi cái trong đúng một đơn vị; 0 đơn vị lẫn nhóm; nhóm lệnh (3 đơn vị) và nhóm đường
    dẫn (2 đơn vị) đều bằng lượt quét riêng profile của mình. Ở kho này không có đơn vị CWE-22 nào
    nằm bên trong một lời gọi CWE-78.
11. **Hook pre-push và các bước CI chạy được tại chỗ** (không push): script `.husky/pre-push` đạt
    (frontend 76, backend 585 kiểm thử); `openapi.json` khớp API đang chạy; kiểu sinh ra khớp
    `openapi.json`; `npm run build`, hai cấu hình Compose, `check_worker` và `alembic check` đạt.
    `pip-audit` lúc đó **không đạt** vì ba dependency phát triển (`msgpack`, `filelock`, `certifi`)
    trong `uv.lock` không đổi từ 26/09; theo quyết định của chủ đề án chúng đã được nâng ở commit
    `cce07c1`, và `pip-audit` nay báo không còn lỗ hổng nào.
12. **`scan-parity`:** CLI nghiên cứu (chạy trong image worker thay cho image thực nghiệm của CI) và
    API cho cùng kết quả trên `curling@0.2.0` với profile mặc định v0.1: cùng `unit_id`, mức, số cảnh
    báo theo công cụ và theo đơn vị, hash chính sách, và đúng một đơn vị P1.
13. **Chi phí trong worker** (một lần đo): Python tạo database 12,4 s, phân tích nhóm lệnh 41,5 s,
   bằng chứng nhóm lệnh 31,4 s, lượt pack CWE-22 32,4 s; cả lượt quét hai ngôn ngữ khoảng 3,5 phút.
   Các số này nhỏ hơn nhiều so với mục 16.4 vì ở đó thư mục đầu ra nằm trên ổ gắn từ Windows.

### 17.5 Chưa đạt hoặc chưa kiểm chứng

- **Ca lỗi do công cụ trên stack thật là lỗi được tiêm**, không phải lỗi tự phát: database hỏng,
  lượt pack CWE-22 thoát mã lỗi (đơn vị `F10_FAMILY_NOT_RANKED`) và bước bằng chứng lỗi đều đến từ
  tệp bọc `codeql` (điểm 9). Lỗi tự phát đã gặp chỉ có lượt chạy dở của nhóm lệnh và lượt quét không
  thu nhận được nguồn (điểm 6, 7).
- **Cảnh báo chưa xác định nhóm chỉ có kiểm thử tự động.** Với `multi-cwe-v0.1`, mỗi lượt chạy công
  cụ phục vụ đúng một thành viên nên trạng thái này không thể sinh ra trên stack thật; nó chỉ xuất
  hiện khi một profile sau này cho một lượt chạy phục vụ nhiều nhóm.
- **Hai nhóm trong cùng một file trên dự án có thật chỉ có một ca:** `dsvpwa/handlers.py` (điểm 10).
  Ở pygoat và BenchmarkPython hai nhóm nằm ở các file khác nhau. **Ca lồng nhau** — cảnh báo CWE-22
  nằm bên trong một lời gọi CWE-78, chỗ bộ gộp cũ sẽ gộp nhầm — vẫn chỉ có trên nguồn tổng hợp tự
  viết (điểm 5).
- Commit `dc1db13` không qua `tsc` của frontend khi đứng một mình: một dòng của `get-units.ts` nằm
  ở commit kế tiếp. Đầu nhánh thì sạch; chủ đề án quyết định để nguyên.
- CI trên GitHub chưa chạy: nhánh đã được push tới `04c8e8a` nhưng workflow chỉ chạy khi push vào
  `main` hoặc khi có pull request, và chưa có pull request nào (mục 18.1). Hook pre-commit đã chạy
  ở từng commit, script pre-push và cả năm job CI đã chạy tương đương tại chỗ (điểm 11, mục 18.2).
  Trang "Cảnh báo" tổng hợp và API liệt kê lượt quét vẫn chưa có, như trước.
- `multi-cwe-v0.1` chưa có số liệu đánh giá riêng; số liệu ở trên là kiểm chứng kỹ thuật trên dữ
  liệu phát triển, không dùng nhãn.
- P1b-7 (cho profile đơn đi qua lớp ghép) không làm; hai đường vẫn song song ở `task.py`.

### 17.6 Đầu việc tiếp theo

Thuộc quyền chủ đề án: mở draft pull request để CI chạy (mục 18.1; nhánh đã được push);
quyết định cho P1b-7; và nhóm CWE đầu tiên của P2,
với giao thức và gói bằng chứng riêng trước khi nhóm đó được phép gạn (thiết kế ở mục 19).

## 18. Nghiệm thu kỹ thuật P1 (2026-11-15)

Lần rà này kiểm lại P1a và P1b bằng mã, dữ liệu đã lưu và các lượt chạy mới; không làm lại hai giai
đoạn đó. Đầu ra thô nằm ở `artifacts/multi-cwe-p1-audit/` (không vào Git). Không nhãn nào được dùng,
không dữ liệu held-out hay cặp đã đóng băng nào được quét, không file bị ghim nào bị sửa.

### 18.1 Git và CI

- Khi bắt đầu rà: `HEAD` = `59255dc`, `origin/feat/multi-cwe-core` ở `04c8e8a`, bốn commit chưa
  push. Sau khi chủ đề án quyết định (cùng ngày), bốn bản sửa của lần rà được commit
  (`c8959aa`, `834156b`, `4360121`, `bdfdb7e`) và nhánh được push lên `origin`, không ép ghi đè; hook
  pre-push đạt. Việc mở draft pull request do chủ đề án thực hiện.
- **Vì sao không có lượt GitHub Actions nào:** `.github/workflows/ci.yml` chỉ chạy khi `push` vào
  `main` hoặc khi có `pull_request`. Nhánh được push nhưng chưa có pull request nào, nên không sự
  kiện nào khớp. API của GitHub xác nhận: 0 pull request và 0 lượt chạy cho nhánh và cho commit
  `04c8e8a`; lượt CI gần nhất của kho là trên `main` ngày 2026-10-08.
- **Cách chạy CI mà không merge:** mở một draft pull request. Sự kiện `pull_request` không lọc theo
  nhánh đích, nên có hai lựa chọn:
  1. `feat/multi-cwe-core` → `feat/cwe22-triage` (nên chọn): phần khác biệt chỉ gồm công việc đa CWE.
     Cần push `feat/cwe22-triage` trước, vì bản cục bộ hơn `origin` một commit (`837c53d`) mà nhánh
     đa CWE dựng trên đó.
  2. `feat/multi-cwe-core` → `main`: chạy cùng năm job, nhưng pull request chứa cả công việc của
     `feat/cwe22-triage`. `git merge-tree` cho thấy hai nhánh gộp được không xung đột.

  Thêm `workflow_dispatch` không giúp được ngay: nút chạy tay chỉ xuất hiện khi workflow có trigger
  đó trên nhánh mặc định. Máy làm việc không có `gh`, nên trợ lý không mở được pull request.
- **CI xanh vẫn chưa chạy profile ghép bằng công cụ thật:** job `frontend` bỏ qua
  `multi-cwe-full-stack.spec.ts` (không có `FULL_STACK_URL`), `scan-parity` chỉ quét profile mặc định
  v0.1, và `docker-integration` không quét gì. Việc đưa một lượt quét ghép thật vào CI là tiêu chí
  của P2 (mục 19.5).

### 18.2 Kiểm thử đã chạy

| Tầng | Lệnh | Kết quả |
|---|---|---|
| Công cụ giả lập, SQLite | `uv run pytest --cov` (Windows) | 592 đạt, **2 bỏ qua**, độ phủ 95,58%; 2 ca **bỏ qua** là `tests/scanners/test_process.py:65` và `:157` (nhóm tiến trình POSIX), không tính là đạt ở tầng này |
| Công cụ giả lập, PostgreSQL | `docker compose --profile test run --build --rm test` | 594 đạt, độ phủ 95,70%, không ca nào bỏ qua (hai ca POSIX chạy ở đây) |
| Golden bốn profile cũ | nằm trong hai lệnh trên (`test_legacy_golden.py`, 15 kịch bản) | Đạt; 14 file không đổi, file `path-traversal-v0.2-partial-run` được sinh lại có chủ ý (lỗi L1, mục 18.5) |
| Tĩnh | `ruff check`, `ruff format --check`, `mypy`, `pip-audit` trong image kiểm thử | Sạch; không lỗ hổng đã biết |
| Migration, PostgreSQL | `alembic upgrade head` → `check` → `downgrade base` → `upgrade head` → `check` trên database tạm; `test_migration_0008.py` | Đạt; không chạy trên database đang có dữ liệu |
| Hợp đồng API | `scripts.export_openapi` so với `frontend/openapi.json`; kiểu sinh ra so với `api-schema.d.ts` | Giống hệt |
| Thực nghiệm | `python -m unittest discover -s experiments/tests` (Python 3.12, `pyyaml` 6.0.3, `jsonschema` 4.26.0) | 153 đạt. Bằng Python 3.11 của máy thì 4 module không nạp được (cú pháp 3.12): giới hạn môi trường, không phải lỗi mã |
| Giao diện, API giả lập | `npm run lint`, `format:check`, `npm test`, `npm run build`, `npm run test:e2e` | Vitest 78 đạt; Playwright 2 đạt, **1 bỏ qua** (kiểm thử stack thật) |
| Giao diện, **công cụ thật** | `FULL_STACK_URL=… npx playwright test multi-cwe-full-stack` | 1 đạt, chạy lại sau các bản sửa: 239 kết quả công cụ = 176 cảnh báo phát hiện + 63 kết quả truy vấn bằng chứng; 0 cảnh báo chưa xếp hạng; 149 đơn vị, 64 đã gạn — bằng P1a và P1b |
| Bốn profile cũ, **công cụ thật** | `legacy_regression.py`: quét lại nguồn phát triển và so với lượt quét lưu ngày 14/11 | 4/5 ca giống hệt; ca v0.1 xem mục 18.3. Chạy lại sau mọi bản sửa (`bdfdb7e`): cùng kết quả |
| Job `reconciliation-integration` | cùng lệnh và cùng script tiêu chí của CI, image thực nghiệm dựng tại chỗ | Đạt |
| Job `scan-parity` | CLI trong image thực nghiệm so với API | Đạt mọi điều kiện |
| Các bước còn lại của `docker-integration` | hai cấu hình Compose, `check_worker`, proxy, readiness, `celery inspect ping` | Đạt |
| Dữ liệu đã lưu | `db_audit.sql`, `db_filtered.sql` trên 392 lượt quét, 6.492 kết quả, 3.945 đơn vị | Xem mục 18.3 |

Hai dòng đầu, dòng thực nghiệm và dòng bốn profile cũ là của trạng thái cuối (`bdfdb7e`); hai dòng
giao diện là của `4360121` (bản sửa sau đó không đổi frontend hay hợp đồng API); ba dòng job CI chạy
ở `59255dc`. Giới hạn môi trường: mọi lệnh chạy trên một máy
Windows với Docker; không lượt nào chạy trên GitHub Actions. Các ca lỗi công cụ trên stack thật vẫn là lỗi được tiêm (mục 17.4, điểm 9).

**Lượt chạy cuối** (2026-11-15) trên commit `82b82a5`, cây làm việc sạch, stack dựng lại từ đúng
commit đó; một lệnh `bash artifacts/multi-cwe-p1-final/run_all.sh`, đầu ra ở
`artifacts/multi-cwe-p1-final/` (`run.txt` và từng file bên dưới). Các commit sau `82b82a5` chỉ sửa
tài liệu.

| # | Lệnh | Đạt | Bỏ qua | Đầu ra |
|---|---|---|---|---|
| 1 | `uv run pytest -q -rs --cov` (SQLite, công cụ giả lập) | 592 | 2 (`test_process.py:65`, `:157`, nhóm tiến trình POSIX) | `backend-sqlite.txt` |
| 2 | `docker compose --profile test run --build --rm test` (PostgreSQL, công cụ giả lập) | 594 | 0 | `backend-postgres.txt` |
| 3 | `ruff check`, `ruff format --check`, `mypy`, `pip-audit` trong image kiểm thử | sạch | — | `static.txt` |
| 4 | `python -m unittest discover -s experiments/tests` (Python 3.12) | 153 | 0 | `experiments.txt` |
| 5 | `npm run check`, `npm run build`, `npm run test:e2e` (API giả lập) | Vitest 78; Playwright 2 | 1 (kiểm thử stack thật, chạy ở dòng 7) | `frontend.txt` |
| 6 | `scripts.export_openapi` so với `frontend/openapi.json`; `scripts.check_worker` | giống hệt; worker sẵn sàng | — | `run.txt` |
| 7 | `FULL_STACK_URL=http://127.0.0.1:5173 npx playwright test multi-cwe-full-stack` (**công cụ thật**, từ biểu mẫu tới SARIF) | 1 | 0 | `full-stack.txt`, `e2e/` (báo cáo JSON, SARIF, ảnh chụp) |
| 8 | `legacy_regression.py` (**công cụ thật**, bốn profile cũ so với lượt quét lưu ngày 14/11) | 4/5 giống hệt; ca v0.1 như mục 18.3 | — | `legacy-regression.txt` |

Dòng 7, lượt quét `9c25499b…` của OWASP BenchmarkPython `f129148`: 239 kết quả = 176 cảnh báo phát
hiện + 63 kết quả truy vấn bằng chứng; 0 cảnh báo chưa xếp hạng; 149 đơn vị rà soát thành 145 ứng
viên, 81 ở danh sách rà chính và 64 đã gạn; nhóm lệnh 51 → 24 đơn vị (2 gạn), nhóm đường dẫn 125 →
125 đơn vị (62 gạn). SARIF có 239 kết quả, 68 kết quả mang `suppressions` (thuộc 64 đơn vị đã gạn).

### 18.3 Bảng nghiệm thu

| # | Tiêu chí | Kết luận | Căn cứ |
|---|---|---|---|
| 1 | Bốn profile cũ giữ kết quả | **PASS**, một thay đổi có chủ ý | Golden 15 kịch bản trên SQLite và PostgreSQL; thay đổi duy nhất là lượt `path-traversal-v0.2` chạy dở nay giữ cảnh báo thành đơn vị mức U, theo quyết định của chủ đề án (L1). Công cụ thật: `command-injection-v0.2` và `v0.3` trên `curling@0.2.0`, `v0.2` trên BenchmarkPython (51 kết quả, 24 đơn vị, 2 gạn), `path-traversal-v0.2` trên `flask-admin@4f8be45` cho đúng khóa đơn vị, mức, quyết định, lý do, ứng viên, báo cáo và số kết quả SARIF của lượt quét lưu trước P1. `v0.1` trên `curling`: khóa đơn vị, mức, quyết định, lý do và hash chính sách giống; bản lưu ngày 14/11 thiếu bản ghi ứng viên và lý do giữ vì nó được ghi trước commit `c187059` (thêm bước gạn cho mọi profile), không phải do P1. `scan-parity` và `reconciliation-integration` đạt |
| 2 | Pipeline ghép `multi-cwe-v0.1` | **PASS** | Lượt quét từ giao diện hôm nay cho đúng số của P1a và P1b; mỗi nhóm bằng lượt quét riêng (P1a `run-03`, pygoat, DSVPWA) |
| 3 | Migration 0008 | **PASS** | Vòng hai chiều trên PostgreSQL; `alembic check`; trên database thật: 366 lượt quét, md5 của ba bảng không đổi, `analysis_family` NULL ở 3.557 đơn vị cũ |
| 4 | API | **PASS** | 0 trường đổi giá trị trên 366 lượt quét cũ; `openapi.json` khớp; kiểm thử API trên PostgreSQL |
| 5 | Giao diện | **PASS**, một giới hạn | Vitest, Playwright với API giả lập, và luồng đầy đủ trên stack thật. Giới hạn: luồng stack thật không nằm trong CI |
| 6 | SARIF | **PASS** sau khi sửa | Lượt ghép: số kết quả SARIF bằng số kết quả lưu ở mọi lượt, kể cả ba ca lỗi tiêm. Lượt chạy dở của profile đơn `path-traversal-v0.2` trước đây xuất SARIF rỗng và không vào danh sách rà (lỗi L1); nay mọi kết quả đã lưu đều được xuất và cảnh báo chưa xếp hạng thành đơn vị giữ mức U |
| 7 | Bảo toàn cảnh báo | **PASS** | 6.492 kết quả, mỗi kết quả liên kết với đúng một đơn vị; 0 kết quả ngoài đơn vị; 0 kết quả nằm trong hai đơn vị. Lượt ghép còn tự kiểm lúc chạy (`families.check_conservation`) và thất bại thay vì ghi kết quả thiếu |
| 8 | Không gộp nhầm giữa các CWE | **PASS**, bằng chứng trên mã thật còn mỏng | 0 liên kết giữa đơn vị và kết quả của nhóm khác; 0 khóa ứng viên dùng chung giữa hai nhóm. Một file thật có cả hai nhóm (DSVPWA); ca lồng nhau chỉ có trên nguồn tổng hợp |
| 9 | Không tự gạn khi thiếu bằng chứng | **PASS** | 314 đơn vị đã gạn: 0 đơn vị thuộc lượt chạy ngôn ngữ có công cụ phát hiện hoặc bộ định vị chưa hoàn tất; 0 đơn vị bị gạn bởi G1, G3 hay G4 khi bước bằng chứng của chính quy tắc đó lỗi; mọi đơn vị đã gạn có tên quy tắc, bản ghi bằng chứng và danh sách lý do giữ rỗng. Khi `codeql-evidence` lỗi, G2 vẫn gạn lệnh hằng: G2 không dùng bước đó (chứng minh lệnh hằng và mức Bandit), và đây là logic đã khóa, không đổi |
| 10 | Trạng thái bằng chứng | **PASS** sau khi sửa | Lỗi L3 ở mục 18.5 đã sửa kèm kiểm thử |
| 11 | Provenance của lượt quét ghép | **PASS** sau khi sửa | Lỗi L2 ở mục 18.5 đã sửa kèm kiểm thử và kiểm trên stack thật |
| 12 | CI | **FAIL** (chưa chạy) | Không có lượt GitHub Actions nào cho nhánh; mọi job đã chạy tương đương tại chỗ và đạt. Nhánh đã được push; còn chờ draft pull request của chủ đề án (mục 18.1) |
| 13 | Tuyên bố của báo cáo khớp hiện vật | **PASS** sau khi sửa | Mục 18.4: câu chữ đã sửa, và báo cáo của ứng dụng nay tự tách cảnh báo phát hiện khỏi kết quả truy vấn bằng chứng (lỗi L4) |

### 18.4 Đối chiếu tuyên bố của báo cáo P1 với hiện vật

| Tuyên bố | Hiện vật | Kết luận |
|---|---|---|
| Lượt ghép bằng hai lượt quét riêng (P1a) | `run-02`, `run-03`: `equivalent: true`; `run-01`: `false` vì công cụ so sánh, bản gốc còn giữ; tiêu chí `run-03` ghi trước khi chạy | Đúng |
| "239 cảnh báo, 51 và 188 theo nhóm" | 51 + 125 cảnh báo phát hiện + 63 kết quả truy vấn bằng chứng `st/cwe-22/all` | **Đã nói lại:** 239 là số kết quả công cụ; số cảnh báo phát hiện là 176. Câu chữ ở mục 17.4 và `docs/research.md` đã sửa; báo cáo của ứng dụng nay ghi 176 và 63 riêng |
| "2 và 62 đơn vị đã gạn" | Đúng số; không nhãn nào được dùng | Đúng, với điều kiện không đọc thành "64 cảnh báo sai đã xác minh". Hiệu quả gạn đã đo vẫn chỉ là các số ở bảng mục 5.6 |
| Migration không ghi lại dữ liệu cũ | `db-before-0008.txt` và `db-after-0008.txt`: cùng số dòng và md5 | Đúng |
| API cũ và mới giống nhau trên 366 lượt quét | `history-compare.txt` | Đúng |
| Ba ca lỗi tiêm giữ đủ cảnh báo | `fault-run.txt` | Đúng; là lỗi tiêm |
| Dự án thật có hai nhóm trong một file | `real-project-2-result.json`; tiêu chí ghi trước kết quả | Đúng, một file; ứng viên đầu không đạt và được ghi là không đạt |
| "Cảnh báo chưa xác định nhóm" đã kiểm | Chỉ kiểm thử tự động | Đúng như đã ghi: chưa gặp trên stack thật |

### 18.5 Lỗi còn tồn tại và lỗi đã sửa

**Đã sửa trong lần rà này** (mỗi lỗi có kiểm thử thất bại khi bỏ bản sửa):

- **L2 — bản ghi lượt quét ghép thiếu hash truy vấn đã quan sát** (`c8959aa`). Worker chỉ tải lên các
  file ở gốc thư mục ngôn ngữ (`task.py`, `_upload`), còn `run.json` của từng thành viên — nơi ghi
  `codeql_query_files` — nằm dưới `families/` và bị bỏ lại. Lượt quét profile đơn lưu thông tin này,
  lượt ghép thì không. Sửa: `run.json` của lượt ghép ghi `codeql_query_files` cho từng thành viên
  (`families.py`, `scan_language_families`). Kiểm thử: `test_families.py` và
  `test_composite_scan.py`; trên stack thật, bản ghi lưu của một lượt quét DSVPWA có đúng hash đã
  ghim của cả hai thành viên.
- **L3 — hai lý do giữ bị gắn nhầm trạng thái "đã đối chiếu"** (`834156b`). `service.evidence_state`
  trả `not_refuted` cho `flow_rule_without_evidence_query` và
  `evidence_baseline_does_not_report_this_alert`, dù ở hai ca này không có bằng chứng nào để đối
  chiếu. 202 đơn vị đã lưu mang lý do thứ nhất. Sửa: hai lý do này cho `insufficient`
  (`service.py`, `_EVIDENCE_INSUFFICIENT`). Không quyết định gạn nào đổi: trường này chỉ được suy ra
  khi đọc.
- **L1 — lượt quét `path-traversal-v0.2` chạy dở giấu cảnh báo khỏi người rà** (có từ trước P1).
  `analysis.py:350-351` chỉ xếp hạng khi lượt chạy hoàn tất; cảnh báo vẫn được lưu nhưng không có
  đơn vị, nên không vào danh sách rà, báo cáo ghi "3 cảnh báo → 0 ứng viên" và `report.build_sarif`
  (nối với `unit_findings`) xuất SARIF rỗng. Sửa theo hai quyết định của chủ đề án:
  1. Lớp xuất (`4360121`): báo cáo có `stages.unranked_alerts` và SARIF xuất mọi kết quả đã lưu, kể
     cả kết quả không nằm trong đơn vị nào (`ranked: false`). Phần này còn giá trị cho dữ liệu ghi
     trước bản sửa thứ hai.
  2. Đơn vị giữ (commit kế tiếp): khi một profile đơn không xếp hạng cảnh báo nào của lượt chạy,
     `task.scan_snapshot` gọi `families.hold_unranked` để giữ chúng đúng như lượt quét ghép giữ cảnh
     báo của nhóm chưa xếp hạng: mỗi vị trí được báo là một đơn vị `F10_FAMILY_NOT_RANKED`, mức U, ở
     danh sách rà, trạng thái bằng chứng "không lấy được", không bao giờ bị gạn. File bị ghim
     `analysis.py` không đổi. Đây là thay đổi hành vi có chủ ý của một profile cũ ở đúng một trạng
     thái: golden `path-traversal-v0.2-partial-run.json` được sinh lại (thêm 2 đơn vị và 2 đánh giá;
     cảnh báo, lượt chạy công cụ và trạng thái lượt quét không đổi), 14 golden còn lại không đổi.
     Lượt chạy hoàn tất không bị ảnh hưởng. Kiểm thử:
     `test_an_incomplete_single_profile_run_holds_its_alerts_for_review`,
     `test_stored_alerts_without_a_unit_are_counted_and_exported`,
     `test_task.py::test_partial_evidence_run_ranks_nothing_and_holds_every_alert`.

  Kiểm trên stack thật ở `82b82a5` (`artifacts/multi-cwe-p1-audit/single_profile_fault.py`, cùng
  tệp bọc `codeql` của mục 17.4 điểm 9, nguồn tổng hợp đã lưu): CodeQL thật phân tích xong pack
  CWE-22 nhưng thoát mã lỗi. Lượt quét `path-traversal-v0.2` ghi `failed`; 4 kết quả đã lưu nằm trong
  2 đơn vị `F10_FAMILY_NOT_RANKED` mức U ở danh sách rà, trạng thái bằng chứng "không lấy được"; SARIF
  có đủ 4 kết quả, không kết quả nào mang `suppressions`. Lượt quét sạch của cùng snapshot và cùng
  profile cho 2 đơn vị `EV_KEPT_NO_PROOF` như trước (2 cảnh báo phát hiện + 2 kết quả bằng chứng). Đây
  là lỗi được tiêm; chưa gặp lượt chạy dở tự phát của profile này.
- **L4 — kết quả truy vấn bằng chứng được đếm là cảnh báo** (có từ trước P1; `4360121`). Báo cáo đếm
  mọi dòng `findings`; với nhóm CWE-22 con số "trước" vì thế gồm cả kết quả của `st/cwe-22/all`
  (`safety_evidence.py:90-119`). Sửa: báo cáo có `evidence_results` và `detection_alerts` cho cả lượt
  quét và từng nhóm, giao diện dùng `detection_alerts` làm cột "trước", và mỗi kết quả SARIF mang
  `resultRole`. `raw_alerts` giữ nguyên nghĩa cũ. Trên BenchmarkPython bằng công cụ thật: 239 kết quả
  = 176 cảnh báo phát hiện + 63 kết quả truy vấn bằng chứng; nhóm CWE-22 là 125 → 63. Kiểm thử:
  `test_a_single_evidence_profile_counts_its_evidence_results_apart` và bảng số của lượt ghép. Vai
  trò của kết quả chỉ biết được ở đơn vị do thành viên xếp hạng; ở đơn vị giữ và cảnh báo chưa xếp
  hạng nó là `unknown` và được tính vào `detection_alerts`.
- Câu chữ "công cụ chứng minh ứng viên là sai" trong `schemas.py`, `report.py` và nhãn giao diện ở
  `scan-report.tsx` đã đổi thành "thỏa điều kiện gạn của nhóm"; chú thích sai ở
  `families.CompositeResult.findings` đã được viết lại.

Commit theo từng lỗi (đều đã push; không commit nào bị viết lại):

| Lỗi | Commit | Ghi chú |
|---|---|---|
| L2 | `c8959aa` | Riêng |
| L3 | `834156b` | Riêng |
| L1 | `bdfdb7e` (đơn vị giữ) và phần xuất SARIF trong `4360121` | Phần xuất nằm chung commit với L4 vì cùng sửa bảng số của báo cáo; tách ra sẽ phải viết lại lịch sử đã push |
| L4 | `4360121` | Chung với phần xuất của L1 |

**Còn tồn tại:**

- **L5 — CI chưa chạy trên GitHub**, và không job nào quét profile ghép bằng công cụ thật (mục 18.1).
- **L6 — commit `dc1db13` không qua `tsc` khi đứng riêng**; chủ đề án đã quyết định để nguyên.
- Đơn vị giữ của profile đơn (L1) đã kiểm trên stack thật bằng lỗi được tiêm; chưa gặp lượt chạy dở tự phát.

### 18.6 Có đóng được P1 không

**Về kỹ thuật thì đóng được, với một điều kiện còn lại: CI chạy trên GitHub và xanh.** Mười hai
trong mười ba tiêu chí đạt. Tiêu chí CI chưa đạt vì chưa có lượt chạy nào: nhánh đã được push, và
lượt chạy sẽ bắt đầu khi có draft pull request (mục 18.1). Chủ đề án sau đó yêu cầu mở draft pull
request vào `feat/cwe22-triage`; tại thời điểm ghi mục này pull request **chưa được mở**: máy làm
việc không có `gh`, và trợ lý không được phép đọc thông tin đăng nhập Git để gọi API của GitHub. Vì
vậy tiêu chí CI vẫn là FAIL (chưa chạy) và P1 chưa được ghi là đã đóng. So với
`origin/feat/cwe22-triage`, pull request sẽ gồm 22 commit của công việc đa CWE và **một commit nền**
chưa có trên remote của nhánh đó: `837c53d` (tài liệu luận văn); nhánh cơ sở được để nguyên. Mọi job
của CI đã chạy tương đương tại chỗ và đạt, nhưng điều đó không thay cho lượt chạy thật. Nếu CI đỏ,
P1 chưa đóng cho tới khi nguyên nhân được xử lý.

## 19. P2 — thẩm định và thiết kế tối thiểu cho CWE-89 (2026-11-15)

Chỉ là thẩm định và thiết kế. Không có mã, profile hay rule nào của CWE-89 được thêm ở lần rà này.
Các bước 1–5 của mục 19.4 (P2a) đã được triển khai sau đó; kết quả ở
[mục 20](#20-trạng-thái-p2a-2026-11-15).

### 19.1 Kiến trúc hiện tại cho phép và không cho phép gì

| Ràng buộc | Ở đâu | Hệ quả với CWE-89 |
|---|---|---|
| Đúng một thành viên là `ScanProfile`; nó chạy mọi công cụ sàng lọc và tạo database | `families.py`, `_ordered` (dòng 193-196) và `_participating` | Semgrep, Bandit, ESLint chỉ chạy với cấu hình của nhóm lệnh. Không có chỗ để đưa rule của nhóm khác vào |
| Mọi thành viên còn lại phải là `EvidenceProfile` | `families.py`, vòng lặp sau `run_member(primary, …)` (`assert isinstance(profile, EvidenceProfile)`); `Family.profile_type` | Thành viên thứ ba buộc phải có dạng "truy vấn đối chứng + truy vấn bằng chứng" |
| `EvidenceProfile` chỉ chạy CodeQL, cần pack tự viết nằm trong kho và hai rule `baseline`/`evidence` | `profile.py`, `load_evidence_profile` | Không trỏ được vào `Security/CWE-089/SqlInjection.ql` của pack chuẩn |
| `assess_with_evidence` gạn mọi vị trí mà truy vấn bằng chứng không báo | `safety_evidence.py:124-149` | Một `EvidenceProfile` **không thể** "chỉ phát hiện và giữ". Giả lập bằng truy vấn bằng chứng trùng truy vấn đối chứng sẽ ghi sai rằng "truy vấn bằng chứng vẫn báo" và nhân đôi số kết quả (lỗi L4) |
| Đường đánh giá của `ScanProfile` viết cứng CWE-78 | `assess.py:15` (`_CODEQL_RULES`), `claims.py:51` (`cwe78_candidate`), `sinks_python.py`, `adjudicate.py` | Nhóm thứ hai nhiều công cụ không đi qua `scan_language` được. Các file này bị ghim bởi bản đăng ký nghiên cứu nên không sửa: nhóm mới cần bộ xử lý riêng, bằng file mới |
| Định tuyến theo bộ rule đã ghim khi một lượt chạy phục vụ nhiều nhóm | `classification.py`, nhánh `pinned_rule_set` | Đã có và có kiểm thử, nhưng **chưa từng chạy trên stack thật** |
| Tên lượt chạy = `codeql-<nhóm>`, cột `tool_runs.tool` dài 32 ký tự | `families.PASS_PREFIX`; `features/scans/models.py:54` | `sql-injection` vừa. Tên nhóm dài hơn khoảng 24 ký tự (ví dụ `server-side-request-forgery`) sẽ không ghi được: dùng tên ngắn |
| Ngân sách thời gian | `task.py:63-70`: giới hạn mềm 9.000 s, cứng 10.500 s; `celery_app.py:24`: visibility 10.800 s | Hôm nay còn dư 240 s. Thêm một lượt CodeQL 600 s cho mỗi ngôn ngữ đẩy trường hợp xấu nhất lên 9.960 s: phải nâng cả ba giới hạn hoặc hạ timeout của lượt mới. Kiểm thử `test_task_time_limits_…` sẽ chặn nếu quên |
| Cột `location_units.analysis_family` là chuỗi tự do 48 ký tự | migration 0008 | Không cần migration mới cho nhóm mới |
| `FamilyName` là kiểu liệt kê trong API và giao diện | `schemas.py:19`; `frontend/src/features/scans/types/index.ts` | Thêm nhóm là thay đổi hợp đồng API (thêm giá trị), phải sinh lại `openapi.json` và kiểu |

### 19.2 Công cụ đã ghim hỗ trợ CWE-89 tới đâu

Kiểm tra trong image worker hiện tại; không tải thêm gì.

| Công cụ | Python | JS/TS |
|---|---|---|
| CodeQL 2.27.1 | `py/sql-injection` (`python-queries` 1.8.11), độ chính xác cao, CWE-089 | `js/sql-injection` (`javascript-queries` 2.4.6), khai **CWE-089, CWE-090 và CWE-943**: một rule ánh xạ nhiều CWE, đúng ca mà `mapped_cwes` sinh ra để giữ |
| Bandit 1.9.4 | `B608` (chuỗi SQL ghép), `B610`, `B611` (Django `extra`, `RawSQL`): bắt mẫu cú pháp, không có luồng | — |
| Semgrep CE 1.178.0 | Chưa có rule CWE-89 nào trong kho. Rule phải được đưa vào kho và ghim hash như `experiments/rules/python-upstream/`; cần kiểm tra giấy phép của nguồn rule trước | Như bên trái |
| ESLint + `eslint-plugin-security` 4.2.1 | — | Plugin đã ghim không có rule SQL |

Chi phí đo hôm nay trên BenchmarkPython (một lần): Semgrep 2,0 s, Bandit 1,9 s, tạo database 12,5 s,
`codeql` 10,2 s, `codeql-evidence` 10,4 s, `codeql-path-traversal` 8,2 s. Chi phí nằm ở CodeQL; một
lượt Semgrep hay Bandit riêng cho nhóm mới tốn vài giây.

Dữ liệu phát triển có sẵn: BenchmarkPython có 16 ca `sqli` (CWE-89) theo file kết quả mong đợi của
chính nó. File đó là nhãn: chỉ được dùng theo một giao thức ghi trước.

### 19.3 Hai phương án

**A — CWE-89 chỉ bằng CodeQL, chưa gạn.** Thêm một lượt `codeql-sql-injection` trên database dùng
chung, mỗi cảnh báo thành một đơn vị được giữ.

- Thay đổi: một kiểu thành viên mới "chỉ phát hiện" (không dùng lại `EvidenceProfile`, xem 19.1); nới
  ràng buộc "các thành viên còn lại là `EvidenceProfile`"; profile ghép mới; giá trị mới của
  `FamilyName`; giới hạn thời gian.
- Nguy cơ hồi quy: thấp. Bốn profile cũ và `multi-cwe-v0.1` không đổi một byte cấu hình nào.
- So với mục tiêu năm CWE: phủ nhanh (pack chuẩn của CodeQL có sẵn truy vấn CWE-79 và CWE-918 cho cả
  hai ngôn ngữ), nhưng không đạt phần "nhiều công cụ rồi hợp nhất" của đề án, và giữ nguyên nút thắt:
  công cụ sàng lọc vẫn thuộc riêng nhóm lệnh.

**B — CWE-89 nhiều công cụ, một kế hoạch quét chung, định tuyến rule/query theo nhóm.**

- Nếu hiểu là **gộp cấu hình** (một lượt Semgrep chạy rule của mọi nhóm, một cấu hình Bandit chung):
  nguy cơ hồi quy cao và cụ thể. `analysis.py:165-168` kiểm định nghĩa rule theo tên file
  `rule-<chỉ số>.yaml` của riêng thành viên; `analysis.py:169-179` so hash `bandit.ini` đã ghim với
  file đã dùng. Cấu hình gộp làm lệch cả hai, và G2 của nhóm lệnh dựa vào mức của Bandit. Cả hai chỗ
  nằm trong file bị ghim. Định tuyến khi đó phải dùng nhánh `pinned_rule_set`, lần đầu chạy trên dữ
  liệu thật, và trạng thái "chưa xác định nhóm" trở thành ca có thể gặp.
- Nếu hiểu là **một kế hoạch, nhiều lượt chạy có tên**: mỗi nhóm đóng góp các lượt của riêng mình
  (`codeql-<nhóm>`, sau đó `semgrep-<nhóm>`, `bandit-<nhóm>`) với cấu hình đã ghim của riêng nó; thứ
  dùng chung là snapshot, database CodeQL, thư mục làm việc và phép kiểm bảo toàn. Định tuyến vẫn theo
  lượt chạy, như đã chứng minh ở P1. Các lượt của nhóm lệnh không đổi một byte, nên tính tương đương
  giữ được theo cấu trúc. Giá phải trả là vài giây cho mỗi lượt Semgrep hoặc Bandit thêm.

**Kết luận.** B đáp ứng mục tiêu dài hạn tốt hơn, ở dạng "nhiều lượt chạy có tên", không phải dạng
gộp cấu hình: nó giữ nguyên tắc "không ép gộp" của mục 5.5 và không chạm file bị ghim. A không phải
một kiến trúc khác mà là **bước đầu tiên của B**: lượt `codeql-sql-injection` chính là một lượt chạy
có tên. Vì vậy P2 nên làm A trước, viết theo cấu trúc mà B mở rộng được, rồi mới thêm công cụ.
Gộp cấu hình chỉ nên xét lại khi có số đo cho thấy các lượt Semgrep riêng là nút thắt.

### 19.4 Thiết kế tối thiểu

| Bước | Việc | File | Ghi chú |
|---|---|---|---|
| 0 | CI xanh trên pull request của P1; nâng giới hạn thời gian | `task.py`, `celery_app.py` | Điều kiện vào P2. L1 và L4 đã xử lý ở lần rà mục 18 |
| 1 | Golden cho `multi-cwe-v0.1` trên đầu vào tổng hợp cố định | `backend/tests/golden/` | Lưới an toàn trước khi sửa lớp ghép |
| 2 | Kiểu profile "chỉ phát hiện": các truy vấn của pack chuẩn ghim theo hash, CWE ánh xạ khai trong manifest cho từng rule, không có rule bằng chứng | `scanners/profile.py`; `profiles/sql-injection-v0.1/` | `js/sql-injection` khai ba CWE; không suy CWE từ tên rule |
| 3 | Bộ xử lý "phát hiện và giữ": mỗi vị trí được báo là một đơn vị, luôn ở danh sách rà, lý do giữ `no_filter_condition_for_family`, trạng thái bằng chứng `insufficient` | file mới `workflows/scans/detection.py`; `service.py` | Dùng `reconcile_findings(findings, [], {})` như đơn vị giữ hiện có; không qua `assess.py`. Mức ưu tiên của nhóm là quyết định của chủ đề án |
| 4 | Lớp ghép chọn bộ xử lý theo kiểu thành viên; vẫn đúng một thành viên tạo database | `families.py`: `Family.profile_type`, `_ordered`, `_claim`, vòng lặp thành viên | Thay đổi nhỏ nhất phá ràng buộc ở 19.1 |
| 5 | Nhóm `sql-injection` (CWE-89) và profile `multi-cwe-v0.2` với ba thành viên; `multi-cwe-v0.1` giữ nguyên | `families.FAMILIES`, `core/config.py`, `schemas.py`, `frontend/…/types`, `openapi.json` | Thêm, không sửa profile đã ghim |
| 6 | Lượt `semgrep-sql-injection` và `bandit-sql-injection`; mỗi cảnh báo vẫn là đơn vị riêng theo vị trí được báo | lớp ghép; rule đưa vào kho | Phần "B": lượt chạy có tên cho công cụ sàng lọc |
| 7 | Bộ định vị sink SQL và gộp cảnh báo của nhiều công cụ theo sink | file mới dưới `triage/` | Là hiện vật nghiên cứu: cần đặc tả và phản ví dụ riêng |
| 8 | Điều kiện gạn cho CWE-89 | — | Chỉ sau một giao thức ghi trước và một lượt đo riêng; không dùng lại G1–G4 |

Bước 1–5 là P2a (phương án A trong cấu trúc của B). Bước 6–7 là P2b. Bước 8 nằm ngoài P2.

### 19.5 Tiêu chí nghiệm thu P2a

1. Golden của bốn profile cũ và của `multi-cwe-v0.1` không đổi một byte; `legacy_regression.py` cho
   kết quả giống lần rà này.
2. Trên một snapshot phát triển có cả ba nhóm, `multi-cwe-v0.2` cho nhóm lệnh và nhóm đường dẫn đúng
   kết quả của `multi-cwe-v0.1`, và nhóm SQL đúng tập cảnh báo (rule, vị trí) của một lệnh
   `codeql database analyze` độc lập với cùng truy vấn.
3. Mỗi kết quả nằm trong đúng một đơn vị; không đơn vị nào lẫn nhóm; có kiểm thử cho cảnh báo SQL
   nằm trong một lời gọi lệnh và cho hai nhóm trên cùng một vùng mã.
4. **Không đơn vị nào của nhóm SQL bị gạn**, ở mọi kiểm thử và mọi lượt chạy; trạng thái bằng chứng
   chỉ là `insufficient` hoặc `unavailable`; SARIF không có `suppressions` cho nhóm này.
5. Lượt `codeql-sql-injection` lỗi hoặc chạy dở: cảnh báo của nó thành đơn vị
   `F10_FAMILY_NOT_RANKED`, hai nhóm kia không đổi; kiểm bằng lỗi tiêm trên stack thật.
6. Cảnh báo của `js/sql-injection` giữ nguyên `reported_cwes`, có `mapped_cwes` gồm cả ba CWE và
   thuộc nhóm `sql-injection`.
7. Trường hợp xấu nhất về thời gian nhỏ hơn giới hạn mềm, giới hạn cứng nhỏ hơn visibility timeout;
   chi phí từng lượt được ghi.
8. Không cần migration; dữ liệu cũ đọc như trước (so sánh API trên các lượt quét đã lưu).
9. CI xanh trên một pull request, và có một job chạy profile ghép bằng công cụ thật. *Ngày
   2026-11-16 chủ đề án tách tiêu chí này khỏi P2a: nó thuộc một đầu việc CI/CD riêng, làm sau.*
10. Không file bị ghim hay sổ đăng ký nghiên cứu nào thay đổi; không dùng nhãn; báo cáo chỉ nói
    "phát hiện và giữ", không nêu số giảm cảnh báo sai cho CWE-89.

### 19.6 Nguy cơ hồi quy cần theo dõi

- `families._ordered` và vòng lặp thành viên là nơi duy nhất P2a sửa mã đang chạy của P1; golden
  của lượt ghép (bước 1) phải có trước.
- Giới hạn thời gian và visibility timeout đổi cùng nhau; lệch một bên làm lượt quét đang chạy bị
  giao lại.
- Thêm giá trị vào `FamilyName` là đổi hợp đồng API: giao diện cũ phải bỏ qua được nhóm lạ.
- Khi bước 6 tới: mọi lượt chạy mới phải có tên riêng và cấu hình riêng. Không sửa `bandit.ini`, danh
  sách rule Semgrep hay cấu hình ESLint của nhóm lệnh, kể cả khi "chỉ thêm một rule".
- Kết quả bằng chứng lưu như cảnh báo (L4) nay được báo cáo tách riêng, nhưng chỉ khi thành viên ghi
  vai trò của từng kết quả. Bộ xử lý mới không nên lưu kết quả bằng chứng như cảnh báo; nếu có, nó
  phải ghi vai trò như `safety_evidence` đang làm.

## 20. Trạng thái P2a (2026-11-15)

P2a thêm profile `multi-cwe-v0.2`: một lượt quét xử lý CWE-78, CWE-22 và CWE-89. CWE-89 dùng truy
vấn chuẩn của CodeQL và **chỉ được phát hiện và giữ**: không xếp hạng, không gạn. Đây là các bước
1–5 của mục 19.4. Semgrep, Bandit và mọi cơ chế gạn cho CWE-89 chưa làm. Không nhãn nào được dùng,
không dữ liệu held-out hay cặp đã đóng băng nào được quét, không file bị ghim nào bị sửa.

**Trạng thái mã đã kiểm thử:** nhánh cục bộ `feat/multi-cwe-p2a`, dựng trên `ffc218b`. Mọi kiểm thử
ở mục này chạy trên cây làm việc trước khi commit; sau đó, theo quyết định của chủ đề án, thay đổi
được commit tách theo đầu việc trên nhánh này, **chưa push** lúc ghi (đã push sau đó, mục 22.7). Cây `backend/`, `frontend/`, `profiles/` đã kiểm thử có
mã Git `2e6ed328e7945274b8bc7aa0dbeac6cf0454c369` ở lượt hồi quy mục 20.5 (tính sau lượt chạy; từ
lúc dựng image tới lúc đó chỉ có file kiểm thử và tài liệu thay đổi) và
`081b3da00fd72afc6865f4be2499fd8be683a351` sau khi thêm kiểm thử trình duyệt của `v0.2`; mã ứng dụng
và profile giống nhau ở hai cây; image API và worker đang chạy chứa đúng mã ứng dụng
và profile của cây đó (so hash). Đầu ra thô: `artifacts/multi-cwe-p2a/` (không vào Git).

### 20.1 Đã làm

| Việc | File |
|---|---|
| Kiểu profile `detection`: ghim theo hash truy vấn của gói chuẩn CodeQL, khai CWE ánh xạ của từng rule và mức cố định | `backend/app/scanners/profile.py` (`DetectionProfile`, `load_detection_profile`) |
| Bộ xử lý "phát hiện và giữ": mỗi vị trí được báo là một đơn vị ở danh sách rà | `backend/app/workflows/scans/detection.py` (mới) |
| Lớp ghép chọn bộ xử lý theo kiểu thành viên; nhóm `sql-injection` | `backend/app/workflows/scans/families.py` |
| Thành viên `sql-injection-v0.1` và profile ghép `multi-cwe-v0.2` | `profiles/sql-injection-v0.1/`, `profiles/multi-cwe-v0.2/` |
| Cấu hình, hợp đồng API, lý do giữ mới, giới hạn thời gian | `core/config.py`, `workflows/scans/schemas.py`, `service.py`, `task.py`, `workers/celery_app.py` |
| Giao diện: lựa chọn profile, nhãn nhóm CWE-89, lý do giữ | `frontend/src/features/scans/`, `openapi.json`, `api-schema.d.ts` |
| CLI phát triển quét riêng một thành viên `detection` | `backend/scripts/scan_families.py` |

Giữ nguyên: `profiles/multi-cwe-v0.1/` và bốn profile cũ (không file nào đổi); G1–G4; mọi file bị
ghim bởi bản đăng ký nghiên cứu (`triage/*.py`, `analysis.py`, `semgrep.py`, `acquisition.py`);
`experiments/`, `rules/`, `tools/`; schema database (không migration mới; `alembic check` sạch).
`multi-cwe-v0.2` ghim hai thành viên đầu bằng đúng hash mà `multi-cwe-v0.1` ghim và dùng cùng phiên
bản cách ghép `family-composition-v0.1`.

Truy vấn đã ghim: `Security/CWE-089/SqlInjection.ql` của `codeql/python-queries` 1.8.11 (rule
`py/sql-injection`, CWE-89) và của `codeql/javascript-queries` 2.4.6 (rule `js/sql-injection`,
CWE-89, CWE-90, CWE-943). Mỗi ngôn ngữ có một lượt `codeql-sql-injection` trên database mà nhóm
lệnh đã tạo; không database nào được tạo thêm.

### 20.2 Đối chứng trước khi sửa mã

Trước khi sửa dòng mã nào (mã `ffc218b`, cây làm việc sạch), `multi-cwe-v0.1` được quét trên stack
thật với hai nguồn phát triển: `python artifacts/multi-cwe-p2a/scan_snapshot.py multi-cwe-v0.1
baseline-v0.1`. Kết quả đầy đủ (lượt quét, mọi đơn vị kèm cảnh báo, báo cáo, SARIF) ở
`artifacts/multi-cwe-p2a/baseline-v0.1/`.

| Nguồn | Snapshot | CWE-78 | CWE-22 |
|---|---|---|---|
| OWASP BenchmarkPython `f129148` | `0defda4c…` | 51 kết quả, 24 đơn vị, 2 gạn | 188 kết quả (125 cảnh báo phát hiện), 125 đơn vị, 62 gạn |
| Nguồn tổng hợp ba nhóm `artifacts/multi-cwe-p2a/dev-source/three/` (`app.py`, `server.js`, `routes.ts`; tự viết, không bao giờ được chạy) | `9a310328…` | 19 kết quả, 7 đơn vị, 1 gạn | 6 kết quả, 3 đơn vị, 0 gạn |

Hai kho thật đã dùng ở P1 (`pygoat@2aa4cc1`, `DSVPWA@961f86d`) lấy bản đối chứng từ lượt quét
`multi-cwe-v0.1` đã lưu trước khi sửa mã.

Cùng lúc, kết quả của `multi-cwe-v0.1` được ghim bằng tám file golden mới
(`backend/tests/golden/composite/multi-cwe-v0.1-*.json`,
`tests/workflows/scans/test_composite_golden.py`), sinh từ mã chưa sửa.

### 20.3 Đối chứng sau khi sửa: `v0.2` so với `v0.1`, và CWE-89 so với CodeQL chạy riêng

Lệnh: `scan_snapshot.py multi-cwe-v0.2 v0.2`, `scan_repo.py scan multi-cwe-v0.2 v0.2 …` cho hai kho
thật, rồi `python artifacts/multi-cwe-p2a/compare.py` (đầu ra: `comparison.txt`, `comparison.json`).
Lượt CodeQL riêng không dùng mã ứng dụng: trong một container của image worker, `codeql database
create` rồi `codeql database analyze` với đúng một truy vấn đã ghim, trên cùng snapshot
(`independent_codeql.sh`, `independent_repo.sh`; SARIF ở `independent/`).

| Nguồn | CWE-78 và CWE-22: `v0.2` so với đối chứng `v0.1` | CWE-89 trong `v0.2` | So với CodeQL chạy riêng |
|---|---|---|---|
| BenchmarkPython | 24 và 125 đơn vị: đơn vị, báo cáo theo nhóm và SARIF giống hệt | 0 cảnh báo | 0 và 0 |
| Nguồn tổng hợp ba nhóm | 7 và 3 đơn vị: giống hệt | 8 cảnh báo (4 `py/sql-injection`, 4 `js/sql-injection` ở `server.js` và `routes.ts`), 8 đơn vị | 8 và 8, khớp theo ngôn ngữ, rule và vị trí |
| `pygoat` (mã thật) | 4 và 3 đơn vị: giống hệt | 1 cảnh báo `py/sql-injection` (`dockerized_labs/sql_injection_lab/app.py:57`), 1 đơn vị | 1 và 1, khớp |
| `DSVPWA` (mã thật) | 3 và 2 đơn vị: giống hệt | 0 cảnh báo | 0 và 0 |
| `fportantier/vulpy@5249cc8` (mã thật, Python) | 1 và 1 đơn vị: giống hệt | 3 cảnh báo `py/sql-injection`, 3 đơn vị | 3 và 3, khớp |
| `anxolerd/dvpwa@4a8f4a4` (mã thật, Python) | 0 và 0 đơn vị | 0 cảnh báo | 0 và 0 |
| `OWASP/NodeGoat@c5cb68a` (mã thật, JavaScript) | 1 đơn vị CWE-78: giống hệt; không có CWE-22 | 2 cảnh báo `js/sql-injection`, 2 đơn vị | 2 và 2, khớp |
| `juice-shop/juice-shop@266448a` (mã thật, TypeScript và JavaScript) | 0 và 0 đơn vị ở cả hai lượt | 7 cảnh báo `js/sql-injection` trong bốn file `routes/*.ts`, 7 đơn vị | 7 và 7, khớp |

Juice Shop được thêm sau cùng (`large-source-CRITERIA.json`, ghi trước khi quét) vì chưa có cảnh báo
CWE-89 nào trên mã TypeScript thật. Trên kho này CodeQL **tự** báo lượt chạy JavaScript/TypeScript là
chưa hoàn tất (50 cảnh báo `js/parse-error` của trình trích xuất), ở cả `multi-cwe-v0.1` lẫn
`multi-cwe-v0.2`, nên lượt quét ghi `partial`; xem mục 20.4.

Ba kho cuối được thêm sau, để phép so với CodeQL chạy riêng không chỉ dựa trên nguồn tự viết. Tiêu
chí, quy tắc chọn (theo tên và mục đích công bố của kho, không theo đầu ra công cụ quét) và quy tắc
dừng được ghi trước khi quét ở `more-sources-CRITERIA.json`. `vulpy` chỉ được nêu trong một giao thức
như ứng viên bị loại trước khi quét; hai kho kia không có trong sổ đăng ký nào. Vì không có lượt quét
nào của ba kho này từ trước khi sửa mã, bản `multi-cwe-v0.1` để so được quét trên mã đã sửa — mã mà
bốn nguồn đầu cho thấy vẫn cho đúng kết quả `v0.1` cũ.

"Giống hệt" là so khóa đơn vị, vị trí, loại sink, mức, quyết định, lý do, ứng viên, công cụ, lý do
giữ, trạng thái bằng chứng, bản ghi gạn, phiên bản chính sách và từng cảnh báo (lượt chạy, rule, vị
trí, nhãn CWE). Ở mọi lượt `v0.2`: mỗi kết quả nằm trong đúng một đơn vị, 0 đơn vị lẫn nhóm, 0 kết
quả chưa xếp hạng, số kết quả SARIF bằng số kết quả đã lưu.

Với CWE-89 (21 cảnh báo trên năm nguồn có cảnh báo: 8 trên nguồn tổng hợp, 13 trên mã thật gồm 4
Python, 2 JavaScript và 7 TypeScript):

- Cả 21 đơn vị ở danh sách rà chính, mức `U`, quyết định `K10_DETECTED_KEPT`. **0 đơn vị bị gạn**; 0
  kết quả SARIF mang `suppressions`. Ở 14 đơn vị của lượt chạy hoàn tất, lý do giữ là
  `no_filter_condition_for_family` và trạng thái bằng chứng là "chưa đủ"; ở 7 đơn vị của Juice Shop
  có thêm `run_incomplete` và trạng thái là "không lấy được".
- Lưu và xuất SARIF giữ nguyên mã rule, vị trí, nhãn gốc của công cụ (`cwe-089`; với JavaScript
  `cwe-089`, `cwe-090`, `cwe-943`), CWE ánh xạ theo manifest (`CWE-89`; `CWE-89`, `CWE-90`,
  `CWE-943`) và nguồn cảnh báo (công cụ `codeql`, lượt `codeql-sql-injection`).
- Chỗ hai nhóm gặp nhau trên nguồn tổng hợp, quét bằng công cụ thật: `app.py:67` có cảnh báo CWE-89
  (cột 55) nằm bên trong lời gọi `os.system` của nhóm lệnh (cột 16) và `app.py:74` có cảnh báo
  CWE-89 và CWE-22 trên cùng một dòng. Mỗi cảnh báo ở đơn vị của nhóm mình.

**Hai lần công cụ so sánh báo lệch, cả hai do cách so sánh** (bản đầu ra đầu tiên giữ ở
`comparison-first-attempt.txt`):

1. So với CodeQL chạy riêng: tôi điền `endLine` cho SARIF độc lập trong khi ứng dụng lưu vùng mã như
   công cụ viết (thiếu `endLine` thì để trống). Vùng mã gốc giống nhau.
2. Một lượt `multi-cwe-v0.1` chạy lại sau khi sửa mã khác bản đối chứng ở nhóm CWE-22: CodeQL ghi hai
   kết quả của cùng file `BenchmarkTest00090.py` theo thứ tự ngược lại, nên chỉ số trong raw ID đổi
   chỗ. Khóa đơn vị, vị trí và quyết định của 125 đơn vị giống hệt. Hai lượt `multi-cwe-v0.1` chạy
   thêm trên cùng mã cho đúng thứ tự của bản đối chứng; bốn lượt lưu trước khi sửa mã cũng ổn định
   (`order-stability.txt`). Hiện tượng gặp 1 lần trong 3 lượt và không phụ thuộc mã ứng dụng. Công
   cụ so sánh nay so theo nội dung (lượt chạy, rule, file, vùng mã) thay vì theo chỉ số.

Sau khi sửa công cụ so sánh, mọi phép kiểm ở cả tám nguồn đều đạt.

### 20.4 Ca lỗi có kiểm soát

Trên stack thật, một worker thứ hai cùng image với tệp bọc `codeql` (như mục 17.4, điểm 9), nguồn
tổng hợp ba nhóm; mỗi lượt được so theo nội dung với một lượt sạch chạy cùng cách
(`python artifacts/multi-cwe-p2a/sql_faults.py`, đầu ra `sql-faults.txt`).

| Lỗi tiêm vào lượt `codeql-sql-injection` | Lượt quét | Nhóm CWE-89 | Nhóm CWE-78 và CWE-22 |
|---|---|---|---|
| Không lỗi | `completed` | 8 đơn vị `K10_DETECTED_KEPT`, 0 gạn | 7 và 3 đơn vị |
| Phân tích xong, SARIF bị đánh dấu "chưa hoàn tất" (`executionSuccessful: false`) | `partial`; lượt chạy ghi `partial` ở cả hai ngôn ngữ | 8 cảnh báo vẫn là 8 đơn vị `K10_DETECTED_KEPT` ở danh sách rà, lý do giữ thêm `run_incomplete`, bằng chứng "không lấy được"; đủ 8 trong SARIF, 0 `suppressions` | Giống lượt sạch |
| Phân tích xong, ghi SARIF, rồi thoát mã lỗi | `partial`; lượt chạy ghi `failed` ở cả hai ngôn ngữ | 8 cảnh báo đã thu được thành 8 đơn vị `F10_FAMILY_NOT_RANKED`, mức U, danh sách rà, bằng chứng "không lấy được"; đủ 8 trong SARIF, 0 `suppressions` | Giống lượt sạch |
| Thất bại trước khi ghi kết quả | `partial`; lỗi ghi "produced no SARIF output" | Không có cảnh báo nào để giữ; nhóm ghi `failed` | Giống lượt sạch |

**Lượt chạy dở tự phát.** Trên Juice Shop không có lỗi tiêm nào: chính CodeQL báo 50 cảnh báo
`js/parse-error` nên lượt `codeql-sql-injection` của JavaScript/TypeScript ghi `partial`. Bảy cảnh
báo CWE-89 nó đã báo vẫn thành bảy đơn vị ở danh sách rà với `run_incomplete`, 0 gạn, đủ bảy trong
SARIF, và khớp lượt CodeQL chạy riêng. Lượt `codeql` của nhóm lệnh trên cùng kho cũng `partial` ở cả
hai profile.

Cảnh báo của rule không được ghim chỉ có kiểm thử với công cụ giả lập (`test_sql_family.py`).

**Trên trình duyệt thật** (Chromium, stack thật, `node ../artifacts/multi-cwe-p2a/ui_check.mjs`, đầu
ra `ui-check.json` và hai ảnh chụp): biểu mẫu tạo scan có profile mới kèm mô tả; trang lượt quét
`v0.2` của nguồn tổng hợp liệt kê ba nhóm; lọc theo CWE-89 cho đúng 8 đơn vị của cả ba file, đều
"Chưa đủ bằng chứng" và ở danh sách rà chính; danh sách "Đã gạn" của nhóm này rỗng; chi tiết một đơn
vị TypeScript hiện nhãn gốc `cwe-089, cwe-090, cwe-943`, CWE ánh xạ `CWE-89, CWE-90, CWE-943`, nhóm
và lượt chạy `codeql-sql-injection`; bảng trước–sau có dòng CWE-89 với 8 cảnh báo, 0 gạn. Trang của
lượt quét có lượt CWE-89 thất bại ghi "Scan hoàn thành một phần", hai ngôn ngữ `failed`, và 8 đơn vị
giữ lại với "Không lấy được bằng chứng".

### 20.5 Kiểm thử hồi quy

Một lệnh trên trạng thái mã cuối: `bash artifacts/multi-cwe-p2a/final/run_all.sh` (đầu ra `run.txt`
và các file cùng thư mục).

| # | Lệnh | Đạt | Bỏ qua |
|---|---|---|---|
| 1 | `uv run pytest -q -rs --cov` (SQLite, công cụ giả lập) | 652 | 2 (`test_process.py:65`, `:157`, nhóm tiến trình POSIX trên Windows) |
| 2 | `docker compose --profile test run --build --rm test` (PostgreSQL, công cụ giả lập) | 654 | 0 |
| 3 | `ruff check`, `ruff format --check`, `mypy`, `pip-audit` | sạch | — |
| 4 | `python -m unittest discover -s experiments/tests` (Python 3.12) | 153 | 0 |
| 5 | `npm run check`, `npm run build`, `npm run test:e2e` (API giả lập) | Vitest 80; Playwright 2 | 1 lúc chạy; 2 sau khi thêm kiểm thử stack thật của `v0.2` (cả hai chạy riêng ở dòng 7 và 9) |
| 6 | `scripts.export_openapi` so với `frontend/openapi.json`; `scripts.check_worker` | giống hệt; worker nhận cả sáu profile | — |
| 7 | `npx playwright test multi-cwe-full-stack` (công cụ thật, `multi-cwe-v0.1` từ biểu mẫu tới SARIF) | 1: 239 kết quả, 149 đơn vị, 64 gạn, như trước | 0 |
| 8 | `legacy_regression.py` (công cụ thật, bốn profile cũ so với lượt quét lưu ngày 14/11) | 4/5 giống hệt; ca v0.1 như mục 18.3 | — |
| 9 | `FULL_STACK_URL=… npx playwright test multi-cwe-v02-full-stack` (công cụ thật, `multi-cwe-v0.2` từ biểu mẫu tới SARIF; thêm sau lượt chạy trên, mã ứng dụng không đổi) | 1 | 0 |

Dòng 9 là kiểm thử mới `frontend/tests/e2e/multi-cwe-v02-full-stack.spec.ts`: chọn profile ba nhóm
trên biểu mẫu, quét `pygoat@2aa4cc1` bằng công cụ thật, chờ trang tự cập nhật, lọc theo CWE-89, mở
chi tiết đơn vị, tải báo cáo JSON và SARIF. Kết quả lượt `ad3b3994…`: ba nhóm, 15 kết quả, 8 đơn vị,
1 đơn vị CWE-89 ở danh sách rà, SARIF đủ 15 kết quả và kết quả CWE-89 không mang `suppressions`. Đầu
ra: `artifacts/multi-cwe-p2a/e2e-v02/`.

Trong dòng 1 và 2:

- 15 golden của bốn profile cũ không đổi.
- 8 golden của `multi-cwe-v0.1` sinh từ mã chưa sửa vẫn khớp sau khi sửa
  (`golden-v0.1-before-change.sha256`: 8/8 file không đổi một byte).
- 8 golden mới ghim `multi-cwe-v0.2`.
- Kiểm thử mới: `tests/scanners/test_detection_profile.py` (17), `tests/workflows/scans/
  test_sql_family.py` (25), và hai kiểm thử giao diện trong `families.test.tsx`.
- Hai kiểm thử cũ dùng "sql-injection" làm ví dụ về tên **không tồn tại** được đổi sang một tên
  khác; ý nghĩa của chúng không đổi.

### 20.6 Thời gian quét và giới hạn chạy

Giây của từng bước CodeQL (worker đã chạy các truy vấn ít nhất một lần; mỗi ô một lần đo):

| Bước | BenchmarkPython `v0.1` (trước) | BenchmarkPython `v0.2` | Nguồn tổng hợp `v0.1` (trước) | Nguồn tổng hợp `v0.2` |
|---|---|---|---|---|
| Python `codeql-create` | 15,5 | 14,9 | 2,7 | 2,9 |
| Python `codeql` | 11,2 | 11,1 | 9,4 | 8,7 |
| Python `codeql-evidence` | 9,8 | 10,1 | 6,6 | 7,3 |
| Python `codeql-path-traversal` | 8,3 | 8,8 | 5,8 | 5,6 |
| Python `codeql-sql-injection` | — | 6,4 | — | 5,5 |
| JS/TS `codeql-create` | 7,3 | 7,4 | 5,4 | 5,4 |
| JS/TS `codeql` | 8,4 | 8,5 | 7,8 | 7,6 |
| JS/TS `codeql-sql-injection` | — | 5,1 | — | 5,2 |
| Mọi bước của lượt quét | 76,9 | 88,3 | 47,3 | 57,9 |

- Hai lượt CWE-89 thêm khoảng 11 giây cho một lượt quét (+15% và +22% trên hai nguồn nhỏ này). Các
  bước của hai nhóm cũ không đổi quá sai số giữa các lần đo. Trên Juice Shop, kho lớn nhất đã quét:
  78,0 giây với `v0.1` và 87,6 giây với `v0.2`; lượt CWE-89 của JavaScript/TypeScript mất 9,8 giây
  trên database tạo trong 17,7 giây.
- **Lần đầu sau khi dựng lại image** bộ đệm biên dịch truy vấn của CodeQL trống: lượt `v0.2` đầu
  tiên mất 297 giây cho cùng nguồn, trong đó `codeql-sql-injection` là 21,8 giây (Python) và 53,5
  giây (JS/TS). Chi phí này có ở mọi profile, không riêng CWE-89.
- **Có cần chỉnh giới hạn chạy: có, vì phép tính trường hợp xấu nhất, không vì số đo.** Giới hạn mềm
  của task phải lớn hơn tổng timeout của mọi bước (`task.worst_case_seconds`): `multi-cwe-v0.1` cần
  8.760 giây, `multi-cwe-v0.2` cần 9.960 giây (thêm hai lượt 600 giây), vượt giới hạn mềm cũ 9.000
  giây. Đã chỉnh: giới hạn mềm 10.200 giây, giới hạn cứng 11.700 giây, visibility timeout của broker
  từ 3 lên 4 giờ (14.400 giây). Kiểm thử `test_task_time_limits_…` chạy cho cả sáu profile. Timeout
  600 giây của lượt CWE-89 bằng timeout của các bước khác của nhóm lệnh; số đo lớn nhất gặp là 53,5
  giây.

### 20.7 Quyết định kỹ thuật cần chủ đề án biết

- **Mức `U` cho mọi đơn vị CWE-89.** Nhóm chưa có chính sách xếp hạng nào được đo, nên mức `U` ở
  đây nghĩa là "chưa xếp hạng". Hệ quả: trong hàng đợi, cảnh báo CWE-89 đứng sau P1 và P2 của hai
  nhóm kia. Mức này được ghim trong manifest của `sql-injection-v0.1`; đổi nó là một phiên bản
  profile mới.
- **Visibility timeout của broker tăng lên 4 giờ** cho mọi lượt quét: một task bị mất worker sẽ được
  giao lại muộn hơn một giờ so với trước.
- **Phiên bản cách ghép giữ là `family-composition-v0.1`.** Đổi hằng số này sẽ làm đổi phiên bản ghi
  trong lượt quét và mã của đơn vị giữ ở `multi-cwe-v0.1`.
- **`sql-injection-v0.1` không chọn được như một profile riêng**: nó cần database do thành viên khác
  tạo.

### 20.8 Chưa kiểm chứng

- **CI trên GitHub chưa chạy**, và chưa có job CI nào quét profile ghép bằng công cụ thật. Đây là
  tiêu chí 9 của mục 19.5; chủ đề án đã tách nó khỏi P2a thành một đầu việc CI/CD riêng (2026-11-16),
  nên nó không còn là điều kiện của P2a nhưng vẫn là việc chưa làm.
- **Cảnh báo CWE-89 trên mã thật có 13**, trên bốn kho (`pygoat` 1, `vulpy` 3, `NodeGoat` 2,
  Juice Shop 7); ba trong tám nguồn không có cảnh báo CWE-89 nào. Kho lớn nhất đã quét là Juice Shop
  (tạo database JavaScript/TypeScript khoảng 20 giây); **chưa có số đo trên kho lớn hơn thế**.
  BenchmarkPython có 16 ca kiểm thử thuộc loại `sqli` theo cột danh mục của
  file kết quả mong đợi của nó, nhưng truy vấn chuẩn không báo ca nào, cả trong ứng dụng lẫn khi chạy
  riêng; không nhãn nào được dùng để đánh giá ở P2a. *Nguyên nhân được tìm ở P2b: mục 20.11.*
- **Cảnh báo của rule không được ghim** chỉ có kiểm thử với công cụ giả lập (mục 20.4).
- Hai kiểm thử trình duyệt trên stack thật không nằm trong bộ chạy mặc định (bị bỏ qua khi không có
  `FULL_STACK_URL`); chúng được chạy tay như ở mục 20.5.
- Nhánh `feat/multi-cwe-p2a` chưa push lúc ghi; đã push tới `402566f` sau đó (mục 22.7).

### 20.9 Kết luận

**P2a hoàn tất.** Có kết quả đối chứng thực tế (mục 20.2–20.4) và kiểm thử hồi quy đạt (mục 20.5).
Chín tiêu chí của mục 19.5 thuộc P2a đều có bằng chứng. Tiêu chí 9 (CI xanh và một job quét profile
ghép bằng công cụ thật) được chủ đề án tách thành đầu việc CI/CD riêng ngày 2026-11-16 và **chưa
được làm**. Các giới hạn ở mục 20.8 đi kèm kết luận này.

Bước tiếp theo theo mục 19.4 là P2b (lượt `semgrep-sql-injection`, `bandit-sql-injection`, bộ định vị
sink SQL); điều kiện gạn cho CWE-89 vẫn nằm ngoài P2.

### 20.10 Bổ sung nghiệm thu: dữ liệu đã lưu đọc bằng API của P1 và của P2a (2026-11-16)

Bổ sung cho tiêu chí 8 của mục 19.5 ("dữ liệu cũ đọc như trước"), làm ở bước 1 của P2b.

- **Cách làm.** Database `triage` được sao bằng `pg_dump` thành `p2b_readonly`, đặt
  `default_transaction_read_only = on`, đọc bằng một vai trò chỉ có quyền `SELECT`. Mã `backend/` ở
  `ffc218b` (P1) và ở `aea3dc2` (P2a) được lấy bằng `git archive`, mỗi bản chạy trong image kiểm thử
  và chỉ gọi `GET` qua `TestClient`: lượt quét, mọi trang đơn vị, chi tiết từng đơn vị, báo cáo và
  SARIF. Lệnh: `artifacts/multi-cwe-p2b/api-compare/dump_api.py`, so sánh bằng `compare_api.py` và
  `compare_v02.py`; đầu ra `comparison.txt`, `comparison-v02.txt` cùng thư mục.
- **Kết quả.** 444 lượt quét đã lưu. 426 lượt cho phản hồi giống hệt ở cả hai bản mã: mọi lượt của
  `command-injection-v0.1` (7), `-v0.2` (169), `-v0.3` (203), `path-traversal-v0.2` (20) và
  `multi-cwe-v0.1` (27). 18 lượt khác nhau, **đều là `multi-cwe-v0.2`**, tức dữ liệu do chính P2a
  tạo, mà mã P1 chưa biết nhóm `sql-injection`:
  - 6 lượt có nhóm `sql-injection` nhưng 0 đơn vị CWE-89 (không có cảnh báo CWE-89): mã P1 đọc
    được, mọi phản hồi 200, chỉ khác ở danh sách nhóm (2 nhóm thay vì 3);
  - 12 lượt có đơn vị CWE-89: mã P1 trả 500 cho trang đơn vị và báo cáo (kiểu tên nhóm của P1 chưa
    có `sql-injection`); SARIF vẫn trả 200, nhưng kết quả SQL mang `cwe: null` và
    `evidenceState: not_refuted`, còn mã P2a ghi `CWE-89` và `insufficient`.
- **Chênh lệch ngoài nhóm `sql-injection`: 0.** Ở 12 lượt mà trang đơn vị của P1 lỗi, chi tiết đơn
  vị của hai nhóm kia không so được qua API của P1; phần đó **chưa xác minh**.
- **Kết luận.** Dữ liệu ghi trước P2a đọc giống hệt bằng mã P2a. Mã P1 không đọc trọn được dữ liệu có
  nhóm CWE-89; đây là chiều không tương thích ngược về sau (mã cũ, dữ liệu mới), không phải hồi quy.

### 20.11 Vì sao CodeQL không báo ca `sqli` nào của BenchmarkPython (2026-11-16)

Bước 2 của P2b, làm **trước** khi Semgrep hay Bandit chạy với luật CWE-89. Đầu ra:
`artifacts/multi-cwe-p2b/codeql-baseline/` (`summary.txt`, truy vấn chẩn đoán `Diag*.ql`, lượt hợp lệ
ở `out3/`).

| Kiểm tra | Kết quả |
|---|---|
| Ca theo nhãn chuẩn (`expectedresults-0.1.csv`, loại `sqli`) | 16 ca: 5 đúng, 11 sai |
| File đưa vào database | 1.236 file Python; đủ 16 file `testcode/` của các ca và `helpers/db_sqlite.py` |
| Nhật ký trích xuất | Một thông báo duy nhất: "Could not guess Python version, will use default: Python 3" |
| Trạng thái truy vấn `py/sql-injection` | `executionSuccessful: true`; thông báo 2.487 mức `none`, 9 mức `note`; 0 kết quả |
| Nguồn (dữ liệu request) | Được nhận ở cả 16 file |
| Sink (lời gọi thực thi SQL) | 16 lời gọi `cur.execute(...)` trong 16 file **không** được nhận là `SqlExecution`; cả database chỉ có 1 sink, ở `helpers/db_sqlite.py` |
| Biến thể một biến (bản sao tạm, chỉ đổi kết nối thành `sqlite3.connect(":memory:")`) | Cả 16 lời gọi thành sink; truy vấn báo 2 ca, `00454` và `00455`, đều đúng |

**Kết luận có căn cứ:** CodeQL báo 0 vì kết nối đến từ hàm của chính benchmark,
`helpers.db_sqlite.get_connection()`, mà mô hình PEP 249 của CodeQL không nhận ra, nên `cursor()` và
`execute()` trên kết nối đó không phải sink SQL. Biến thể chỉ đổi đúng điểm đó và làm sink xuất hiện.
Ba ca đúng còn lại vẫn không được báo trong biến thể; nguyên nhân của ba ca đó **chưa xác định** (không
được tìm hiểu thêm). Kết quả của biến thể không phải số đo của profile nào và không vào bảng ở mục
21.6.

## 21. Trạng thái P2b (2026-11-16)

P2b thêm profile `multi-cwe-v0.3`: nhóm CWE-89 chạy ba công cụ, **Semgrep** (Python và
JavaScript/TypeScript), **Bandit** (Python) và **CodeQL**, và chỉ gộp cảnh báo của chúng khi có căn
cứ chúng trỏ đến cùng một điểm thực thi truy vấn SQL. Đây là bước 6–7 của mục 19.4. CWE-89 vẫn **chỉ
được phát hiện và giữ**: không xếp hạng, không gạn. `multi-cwe-v0.2` giữ nguyên làm mốc CodeQL. Không
dữ liệu held-out hay cặp đã đóng băng nào được quét, không file bị ghim nào bị sửa, G1–G4 giữ nguyên.
CI/CD và tự động gạn CWE-89 nằm ngoài P2b.

**Trạng thái mã đã kiểm thử:** nhánh cục bộ `feat/multi-cwe-p2a` tại `aea3dc2` cộng thay đổi **chưa
commit**, chưa push (sau đó commit và push, mục 21.7 và 22.7). Cây đã kiểm thử và lệnh: mục 21.7. Hai lượt quét có nhãn chạy trên mã ứng dụng
có hash `83c58e8179b5ff7b` (giống hệt trong image worker) và profile có hash ở mục 21.1
(`artifacts/multi-cwe-p2b/labeled-run-state.txt`). Đầu ra thô: `artifacts/multi-cwe-p2b/` (không vào
Git).

### 21.1 Đã làm

| Việc | File |
|---|---|
| 37 file luật CWE-89 của `semgrep/semgrep-rules` ở `a84ff9cc`, chép nguyên văn, chọn cơ học (mục 21.6) | `rules/semgrep/sql-injection-v0.1/` (mới; `LICENSE`, `README.md`) |
| Lượt Semgrep và Bandit có tên của một thành viên: SARIF, nhật ký, luật dàn sẵn và raw ID mang tên lượt; mỗi file luật một thư mục `r<index>` | `backend/app/scanners/passes.py` (mới) |
| Bộ định vị lời gọi thực thi truy vấn SQL của Python, `sql-call-site-v1` | `backend/app/workflows/scans/sql_sites.py` (mới) |
| Gộp theo lời gọi; đơn vị theo vị trí và công cụ khi không định vị được; ID luật thượng nguồn | `backend/app/workflows/scans/detection.py` (`keep_detected_v2`, `canonical_rule_id`) |
| Manifest `detection` schema 2: công cụ, luật ghim kèm ID thượng nguồn, Bandit, `units` | `backend/app/scanners/profile.py` |
| Lớp ghép chạy lượt Semgrep/Bandit của thành viên trước lượt CodeQL; trạng thái nhóm tính trên mọi lượt | `backend/app/workflows/scans/families.py` |
| Giới hạn thời gian theo mọi lượt thành viên | `task.py`, `workers/celery_app.py` |
| Thành viên `sql-injection-v0.2` và profile ghép `multi-cwe-v0.3` | `profiles/sql-injection-v0.2/`, `profiles/multi-cwe-v0.3/` |
| Cấu hình, hợp đồng API, lựa chọn profile trên giao diện | `core/config.py`, `workflows/scans/schemas.py`, `frontend/openapi.json`, `src/types/api-schema.d.ts`, `src/features/scans/api/create-scan.ts` |
| Kiểm thử | `tests/scanners/test_member_passes.py`, `tests/workflows/scans/test_sql_sites.py`, `test_sql_multitool.py` (mới); `tests/scanners/test_detection_profile.py`; `frontend/tests/integration/scans/families.test.tsx`; `frontend/tests/e2e/multi-cwe-v03-full-stack.spec.ts` (mới) |

**Ghim.** Semgrep CE 1.178.0; Bandit 1.9.4 với `tools/bandit/bandit.ini` đã ghim (SHA-256
`1b314515…`) và đúng ba test Bandit tự gán CWE-89: `B608`, `B610`, `B611`; CodeQL 2.27.1 với cùng hai
truy vấn như `sql-injection-v0.1`. 25 file luật Python và 12 file JavaScript/TypeScript, mỗi file ghim
SHA-256, rule ID và ID thượng nguồn. Hash: `profiles/sql-injection-v0.2/profile.json`
`39498b0e9d7f5ce8f0e11b57aa3b80519dcc4454541be17b3cb169d85831487b`,
`profiles/multi-cwe-v0.3/profile.json`
`7f7b752875ffd9573ff8b7abc8e9cf45bf6bc8f031df16d593f500d176aa88d1`. `multi-cwe-v0.3` ghim hai thành
viên đầu bằng đúng hash mà `multi-cwe-v0.2` ghim, cách ghép vẫn là `family-composition-v0.1`.

Giữ nguyên: `profiles/multi-cwe-v0.1/`, `multi-cwe-v0.2/`, `sql-injection-v0.1/` và bốn profile cũ;
mọi file bị ghim bởi bản đăng ký nghiên cứu; `experiments/`, `tools/`; schema database (không
migration).

### 21.2 Quy tắc gộp và nhãn đã cài đặt

- **Python.** Cảnh báo của bất kỳ công cụ nào chỉ thành một đơn vị khi vùng mã mỗi cảnh báo báo nằm
  trọn trong **cùng một** lời gọi thực thi truy vấn mà bộ định vị tìm được: phương thức `execute`,
  `executemany`, `executescript`, `raw`, `extra`, hoặc lời gọi `RawSQL`; khi lời gọi lồng nhau, lấy
  lời gọi trong cùng. Không định vị trên dòng có ký tự ngoài ASCII (các công cụ đếm cột khác nhau ở
  đó); vùng không có cột không gộp được; vùng một dòng thiếu `endLine` kết thúc ở dòng bắt đầu (SARIF
  2.1.0, mục 3.30.6).
- **Mọi trường hợp khác** (không có lời gọi chứa trọn vùng, mơ hồ, file không phân tích được,
  JavaScript/TypeScript): mỗi vị trí được báo **của mỗi công cụ** là một đơn vị riêng. Đơn vị chỉ có
  cảnh báo CodeQL giữ cách định danh của `sql-injection-v0.1`. JavaScript/TypeScript chưa có bộ định
  vị, nên chưa có cảnh báo nào được gộp giữa công cụ ở ngôn ngữ này.
- **Luật.** Semgrep đặt tên luật theo thư mục của file luật, nên mỗi file được dàn vào thư mục
  `r<index>` của nó; ID đó được dịch về ID thượng nguồn của file đã ghim, lưu ở `rule_id` và xuất ở
  `ruleId` của SARIF. ID gốc (có thư mục tạm của lượt quét) giữ ở `raw_rule_id` và trong kết quả gốc.
- **CWE.** `reported_cwes` là nhãn của chính công cụ (hai luật Semgrep thượng nguồn ghi CWE-704 và
  CWE-915, và được giữ như vậy); `mapped_cwes` lấy từ manifest (CWE-89; `js/sql-injection` ghi CWE-89,
  CWE-90, CWE-943).
- **Quyết định.** Mọi đơn vị ở mức U, `K10_DETECTED_KEPT`, lý do giữ `no_filter_condition_for_family`,
  trạng thái bằng chứng `insufficient`. Một lượt lỗi hoặc chạy dở làm nhóm của ngôn ngữ đó ở trạng
  thái `partial`: cảnh báo của các lượt còn lại vẫn thành đơn vị, thêm `run_incomplete`, bằng chứng
  `unavailable`. Luật không được ghim làm nhóm giữ cảnh báo ở `F10_FAMILY_NOT_RANKED`.

### 21.3 Luồng tích hợp trên stack thật, nguồn không nhãn

Trên stack dựng từ cây đã kiểm thử, `multi-cwe-v0.3` quét sáu nguồn phát triển không nhãn, mỗi nguồn
một lần, rồi so theo nội dung với lượt `multi-cwe-v0.2` đã lưu ở P2a trên cùng snapshot
(`python artifacts/multi-cwe-p2b/scan.py …`, `compare_v03.py dev …`; đầu ra `dev/`,
`dev/compare-v03.txt`). Phép so: đơn vị, báo cáo theo nhóm và kết quả SARIF của CWE-78 và CWE-22
bằng nhau; tập cảnh báo CodeQL của nhóm SQL bằng nhau; mỗi kết quả nằm trong đúng một đơn vị, không
đơn vị nào lẫn nhóm, SARIF có đủ mọi kết quả, không đơn vị SQL nào bị gạn hay mang `suppressions`.

| Nguồn | Lượt `v0.3` | Trạng thái `v0.2` → `v0.3` | Cảnh báo CWE-89 CodeQL / Semgrep / Bandit | Mục rà CWE-89 `v0.2` → `v0.3` | Mục chứa cảnh báo của ≥ 2 công cụ | CWE-78, CWE-22 như `v0.2` |
|---|---|---|---|---|---|---|
| Tổng hợp ba nhóm | `1e694a8d` | completed → completed | 8 / 18 / 4 | 8 → 12 | 4 | Có (7 và 3 đơn vị) |
| `pygoat@2aa4cc1` | `710b72e4` | completed → completed | 1 / 6 / 1 | 1 → 5 | 1 | Có (4 và 3) |
| `vulpy@5249cc8` | `b013890e` | completed → completed | 3 / 12 / 6 | 3 → 6 | 6 | Có (1 và 1) |
| `DSVPWA@961f86d` | `bf684899` | completed → completed | 0 / 2 / 2 | 0 → 2 | 2 | Có (3 và 2) |
| `dvpwa@4a8f4a4` | `ef46639b` | completed → completed | 0 / 2 / 1 | 0 → 2 | 0 | Có (0 và 0) |
| `NodeGoat@c5cb68a` | `c56431b7` | completed → **partial** | 2 / 0 / — | 2 → 2 | 0 | Có (1 và 0) |

Mọi phép so đạt ở cả sáu nguồn. Hai điều cần biết khi đọc:

- **NodeGoat chuyển sang `partial`.** Lượt `semgrep-sql-injection` của JavaScript/TypeScript tự ghi
  chưa hoàn tất: SARIF của nó có một thông báo "Syntax error" ở `app/assets/vendor/jquery.min.js`.
  Lượt Semgrep bằng chứng của nhóm lệnh cũng ghi `partial` ở cả `v0.2` và `v0.3` (ở `v0.3` SARIF của
  nó có đúng thông báo đó), nhưng lượt bằng chứng không quyết định trạng thái lượt quét; lượt của
  thành viên CWE-89 thì có. Hai cảnh báo CodeQL vẫn là hai đơn vị ở
  danh sách rà, bằng chứng `unavailable`.
- **Công cụ so sánh được chỉnh hai lần trong lúc so, không sửa mã ứng dụng.** (1) Semgrep ghi thư mục
  tạm của lượt quét (`tmp.scan-<id>-<ngẫu nhiên>.`) vào raw ID của luật lệnh: khác nhau giữa hai lượt
  bất kỳ, như đã biết từ P1a; phép so bỏ tiền tố đó. (2) CodeQL ghi `relatedLocations` của một kết quả
  CWE-22 ở `vulpy` theo thứ tự khác và đánh số theo thứ tự ấy; phép so coi chúng là một tập, bỏ số.
  Vùng mã, rule và quyết định giống hệt.

Lượt đầu tiên của `multi-cwe-v0.3` (`a5fe7be1`, nguồn tổng hợp) cho thấy cảnh báo CodeQL không được
gộp vào lời gọi: CodeQL bỏ `endLine` ở vùng một dòng. Bộ định vị được sửa theo SARIF 2.1.0 và có kiểm
thử (3 kiểm thử hỏng khi bỏ bản sửa), trước mọi lượt quét có nhãn; hash profile không đổi vì profile
không ghim mã ứng dụng (lệch giao thức D2). Bảng trên là các lượt sau khi sửa.

Kiểm thêm, theo từng kết quả (`sarif_preserved.py`, đầu ra `sarif-preserved.txt`) trên sáu lượt này và
hai lượt có nhãn: tập (lượt chạy, rule, file, vùng) của SARIF xuất ra bằng đúng tập của các cảnh báo
đã lưu (tổng 413 kết quả); mỗi kết quả giữ vùng và thông điệp của kết quả gốc của công cụ và đúng CWE
công cụ báo; 70 kết quả Semgrep CWE-89 có raw ID truy được về đúng file luật đã ghim có ID thượng
nguồn bằng `ruleId` đã xuất; 0 kết quả CWE-89 mang `suppressions`. Đạt cả tám lượt.

### 21.4 Ca lỗi có kiểm soát

Trên stack thật, một worker thứ hai cùng image nghe hàng đợi `faults`, với tệp bọc `semgrep`, `bandit`
và `codeql` đứng đầu `PATH` (`artifacts/multi-cwe-p2b/fault/`). Tệp bọc gọi công cụ thật, trừ đúng một
lỗi ghi trong `fault/mode` và chỉ cho lượt của thành viên CWE-89. Nguồn: snapshot tổng hợp ba nhóm.
Mỗi lượt lỗi được so theo nội dung với một lượt sạch chạy cùng cách
(`python artifacts/multi-cwe-p2b/sql_tool_faults.py`, đầu ra `sql-tool-faults.txt`; lỗi của CodeQL:
`sql_tool_faults.py sql-codeql-faults sql-pass-fails sql-pass-exits-nonzero`, đầu ra
`sql-codeql-faults.txt`).

| Lỗi tiêm vào | Lượt quét | Lượt hỏng | Nhóm CWE-89 | Cảnh báo của các công cụ còn lại | CWE-78, CWE-22 |
|---|---|---|---|---|---|
| Không lỗi (hai lượt sạch) | `completed` | — | 30 cảnh báo, 12 đơn vị `K10_DETECTED_KEPT`, `insufficient` | — | 7 và 3 đơn vị |
| Semgrep CWE-89 thoát lỗi, không ghi SARIF | `partial` | `semgrep-sql-injection`, cả hai ngôn ngữ: `failed` | 12 cảnh báo (CodeQL 8, Bandit 4), 8 đơn vị K10, `run_incomplete`, `unavailable` | Giống lượt sạch | Giống lượt sạch |
| Semgrep CWE-89 ghi SARIF rồi thoát lỗi | `partial` | như trên | 30 cảnh báo, 12 đơn vị K10, `run_incomplete`, `unavailable` (18 cảnh báo Semgrep đã thu vẫn được giữ) | Giống lượt sạch | Giống lượt sạch |
| Bandit CWE-89 thoát lỗi, không ghi SARIF | `partial` | `bandit-sql-injection` (Python): `failed` | 26 cảnh báo; 4 đơn vị Python `run_incomplete`, `unavailable`; 8 đơn vị JS/TS `insufficient` | Giống lượt sạch | Giống lượt sạch |
| CodeQL CWE-89 thoát lỗi, không ghi SARIF | `partial` | `codeql-sql-injection`, cả hai ngôn ngữ: `failed` | 22 cảnh báo (Semgrep 18, Bandit 4), 8 đơn vị K10, `run_incomplete`, `unavailable` | Giống lượt sạch | Giống lượt sạch |
| CodeQL CWE-89 ghi SARIF rồi thoát lỗi | `partial` | như trên | 30 cảnh báo, 12 đơn vị K10, `run_incomplete`, `unavailable` | Giống lượt sạch | Giống lượt sạch |

Mọi lượt: mỗi kết quả trong đúng một đơn vị, SARIF đủ kết quả, mọi đơn vị CWE-89 ở danh sách rà, 0
gạn, 0 `suppressions`. **Khác P2a:** ở `multi-cwe-v0.2`, CodeQL là công cụ duy nhất của nhóm, nên lượt
CodeQL hỏng làm cả nhóm hỏng và cảnh báo thành đơn vị giữ `F10_FAMILY_NOT_RANKED`. Ở `v0.3`, nhóm còn
lượt chạy được nên chỉ `partial`: cảnh báo vẫn qua bộ "phát hiện và giữ" và vẫn được gộp theo lời gọi,
với `run_incomplete`. Trường hợp cả ba lượt cùng hỏng chỉ có kiểm thử với công cụ giả lập
(`test_every_pass_failing_ranks_nothing_and_holds_nothing_unreported`), chưa chạy trên stack thật.

### 21.5 Giao thức đo đã chốt trước

`artifacts/multi-cwe-p2b/PROTOCOL.md`, SHA-256
`0931ee0b1c0ca52e7098f701fe5181296897f10503915084952c1f744ed8c897`, ghi lúc 2026-11-16T07:19:11Z,
trước khi Semgrep hay Bandit chạy với luật CWE-89 trên bất kỳ nguồn có nhãn nào. File không sửa sau
đó; lệch giao thức ghi ở `PROTOCOL-DEVIATIONS.md`. Tóm tắt:

- **Luật, chọn cơ học.** Mọi file luật dưới `python/`, `javascript/`, `typescript/` của
  `semgrep/semgrep-rules@a84ff9cc` (cùng commit đã dùng cho luật lệnh), không phải file kiểm thử, có
  một luật ghi CWE-89 cho một trong ba ngôn ngữ, hoặc nằm dưới `/security/` và tên chứa `sql`. Không
  bỏ, không sửa luật nào. Bandit: mọi test Bandit tự gán CWE-89.
- **Nguồn và nhãn.** BenchmarkPython `f1291485` (archive `0defda4c…`), nhãn `expectedresults-0.1.csv`:
  16 ca `sqli`, 5 đúng, 11 sai. Juice Shop `266448ab` (snapshot `f47f3dfe…`), nhãn là chú thích
  `vuln-code-snippet vuln-line` (trừ `data/static/codefixes/`) với challenge trong
  `data/static/challenges.yml`: 2 vị trí SQL (`routes/login.ts:34`, `routes/search.ts:23`); 1 vị trí
  NoSQL (`routes/updateProductReviews.ts:18` hoặc `:20`) báo riêng; **không có nhãn âm tính**.
- **Ghép cảnh báo với nhãn.** Python: một công cụ báo một ca nếu có cảnh báo CWE-89 của nó trong file
  của ca; ca sai được báo là cảnh báo sai xác minh được; cảnh báo ở file khác là "ngoài tập có nhãn",
  không tính là sai. JavaScript/TypeScript: một vị trí được báo nếu khoảng dòng của vùng báo chứa dòng
  có nhãn; cảnh báo khác là "ngoài tập có nhãn", không phân loại đúng sai. "Bổ sung so với CodeQL": ca
  hoặc vị trí đúng mà công cụ báo còn CodeQL không. Chỉ báo số đếm.
- **Dừng.** Mỗi nguồn có nhãn được quét một lần với `multi-cwe-v0.3`, sau khi hash profile đã ghim và
  luồng tích hợp đã chạy trên nguồn không nhãn. Không chỉnh luật, cấu hình hay cách gộp sau đó.
- **Lệch giao thức.** D1: đếm sai số file luật theo ngôn ngữ trong câu mô tả (thực tế 25 Python, 12
  JavaScript/TypeScript; tổng 37 và tiêu chí không đổi). D2: sửa `endLine` ở bộ định vị dưới cùng hash
  profile, trước lượt có nhãn (mục 21.3). D3: thêm số mục rà theo từng công cụ ở lần chạy thứ hai của
  `measure.py`, cách ghép không đổi. D4: lượt Semgrep CWE-89 của Juice Shop tự ghi `partial` mà mục 1
  chưa nêu trước (mục 21.6).

**Điều đã biết trước khi đo:** kết quả CodeQL trên cả hai nguồn (P2a và mục 20.11); nội dung 5 ca
`sqli` đúng của BenchmarkPython (đọc ở mục 20.11; vì vậy không luật nào được viết hay sửa).

### 21.6 Giá trị tăng thêm trên dữ liệu phát triển có nhãn

Hai lượt quét, mỗi nguồn một lần, cùng phiên bản mã nguồn cho cả ba công cụ: BenchmarkPython
`87aa1417` (`completed`), Juice Shop `1dc10be3` (`partial`). Lệnh:
`python artifacts/multi-cwe-p2b/scan.py multi-cwe-v0.3 labeled …`, rồi
`uv run --no-project --python 3.12 --with pyyaml==6.0.3 python artifacts/multi-cwe-p2b/measure.py`;
đầu ra `labeled/`, `measure.json`, `measure.txt`. Trên cả hai lượt, CWE-78 và CWE-22 giống hệt
`multi-cwe-v0.2` và cảnh báo CodeQL CWE-89 giống hệt tập của `v0.2` (`labeled/compare-v03.txt`).

**Python — BenchmarkPython, 16 ca `sqli` (5 đúng, 11 sai)**

| | CodeQL | Semgrep | Bandit | Hợp nhất |
|---|---|---|---|---|
| Cảnh báo thô | 0 | 12 | 16 | 28 |
| Mục rà chứa cảnh báo của công cụ | 0 | 6 | 16 | 22 |
| Ca đúng được báo (trên 5) | 0 | 5 | 5 | 5 |
| Ca đúng bổ sung so với CodeQL | — | 5 | 5 | 5 |
| Cảnh báo sai xác minh được (ca sai được báo, trên 11) | 0 | 0 | 11 | 11 |
| Cảnh báo ngoài tập có nhãn | 0 | 0 | 0 | 0 |
| Thời gian lượt (giây) | 18,2 (bộ đệm trống, xem mục 21.8) | 7,4 | 1,8 | — |

**JavaScript/TypeScript — Juice Shop, 2 vị trí SQL có nhãn, không nhãn âm tính**

| | CodeQL | Semgrep | Hợp nhất |
|---|---|---|---|
| Cảnh báo thô | 7 | 18 | 25 |
| Mục rà chứa cảnh báo của công cụ | 7 | 18 | 25 |
| Vị trí SQL được báo (trên 2) | 2 | 2 | 2 |
| Vị trí bổ sung so với CodeQL | — | 0 | 0 |
| Vị trí NoSQL được báo (báo riêng, trên 1) | 1 | 0 | 1 |
| Cảnh báo trúng một vị trí có nhãn | 3 | 6 | 9 |
| Cảnh báo ngoài tập có nhãn (không phân loại đúng sai) | 4 | 12 | 16 |
| Thời gian lượt (giây) | 9,3 | 4,9 | — |

Bandit không quét JavaScript/TypeScript. Lượt CodeQL và lượt Semgrep CWE-89 của JavaScript/TypeScript
đều tự ghi `partial`. Với Semgrep, SARIF đã lưu có 15 thông báo "Syntax error", tất cả ở
`data/static/codefixes/*.ts`, thư mục đã loại khỏi nhãn (D4); vì vậy số của ngôn ngữ này là cận dưới.

**Đọc bảng (quan sát sau khi đo, không phải chỉ số của giao thức):**

- **Mốc CodeQL bằng 0 trên Python có nguyên nhân đã biết** (mục 20.11): kết nối qua hàm của chính
  benchmark. "Bổ sung so với CodeQL" ở Python vì vậy đo so với một mốc không thấy sink nào, không so
  với CodeQL nói chung.
- **5 ca đúng Semgrep báo đúng là 5 ca Bandit báo.** Thêm công cụ thứ hai không thêm ca đúng nào so với
  một trong hai công cụ.
- **Không mục nào trên BenchmarkPython chứa cảnh báo của hai công cụ.** Bandit `B608` báo dòng dựng
  chuỗi truy vấn (`sql = f'…'`), nằm ngoài lời gọi `cur.execute(sql)` mà Semgrep báo, nên theo quy tắc
  ở mục 21.2 chúng là các mục riêng. Mức giảm từ 28 cảnh báo xuống 22 mục là do hai luật Semgrep cùng
  báo một lời gọi (5 mục) và hai luật Semgrep cùng báo một vùng (1 mục), không phải do gộp giữa công
  cụ.
- **11 cảnh báo sai của Bandit** là mọi ca sai của tập: Bandit báo cả chuỗi f-string không chèn giá
  trị nào (`… where password = ?`, truy vấn có tham số).
- **Juice Shop:** 6 cảnh báo Semgrep trúng hai vị trí CodeQL đã báo (ba luật, mỗi luật hai vị trí) và
  thành 6 mục riêng, vì JavaScript/TypeScript chưa có bộ định vị. 12 cảnh báo Semgrep còn lại nằm
  ngoài tập có nhãn và chưa được phân loại.
- Nhãn CWE gốc được giữ: kết quả của hai luật Semgrep thượng nguồn ghi CWE-704 và CWE-915 xuất ở
  `reportedCwes` đúng như vậy, `mappedCwes` là CWE-89.

### 21.7 Kiểm thử hồi quy

Một lệnh trên trạng thái mã cuối: `bash artifacts/multi-cwe-p2b/final/run_all.sh` (đầu ra `run.txt` và
các file cùng thư mục). **Trạng thái đã kiểm thử:** `aea3dc2` cộng thay đổi chưa commit; cây
`backend/`, `frontend/`, `profiles/`, `rules/` có mã Git `55c68496b7d828eb19f2125ec6ecfbd85bed7711`
(`final/tested-state.txt`; tính ngay sau lượt chạy vì đường dẫn chỉ mục tạm trong script hỏng trên
Windows; không file nào trong bốn thư mục đổi sau khi lượt chạy bắt đầu). Mã ứng dụng trong image
worker có hash `83c58e8179b5ff7b`, giống cây làm việc và giống lượt quét có nhãn. Bốn thư mục này
sau đó được commit nguyên vẹn thành `557735e` (bộ luật) và `64b6d78` (mã, profile, giao diện):
`git diff --quiet 55c6849 64b6d78 -- backend frontend profiles rules` không báo khác biệt.

| # | Lệnh | Đạt | Bỏ qua |
|---|---|---|---|
| 1 | `uv run pytest -q -rs --cov` (SQLite, công cụ giả lập) | 692 | 2 (`test_process.py:65`, `:157`, nhóm tiến trình POSIX trên Windows) |
| 2 | `docker compose --profile test run --build --rm test` (PostgreSQL, công cụ giả lập) | 694, độ phủ 95,64% | 0 |
| 3 | `ruff check`, `ruff format --check`, `mypy`, `pip-audit` (image kiểm thử) | sạch; không lỗ hổng đã biết | — |
| 4 | `python -m unittest discover -s experiments/tests` (Python 3.12) | 153 | 0 |
| 5 | `npm run check`, `npm run build`, `npm run test:e2e` (API giả lập) | Vitest 81; build; Playwright 2 | 3 (ba kiểm thử stack thật, chạy riêng ở dòng 7 và 9) |
| 6 | `scripts.export_openapi` so với `frontend/openapi.json`; `scripts.check_worker` | giống hệt; worker nhận cả bảy profile | — |
| 7 | `FULL_STACK_URL=… npx playwright test multi-cwe-full-stack.spec` (công cụ thật, `multi-cwe-v0.1`, không có lượt CWE-89) | 1: 239 kết quả, 149 đơn vị, 64 gạn, như trước | 0 |
| 8 | `legacy_regression.py` (công cụ thật, bốn profile cũ so với lượt quét lưu ngày 14/11) | 4/5 giống hệt; ca `command-injection-v0.1` khác đúng như mục 18.3 và 20.5 | — |
| 9 | `FULL_STACK_URL=… npx playwright test multi-cwe-v02-full-stack` và `multi-cwe-v03-full-stack` (công cụ thật, PyGoat, không nhãn) | 2: lượt `v0.3` `239e954d…`: 22 kết quả, 5 mục CWE-89, 1 mục chứa cảnh báo của hai công cụ, SARIF có 8 kết quả CWE-89 | 0 |
| 10 | Golden, thực nghiệm, công cụ, pack và profile cũ; hash hai profile mới | 0 file đổi; hash bằng đúng hash lúc chạy lượt có nhãn | — |

Dòng 7 và 8 quét lại BenchmarkPython bằng `multi-cwe-v0.1` và `command-injection-v0.2`, như mọi lần
hồi quy trước; hai profile này không có lượt Semgrep hay Bandit CWE-89, nên không phải lần đo thứ hai
của giao thức. Dòng 9 là kiểm thử mới `frontend/tests/e2e/multi-cwe-v03-full-stack.spec.ts`: chọn
`multi-cwe-v0.3` trên biểu mẫu, quét `pygoat@2aa4cc1` bằng công cụ thật, kiểm ba lượt CWE-89 có tên,
lọc theo CWE-89, mở mục chứa cảnh báo của hai công cụ, tải báo cáo JSON và SARIF. Đầu ra:
`artifacts/multi-cwe-p2b/final/e2e-v03/`.

Trong dòng 1 và 2:

- 15 golden của bốn profile cũ và 16 golden của `multi-cwe-v0.1` và `v0.2` không đổi một byte.
- Kiểm thử mới: `tests/scanners/test_member_passes.py` và `tests/workflows/scans/test_sql_sites.py`
  (13 cùng nhau, gồm vùng thiếu `endLine`), `test_sql_multitool.py` (13); thêm ca cho manifest
  schema 2 và profile `multi-cwe-v0.3` trong `tests/scanners/test_detection_profile.py`.

### 21.8 Thời gian quét và giới hạn chạy

Giây của từng lượt CWE-89 (mỗi ô một lần đo, lượt quét có nhãn ở mục 21.6):

| Lượt | BenchmarkPython | Juice Shop |
|---|---|---|
| Python `semgrep-sql-injection` | 7,4 | 2,5 |
| Python `bandit-sql-injection` | 1,8 | 0,2 |
| Python `codeql-sql-injection` | 18,2 (bộ đệm trống) | 4,3 |
| JS/TS `semgrep-sql-injection` | 2,6 | 4,9 |
| JS/TS `codeql-sql-injection` | 49,6 (bộ đệm trống) | 9,3 |
| Cả lượt quét, `v0.2` → `v0.3` | 288,4 → 296,1 | 82,0 → 88,1 |

- **Cột BenchmarkPython đo với bộ đệm biên dịch truy vấn của CodeQL còn trống:** đó là lượt quét
  đầu tiên sau lần dựng lại image cuối, nên hai lượt `codeql-sql-injection` gồm cả thời gian biên
  dịch (P2a đo 6,4 và 5,1 giây khi bộ đệm đã đầy, mục 20.6). Không quét lại để lấy số đo khác, vì mỗi
  nguồn có nhãn chỉ được quét một lần. Số khi bộ đệm đã đầy: cột Juice Shop và các nguồn không nhãn.
- Semgrep CWE-89 tốn 1,6–7,4 giây mỗi ngôn ngữ, Bandit dưới 2 giây. Trên năm nguồn không nhãn có mã
  thật, cả lượt quét dài hơn `v0.2` từ 3 đến 8 giây; với nguồn tổng hợp, lượt `v0.3` ngắn hơn (247 so
  với 281 giây). Trạng thái bộ đệm không được kiểm soát cho tổng thời gian của cả lượt quét, nên các
  tổng này chỉ để tham khảo.
- **Giới hạn chạy phải tăng, vì phép tính trường hợp xấu nhất.** `task.worst_case_seconds` nay cộng
  mọi lượt của thành viên: `multi-cwe-v0.3` cần 11.760 giây (thêm ba lượt 600 giây so với `v0.2`).
  Đã chỉnh: giới hạn mềm 12.000 giây (trước 10.200), giới hạn cứng 13.500 giây (trước 11.700);
  visibility timeout của broker giữ 4 giờ (14.400 giây), vẫn lớn hơn giới hạn cứng. Kiểm thử giới
  hạn thời gian chạy cho cả bảy profile.

### 21.9 Quyết định kỹ thuật cần chủ đề án biết

- **Lượt quét "chạy dở" nhiều hơn.** Lượt Semgrep CWE-89 tự ghi chưa hoàn tất khi gặp một file không
  phân tích được, kể cả file thư viện nén như `jquery.min.js`; lượt đó quyết định trạng thái lượt
  quét. NodeGoat: `completed` ở `v0.2`, `partial` ở `v0.3`, cùng số đơn vị.
- **Lượt CWE-89 hỏng không còn làm cả nhóm hỏng.** Khác P2a: cảnh báo của các lượt còn lại vẫn qua
  bộ "phát hiện và giữ" (`K10_DETECTED_KEPT` cùng `run_incomplete`), không thành đơn vị giữ `F10`.
- **`ruleId` trong SARIF của kết quả Semgrep CWE-89 là ID thượng nguồn**, không phải ID có thư mục
  tạm như ở kết quả Semgrep của nhóm lệnh (giữ nguyên như trước để không đổi nhóm đó).
- **Không gộp cảnh báo ở dòng dựng chuỗi truy vấn với lời gọi thực thi.** Bộ định vị không theo luồng
  dữ liệu; một cảnh báo Bandit ở `sql = f'…'` và một cảnh báo Semgrep ở `cur.execute(sql)` vài dòng
  dưới là hai mục, kể cả khi chuỗi chỉ đi vào lời gọi đó. Gộp những cặp này cần căn cứ luồng dữ liệu,
  là một phiên bản bộ định vị mới.
- **Khối lượng rà tăng.** Trên dữ liệu đã đo: Python từ 0 lên 22 mục, JavaScript/TypeScript từ 7 lên
  25 (mục 21.6). Mức `U` của mọi mục CWE-89 giữ như `v0.2`.

### 21.10 Chưa kiểm chứng

- **CI trên GitHub chưa chạy** (đầu việc CI/CD riêng, như P2a). Thay đổi P2b đã commit cục bộ
  (`557735e`, `64b6d78`, `402566f`); nhánh `feat/multi-cwe-p2a` đã push tới `402566f` (mục 22.7).
- **JavaScript/TypeScript chưa có bộ định vị lời gọi SQL**, nên chưa có cảnh báo nào được gộp giữa
  công cụ ở ngôn ngữ này.
- **Độ đúng của phép gộp** chỉ có kiểm thử tự động và các nguồn không nhãn. Trên BenchmarkPython không
  mục nào chứa cảnh báo của hai công cụ, nên dữ liệu có nhãn chưa kiểm phép gộp giữa công cụ.
- Cả ba lượt CWE-89 cùng hỏng: chỉ có kiểm thử với công cụ giả lập.
- Kho lớn hơn Juice Shop: chưa quét; giới hạn thời gian dựa trên phép tính.
- Mục 20.10: với 12 lượt quét mà mã P1 không đọc được trang đơn vị, chi tiết đơn vị của nhóm CWE-78
  và CWE-22 chưa so được qua API của P1.
- Tập có nhãn rất nhỏ (5 ca đúng Python, 2 vị trí JavaScript/TypeScript, không nhãn âm tính ở Juice
  Shop) và là dữ liệu phát triển: số đếm ở mục 21.6 không phải đánh giá độc lập và không ước lượng
  được tỷ lệ.

### 21.11 Kết luận

**P2b hoàn tất về kỹ thuật.** Luồng tích hợp đã chạy thật trên sáu nguồn không nhãn, hai nguồn có nhãn
và qua giao diện (mục 21.3, 21.6, 21.7); khi một công cụ CWE-89 bất kỳ hỏng, kết quả còn lại vẫn xuất
hiện với trạng thái chạy dở (mục 21.4); CWE-78 và CWE-22 cho kết quả như `v0.2` ở mọi nguồn; SARIF giữ
mọi cảnh báo gốc; hồi quy đạt (mục 21.7); có số liệu đối chứng cho từng công cụ (mục 21.6). Thay đổi
đã commit (`557735e`, `64b6d78`) và nhánh đã push tới `402566f` (mục 22.7); CI chưa chạy.

Trên tập đã đo:

- **Semgrep bổ sung ca dương tính đã xác minh ở Python, chỉ làm tăng khối lượng rà ở
  JavaScript/TypeScript.** BenchmarkPython: 5/5 ca đúng mà mốc CodeQL không báo (mốc này bằng 0 vì
  nguyên nhân ở mục 20.11), 0 ca sai được báo, thêm 6 mục rà. Juice Shop: không thêm vị trí có nhãn
  nào (cả 2 vị trí CodeQL đã báo); thêm 18 mục rà, gồm 6 mục trùng vị trí CodeQL nhưng tách riêng vì
  chưa có bộ định vị, và 12 mục ngoài tập có nhãn chưa phân loại.
- **Bandit bổ sung 5 ca dương tính đã xác minh so với CodeQL, kèm 11 cảnh báo sai xác minh được và 16
  mục rà** (chỉ số của giao thức, BenchmarkPython): 5/5 ca đúng mà mốc CodeQL không báo; cả 11 ca sai
  của tập cũng bị báo; 16 mục rà, không mục nào gộp với Semgrep. Quan sát sau khi đo, không phải chỉ
  số của giao thức: 5 ca đó đúng là 5 ca Semgrep đã báo, nên khi đã có Semgrep, Bandit không thêm ca
  đúng nào trên tập này mà chỉ làm tăng khối lượng rà. Bandit không quét JavaScript/TypeScript.

Bước tiếp theo, nếu chủ đề án chọn: bộ định vị lời gọi SQL cho JavaScript/TypeScript; xét lại việc
đưa Bandit vào nhóm CWE-89 dựa trên số liệu trên; nhãn âm tính trên mã thật trước khi nghĩ tới bất kỳ
điều kiện gạn nào cho CWE-89.

## 22. Đánh giá cấu hình CWE-89 cho Python và JS/TS (2026-11-16)

Đợt đánh giá để đề xuất cấu hình CWE-89, dùng `multi-cwe-v0.3` (mục 21) làm mốc đối chứng. Không
sửa mã, luật, cấu hình hay phép gộp. Không quét lại BenchmarkPython hay Juice Shop. Các số đo P2b ở
mục 21 và `artifacts/multi-cwe-p2b/` giữ nguyên.

- **Commit đã đo:** `402566f4b02d888d7ae2764776f5d06fd4df07c7`.
  - Mã ứng dụng trong image worker có hash `83c58e8179b5ff7b`, giống cây làm việc và giống P2b.
  - Hash profile như mục 21.1; Semgrep 1.178.0, Bandit 1.9.4, CodeQL 2.27.1.
  - Ghi ở `artifacts/cwe89-eval/sven-run-state.txt`.
- **Đầu ra:** `artifacts/cwe89-eval/`, không vào git.
- **Trạng thái nhãn:** nhãn ở mục 22.2 là đề xuất, chưa được duyệt.

### 22.1 Nguồn dữ liệu và lệnh tái lập

| Bước | Dữ liệu | Lệnh (từ gốc repo) | Đầu ra |
|---|---|---|---|
| 1 | Lượt quét đã lưu `1dc10be3…` (Juice Shop `266448ab`), mã nguồn cục bộ `artifacts/multi-cwe-p2b/juice/src` | `docker compose exec -T api python - 194e5825-028c-48de-9b79-fa245fdb3e60 < artifacts/cwe89-eval/snapshot_hashes.py > artifacts/cwe89-eval/juice-stored/snapshot-hashes.json`; `python artifacts/cwe89-eval/compare_snapshot.py`; với mỗi tệp `K` trong `codeql.sarif`, `codeql-sql-injection.sarif`, `semgrep-sql-injection.sarif`, `codeql-create.stdout.log`: `docker compose exec -T api python - 1dc10be3-7949-43f9-96ce-70d72c2f6178 javascript/K < artifacts/cwe89-eval/scan_artifacts.py > artifacts/cwe89-eval/juice-stored/K`; `python artifacts/cwe89-eval/juice_trace.py` | `juice-stored/`, `juice-trace.json`, `juice-trace.txt` |
| 2 | Như bước 1 | `python artifacts/cwe89-eval/js_merge_estimate.py` (gọi `js_sql_sites.mjs`) | `merge-estimate.json`, `merge-estimate.txt` |
| 3 | SVEN `eth-sri/sven@e8449a0d`, `data_train_val/{train,val}/cwe-089.jsonl`; file gốc tại commit sửa từ `raw.githubusercontent.com` | với `S` là `train` và `val`: `curl -o artifacts/cwe89-eval/sven-download/S-cwe-089.jsonl https://raw.githubusercontent.com/eth-sri/sven/e8449a0d54a5ae0bbdc6bb236330b8c7ec71df57/data_train_val/S/cwe-089.jsonl` (sha256 train `b47eb0e2…`, val `5dc8065a…`, đầy đủ trong `PROTOCOL-SVEN.md`; `build_sven.py` kiểm lại); `python -I artifacts/cwe89-eval/build_sven.py`; `python artifacts/cwe89-eval/scan_corpus.py file`; `python artifacts/cwe89-eval/scan_corpus.py fragment`; `python -I artifacts/cwe89-eval/measure_sven.py file`; `python -I artifacts/cwe89-eval/measure_sven.py fragment`; `python -I artifacts/cwe89-eval/sven_posthoc.py` | `PROTOCOL-SVEN.md`, `PROTOCOL-SVEN-DEVIATIONS.md`, `sven-download/`, `sven-corpus-*/`, `sven-scan-*.json`, `sven-measure-*.{json,txt}`, `sven-posthoc-file.*` |

Bước 3 chỉ chạy lại được trên một stack mới. `scan_corpus.py` từ chối quét khi đã có
`sven-scan-*.json`, và `build_sven.py` từ chối ghi vào thư mục tập đã có.

### 22.2 Truy vết 12 cảnh báo Semgrep JS/TS ngoài tập có nhãn (Juice Shop)

**Dữ liệu dùng:**

- Lượt quét đã lưu `1dc10be3-7949-43f9-96ce-70d72c2f6178` (`multi-cwe-v0.3`, Juice Shop
  `266448ab`, snapshot `f47f3dfe…`).
- Mã nguồn cục bộ `artifacts/multi-cwe-p2b/juice/src`: giống từng byte với snapshot đã quét. Đã so
  1498/1498 tệp với bản lưu trong kho đối tượng (`juice-stored/snapshot-hashes.json`).
- SARIF thô của hai lượt CodeQL JavaScript trong cùng lượt quét, tải lại từ kho đối tượng:
  - `codeql.sarif`, lượt CWE-78: 0 kết quả;
  - `codeql-sql-injection.sarif`: 7 kết quả, là toàn bộ kết quả CodeQL JavaScript của lượt quét.

Không quét lại.

**Vị trí của 12 cảnh báo:** cả 12 nằm trong 4 tệp `data/static/codefixes/`, mỗi tệp đúng 3 cảnh báo
(3 luật) trên cùng một lời gọi `models.sequelize.query(...)`.

**Nhãn:** là **đề xuất, chờ chủ đề án duyệt từng mục**. Nhãn xét đoạn mã như đang viết; cột "Chạy
trong ứng dụng" xét riêng. Tên đầy đủ của ba luật:

- `raw-query` = `javascript.sequelize.security.audit.sequelize-raw-query.sequelize-raw-query`
- `express-seq` = `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`
- `tainted-sql` = `javascript.express.security.injection.tainted-sql-string.tainted-sql-string`

Cả ba luật đều ghi CWE-89.

| # | Mã cảnh báo (mục rà) | Tệp:dòng:cột | Quy tắc | Cảnh báo CodeQL tương ứng | Căn cứ | Nhãn đề xuất | Chạy trong ứng dụng |
|---|---|---|---|---|---|---|---|
| 1 | `semgrep-sql-injection:0:0` (`0fe54b58`) | `dbSchemaChallenge_1.ts:5:5–163` | `raw-query` | không có (E) | A, F | Có lỗi | không |
| 2 | `semgrep-sql-injection:0:1` (`840af573`) | `dbSchemaChallenge_1.ts:5:28–162` | `express-seq` | không có (E) | A, F | Có lỗi | không |
| 3 | `semgrep-sql-injection:0:2` (`ed192ef3`) | `dbSchemaChallenge_1.ts:5:74–82` | `tainted-sql` | không có (E) | A, F | Có lỗi | không |
| 4 | `semgrep-sql-injection:0:3` (`2ad3a8d9`) | `dbSchemaChallenge_3.ts:11:5–161` | `raw-query` | không có (E) | B, F | An toàn | không |
| 5 | `semgrep-sql-injection:0:4` (`efbde5e9`) | `dbSchemaChallenge_3.ts:11:28–159` | `express-seq` | không có (E) | B, F | An toàn | không |
| 6 | `semgrep-sql-injection:0:5` (`b785def2`) | `dbSchemaChallenge_3.ts:11:74–82` | `tainted-sql` | không có (E) | B, F | An toàn | không |
| 7 | `semgrep-sql-injection:0:6` (`5f21afd2`) | `unionSqlInjectionChallenge_1.ts:6:5–161` | `raw-query` | không có (E) | C, F | Có lỗi | không |
| 8 | `semgrep-sql-injection:0:7` (`8f944110`) | `unionSqlInjectionChallenge_1.ts:6:28–159` | `express-seq` | không có (E) | C, F | Có lỗi | không |
| 9 | `semgrep-sql-injection:0:8` (`d7517818`) | `unionSqlInjectionChallenge_1.ts:6:74–82` | `tainted-sql` | không có (E) | C, F | Có lỗi | không |
| 10 | `semgrep-sql-injection:0:9` (`e2dff7ff`) | `unionSqlInjectionChallenge_3.ts:10:5–161` | `raw-query` | không có (E) | D, F | An toàn | không |
| 11 | `semgrep-sql-injection:0:10` (`5dbb2fea`) | `unionSqlInjectionChallenge_3.ts:10:28–159` | `express-seq` | không có (E) | D, F | An toàn | không |
| 12 | `semgrep-sql-injection:0:11` (`e015936f`) | `unionSqlInjectionChallenge_3.ts:10:74–82` | `tainted-sql` | không có (E) | D, F | An toàn | không |

Mọi tệp đều nằm dưới `data/static/codefixes/`. Ở mỗi lời gọi:

- `raw-query` trùm cả lời gọi;
- `express-seq` trỏ vào đối số chuỗi SQL;
- `tainted-sql` trỏ vào biến `criteria` được chèn vào chuỗi.

**Căn cứ (phân tích tĩnh mã như đang viết):**

- **A, `dbSchemaChallenge_1.ts` (Có lỗi):**
  - `criteria` lấy từ `req.query.q`, chỉ bị cắt còn 200 ký tự, rồi nối thẳng vào chuỗi SQL ở dòng 5.
  - Không có `replacements` hay `bind`: giống hệt `routes/search.ts:23`, vị trí có nhãn dương tính.
  - Khớp ghi chú của chính Juice Shop (`dbSchemaChallenge.info.yml`, bản sửa 1).
- **B, `dbSchemaChallenge_3.ts` (An toàn, trái với ghi chú của Juice Shop):**
  - Dòng 7 trả 400 khi `criteria` khớp `/"|'|;|and|or|;|#/i`, nên chuỗi tới dòng 11 không chứa dấu `'`.
  - Giá trị nằm trong literal `'%…%'` của SQLite (`models/index.ts`: `dialect: 'sqlite'`). Literal
    SQLite chỉ đóng bằng dấu `'`, còn `\` không phải ký tự thoát.
  - Mảng hay object từ query string làm `criteria.match` ném `TypeError` trước khi truy vấn chạy.
  - Còn lại chỉ là chèn ký tự đại diện `%` và `_` của `LIKE`, không đổi cú pháp câu lệnh.
  - Ghi chú của Juice Shop (bản sửa 3) chỉ nói chung rằng danh sách chặn "có thể bị vượt qua", không
    nêu cách nào.
- **C, `unionSqlInjectionChallenge_1.ts` (Có lỗi):**
  - Dòng 5 gọi `criteria.replace(...)` nhưng bỏ kết quả, vì chuỗi JS bất biến; kể cả nếu gán lại,
    biểu thức không có cờ `g` chỉ xóa lần khớp đầu.
  - `criteria` tới dòng 6 không đổi và vào thẳng template SQL như `routes/search.ts:23`.
  - Khớp ghi chú của Juice Shop (bản sửa 1).
- **D, `unionSqlInjectionChallenge_3.ts` (An toàn, trái với ghi chú của Juice Shop):**
  - Điều kiện dòng 6 `!criteria.startsWith("apple") || !criteria.startsWith("orange")` đúng với mọi
    chuỗi, vì không chuỗi nào bắt đầu bằng cả hai từ. Hàm luôn trả 400 ở dòng 7–8; mảng hay object
    làm `startsWith` ném `TypeError`.
  - Lời gọi truy vấn ở dòng 10 không bao giờ chạy.
  - Ghi chú của Juice Shop (bản sửa 3: vẫn tiêm được bằng `orange')) UNION …`) mô tả ý định của bản
    sửa, không phải mã như đang viết. Vế sau của ghi chú, rằng bản sửa làm hỏng tìm kiếm, khớp với
    mã.
- **E, CodeQL:**
  - CodeQL đã trích xuất cả 4 tệp: có thông báo `js/baseline/expected-extracted-files` và không có
    `js/parse-error` nào cho chúng. Cả hai lượt CodeQL JavaScript không có kết quả nào trong 4 tệp.
  - Cùng mẫu mã ở `routes/search.ts:23` được CodeQL báo (`codeql-sql-injection:0:5`).
  - **Đã kiểm:** các tệp không có import nào, nên `models` và `Request` không được khai báo, và hàm
    `searchProducts` của chúng không được đăng ký làm route ở đâu.
  - **Chưa kiểm (suy luận):** vì vậy CodeQL không thấy nguồn từ request hay điểm thực thi của
    Sequelize. Không chạy CodeQL lại trên tệp Juice Shop để thử.
- **F, phạm vi:**
  - Đây là tệp dữ liệu của thử thách sửa mã: `routes/vulnCodeFixes.ts` đọc chúng bằng
    `fs.readFileSync` để hiển thị, và không tệp nào import chúng.
  - Cấu hình CodeQL (`paths-ignore`), ESLint và Code Climate của chính Juice Shop bỏ qua
    `data/static/codefixes`; giao thức P2b cũng loại thư mục này khỏi nhãn.
  - Vì vậy **không cảnh báo nào trong 12 trỏ tới mã chạy trong ứng dụng**: xét ở mức ứng dụng đã triển
    khai, cả 12 không khai thác được.

**Tổng hợp đề xuất:**

- Xét đoạn mã: 6 Có lỗi (A, C), 6 An toàn (B, D), 0 Chưa xác định.
- 6 mục An toàn trái với ghi chú của Juice Shop; nên duyệt kỹ hai tệp này trước.
- Ngoài 12 cảnh báo: Semgrep không báo hai bản sửa đúng `dbSchemaChallenge_2_correct.ts` và
  `unionSqlInjectionChallenge_2_correct.ts`, cả hai đều dùng `replacements`. Semgrep không phân tích
  được 12 tệp codefix của ba thử thách đăng nhập: 15 lỗi cú pháp, lệch D4 của P2b.

**Ngoài phạm vi CWE-89:**

- **Trong 12 cảnh báo Semgrep:** không cảnh báo nào ngoài phạm vi CWE-89 xét theo điểm thực thi hay
  nhãn của luật; cả 12 là câu SQL thô của Sequelize. Cả 12 nằm ngoài mã chạy của ứng dụng (F).
- **Trong 7 cảnh báo CodeQL của cùng lượt quét:** 5 cảnh báo là truy vấn NoSQL, vì `js/sql-injection`
  gộp cả NoSQL và ghi `cwe-089`, `cwe-090`, `cwe-943`. Chúng là lời gọi `findOne`/`update` trên
  `db.reviewsCollection` ở:
  - `routes/likeProductReviews.ts:25`, `:36`, `:43`, `:51`;
  - `routes/updateProductReviews.ts:18`, vị trí có nhãn NoSQL.

  Đây là CWE-943, không phải CWE-89. Hai cảnh báo còn lại nằm ở hai vị trí SQL có nhãn.

### 22.3 Lợi ích của phép gộp cảnh báo JS/TS

**Quy tắc ước lượng** là quy tắc Python của `sql-injection-v0.2` mang sang JS/TS: cảnh báo của mọi
công cụ và mọi luật chỉ thành một mục khi vùng báo nằm trọn trong cùng một lời gọi thực thi SQL.

- **Lời gọi thực thi SQL:** lời gọi trong cùng nhất có tên `query`, `execute`, `raw`, `whereRaw`,
  `fromRaw` hoặc `literal`, là các phương thức điểm thực thi mà 12 luật JS của pack có nêu.
- **Còn lại** mỗi cảnh báo là một mục.
- **Cách tính:**
  - bộ định vị thử nghiệm `artifacts/cwe89-eval/js_sql_sites.mjs`, dùng trình phân tích cú pháp
    TypeScript của `frontend/node_modules`; chỉ dùng cho phép ước lượng, không thuộc ứng dụng;
  - script `js_merge_estimate.py`, đọc lượt quét đã lưu, không quét lại.

| Nhóm | Cảnh báo | Mục hiện nay | Mục khi gộp | Giảm | Cảnh báo gốc theo nhóm |
|---|---|---|---|---|---|
| `routes/login.ts:34` (`models.sequelize.query`, có nhãn) | 4 (CodeQL + 3 luật Semgrep) | 4 | 1 | 3 | `codeql-sql-injection:0:4`, `semgrep-sql-injection:0:12`, `:0:13`, `:0:14` |
| `routes/search.ts:23` (có nhãn) | 4 (CodeQL + 3 luật Semgrep) | 4 | 1 | 3 | `codeql-sql-injection:0:5`, `semgrep-sql-injection:0:15`, `:0:16`, `:0:17` |
| 4 tệp codefix (mục 22.2) | 12 (3 luật Semgrep mỗi lời gọi) | 12 | 4 | 8 | `semgrep-sql-injection:0:0`–`:0:11`, ba cảnh báo liền nhau mỗi tệp |
| 5 cảnh báo NoSQL của CodeQL | 5 | 5 | 5 | 0 | `codeql-sql-injection:0:0`–`:0:3`, `:0:6`: không nằm trong lời gọi nào ở trên |
| **Tổng** | **25** | **25** | **11** | **14** | |

**Phân tích phần giảm:**

- 6 trong 14 là gộp giữa công cụ, ở hai vị trí có nhãn.
- 8 là gộp giữa các luật của cùng Semgrep, ở 4 tệp codefix.
- Chỉ trong mã chạy của ứng dụng (bỏ `data/static/codefixes`): 13 mục còn 7, giảm 6.
- 8 mục codefix cũng mất nếu chỉ loại thư mục đó khỏi quét, không cần bộ định vị. Juice Shop tự làm
  việc này trong cấu hình CodeQL của nó, nhưng cách này chỉ đúng riêng cho dự án này.
- Riêng Semgrep: 18 cảnh báo thành 6 mục. Ba luật Semgrep luôn cùng báo ở mỗi lời gọi
  `sequelize.query` có chuỗi SQL dựng từ dữ liệu vào, nên hai trong ba cảnh báo là thừa.

**Ánh xạ mơ hồ:**

- Mọi vùng SQL nằm trọn trong đúng một lời gọi; không vùng nào nằm trong hai lời gọi lồng nhau. Vùng
  của `raw-query` trùng đúng với cả lời gọi.
- Chạy bộ định vị trên toàn cây (673 tệp `.ts`/`.js`) cho 26 lời gọi:
  - 21 là `models.sequelize.query`: 3 ở `routes/`, 18 ở `codefixes/`;
  - 5 là `fixture.debugElement.query` trong kiểm thử Angular, không phải SQL.

  Một bộ định vị chỉ dựa vào tên sẽ coi 5 lời gọi này là điểm thực thi SQL. Hiện không có cảnh báo
  nào rơi vào chúng, nên chưa gây gộp sai.
- Trường hợp Python đã gặp, câu SQL dựng ở một câu lệnh riêng rồi mới truyền vào lời gọi như Bandit
  trên BenchmarkPython, không có ở Juice Shop. Ở dạng đó vùng báo nằm ngoài lời gọi, nên không gộp
  được.
- Cỡ mẫu nhỏ: 6 lời gọi SQL có cảnh báo, một ORM (Sequelize), một kho.

### 22.4 Bandit trên một tập Python độc lập (SVEN)

**Giao thức:**

- `artifacts/cwe89-eval/PROTOCOL-SVEN.md`, sha256
  `b57d75ba0966ea22a7697457802ff38fdf5ddc942ed335614ea675d900d2d8a4`, chốt lúc 2026-11-16T10:03:47Z.
- Giao thức được chốt trước khi dựng tập và trước khi công cụ nào chạy: lượt quét đầu tạo lúc
  10:05:05Z. Hash của bốn script cũng được ghi trong giao thức và vẫn khớp sau khi đo.
- **Một sai lệch** (`PROTOCOL-SVEN-DEVIATIONS.md`, D1): giao thức hứa số mục rà theo từng nhóm, nhưng
  script đo chỉ tính cho cả tập và vùng có nhãn. Phân bố theo nhóm bên dưới vì thế là quan sát sau
  khi đo. Không số nào của giao thức đổi.

**Dữ liệu:**

- **Nguồn:** SVEN `eth-sri/sven@e8449a0d54a5ae0bbdc6bb236330b8c7ec71df57`, 204 cặp hàm Python CWE-89
  (184 train, 20 val, không cặp trùng). Mỗi cặp là hàm trước và sau một commit sửa lỗi.
  - **Ca dương:** hàm trước khi sửa.
  - **Ca âm:** hàm sau khi sửa.
- **Độc lập:** không file nào của dự án nhắc tới SVEN, và không kho nào trong 71 kho của nó có trong
  dữ liệu dự án.
- **Biến thể "file" (chính):** quét cả file tại commit sửa.
  - 174 ca, 251 file, 56 kho.
  - 30 ca bị loại theo tiêu chí cơ học: 11 do file trả 404 (5 file khác nhau), 3 do không tìm thấy
    hàm, 16 do file không qua `ast.parse`.
  - Theo mục 4 của giao thức: 117 ca có lời gọi thực thi (`execute`…), 57 ca qua hàm bọc. 101 ca có
    import thư viện cơ sở dữ liệu trong file, 73 ca không.
- **Biến thể "fragment" (độ nhạy):** mỗi hàm đứng riêng trong một file; 204 ca (140 có lời gọi thực
  thi, 64 qua hàm bọc), 408 file.

**Lượt quét:** mỗi biến thể quét một lần bằng `multi-cwe-v0.3`, cả hai `completed`.

- File: `bed105e3-9fea-41e3-8c3c-cbca1d0e9970`, snapshot `418bfdd7…`.
- Fragment: `dde8e6d8-af99-48cf-bf53-5df452c9bc47`, snapshot `deb81bfc…`.
- "CodeQL + Semgrep" được suy ra từ chính lượt quét bằng cách bỏ cảnh báo Bandit.

**Biến thể "file", 174 ca dương và 174 ca âm:**

| | CodeQL | Semgrep | Bandit | CodeQL + Semgrep | CodeQL + Semgrep + Bandit |
|---|---|---|---|---|---|
| Ca dương bị báo | 7 | 126 | 167 | 126 | 171 |
| Ca âm bị báo | 0 | 4 | 23 | 4 | 24 |
| Cảnh báo thô | 7 | 648 | 613 | 655 | 1268 |
| Cảnh báo ngoài vùng có nhãn | 0 | 304 | 372 | 304 | 676 |
| Mục rà trong vùng có nhãn | — | — | — | 193 | 343 |
| Mục rà cả tập | — | — | — | 403 | 833 |
| Thời gian lượt (giây) | 6,5 | 6,6 | 1,9 | — | — |

**Giá trị tăng thêm của Bandit (CodeQL + Semgrep + Bandit so với CodeQL + Semgrep):**

| Nhóm | Ca | Ca dương riêng Bandit bổ sung | Ca âm riêng Bandit báo thêm | Ca dương cả ba công cụ đều bỏ sót |
|---|---|---|---|---|
| **Biến thể "file", tất cả** | 174 | **45** | **20** | 3 |
| Có lời gọi thực thi trong hàm | 117 | 0 | 0 | 1 |
| Qua hàm bọc | 57 | 45 | 20 | 2 |
| Có import thư viện cơ sở dữ liệu | 101 | 10 | 5 | 2 |
| Không có import | 73 | 35 | 15 | 1 |
| **Biến thể "fragment", tất cả** | 204 | **50** | **23** | 3 |
| Có lời gọi thực thi trong hàm | 140 | 0 | 0 | 1 |
| Qua hàm bọc | 64 | 50 | 23 | 2 |

**Mục rà tăng sau gộp:**

- Biến thể "file":
  - +150 trong vùng có nhãn (193 lên 343);
  - +430 trên cả tập (403 lên 833). Con số cả tập bị phóng đại, vì mã ngoài hàm có nhãn lặp lại ở
    mỗi bản sao của một file.
- Biến thể "fragment": +172 (226 lên 398).
- 185 mục ở biến thể "file" chứa cảnh báo của hơn một công cụ, nằm trong cùng một lời gọi.

Biến thể "fragment" cho cùng kết luận. Ở đó CodeQL không báo ca nào, vì không có ngữ cảnh.

**Quan sát sau khi đo** (`sven_posthoc.py`; không phải chỉ số của giao thức):

- **Phân bố 150 mục Bandit thêm trong vùng có nhãn:**
  - 61 mục nằm trong hàm có lời gọi thực thi (59 phía dương, 2 phía âm), nơi Bandit không thêm ca
    nào. Bandit báo ở dòng dựng chuỗi, Semgrep báo ở lời gọi `execute`, nên hai bên không gộp được,
    như trên BenchmarkPython.
  - 89 mục nằm trong hàm qua hàm bọc (67 dương, 22 âm).
- **20 ca âm riêng Bandit báo** (đọc trọn câu lệnh bị báo, chưa xác minh đầy đủ):
  - 18 ca chỉ dựng câu SQL từ hằng:
    - 6 ca chèn tên bảng lấy từ hằng hay cấu hình (`.format(TABLE_NAME)`, `CFG("…_table_name")`,
      `% (self.table)`);
    - 12 ca dùng f-string hay nối chuỗi không chứa dữ liệu vào, còn giá trị đi qua tham số `%s`/`?`.
  - 2 ca cần duyệt: `RandyRomero/photoGPSbot clean_cache` (`f'WHERE chat_id in {user_ids} '`) và
    `DKelle/Smash_stats h2h` (`'{player1}'` được thay bởi hàm `db.exec(sql, args)` của dự án).
- **45 ca dương riêng Bandit bổ sung:** đều là luật B608. Chúng đến từ 12 kho, trong đó 4 kho góp 31
  ca: `DKelle/Smash_stats` 10, `ShaominLi/Twitter_project` 9, `RandyRomero/photoGPSbot` 6,
  `sgosal2/tiger-boards-backend` 6. Cỡ mẫu thực vì thế gần với 12 dự án hơn là 45 ca độc lập.
- **Bandit báo cả hai phía ở 18/45 ca:** với 18 ca dương riêng Bandit bổ sung, Bandit vẫn báo hàm sau
  khi sửa. Đó chính là 18 trong 20 ca âm riêng Bandit báo thêm. Chỉ ở 27 ca, Bandit báo riêng bản có
  lỗi.
- **BenchmarkPython khớp với nhóm "có lời gọi thực thi" của SVEN:** cả 16 ca `sqli` đều có `.execute(`,
  và trên tập đó Bandit cũng không thêm ca đúng nào so với Semgrep (mục 21.6).

**Áp quy tắc chốt trước** (mục 8 của giao thức, biến thể "file"): Bandit bổ sung 45 ca dương, không
ít hơn 20 ca âm nó báo thêm. Kết quả: **đề xuất dùng thường xuyên**.

### 22.5 Đề xuất cấu hình

Đề xuất để chủ đề án quyết định bước triển khai tiếp theo. Mọi thay đổi đều cần một phiên bản
profile mới (ví dụ `sql-injection-v0.3` trong `multi-cwe-v0.4`) và một lượt đo mới, vì `v0.2`/`v0.3`
đã khóa.

**Python:**

| Công cụ | Đề xuất | Căn cứ |
|---|---|---|
| CodeQL | Dùng thường xuyên (mốc) | 0 ca âm bị báo trên cả hai tập. Độ phủ thấp khi thiếu ngữ cảnh (0/5 BenchmarkPython, 7/174 SVEN), nhưng là công cụ duy nhất theo luồng dữ liệu giữa các file. Chạy trên cơ sở dữ liệu dùng chung, khoảng 5–7 giây |
| Semgrep | Dùng thường xuyên | BenchmarkPython: 5/5 ca đúng, 0 ca sai. SVEN: 126/174 ca dương, 4/174 ca âm; 116/117 ca có lời gọi thực thi |
| Bandit | Dùng thường xuyên, theo quy tắc chốt trước, **kèm điều kiện về khối lượng rà** | SVEN: +45 ca dương, +20 ca âm, +150 mục rà trong vùng có nhãn (tăng 78%). Toàn bộ phần bổ sung nằm ở mã qua hàm bọc. Ở mã có lời gọi thực thi, Bandit chỉ thêm mục trùng (SVEN: 0 ca thêm; BenchmarkPython: 0 ca thêm, 11 ca sai). Quan sát sau khi đo: ở 18/45 ca thêm, Bandit cũng báo cả bản đã sửa |

**Điều kiện cho Bandit:**

- Nếu khối lượng rà là ràng buộc chính, có thể để Bandit tùy chọn cho mã gọi thẳng `execute`.
- Cách giữ được lợi ích mà giảm mục trùng là nối cảnh báo B608 với lời gọi dùng chuỗi đó trong cùng
  hàm, ví dụ một luật đơn vị `sql-call-site-v2`. Trên SVEN, cách này gộp được tối đa 61 trong 150 mục
  thêm. Đây là ước lượng trên, chưa đo; cần phiên bản mới và lượt đo mới.

**JavaScript/TypeScript:**

| Công cụ | Đề xuất | Căn cứ |
|---|---|---|
| CodeQL | Dùng thường xuyên (mốc) | Báo 2/2 vị trí SQL có nhãn ở Juice Shop. 5 cảnh báo còn lại là NoSQL (CWE-943, mục 22.2) |
| Semgrep | Để tùy chọn | Không thêm vị trí có nhãn nào. 6/18 cảnh báo trùng CodeQL. 12/18 nằm ở mã không chạy trong ứng dụng; trong đó 6 có lỗi nếu xét đoạn mã (đề xuất, mục 22.2). Mới có một kho, 2 vị trí; cần một tập JS/TS có nhãn thứ hai trước khi dùng thường xuyên |
| Bandit | Không áp dụng | Chỉ quét Python |

**Phép gộp JS/TS: nên làm, ở quy mô nhỏ, đi cùng Semgrep JS/TS.**

- **Lợi ích:** trên Juice Shop, 25 mục còn 11, giảm 14; riêng ở mã chạy trong ứng dụng, 13 mục còn
  7.
- **Chi phí:** bộ định vị thử nghiệm khoảng 80 dòng, dùng trình phân tích cú pháp TypeScript.
- **Mơ hồ:** 5 lời gọi `debugElement.query` không phải SQL; hiện chưa gây gộp sai.
- **Phụ thuộc vào Semgrep JS/TS:** chỉ có ích khi Semgrep JS/TS chạy. Lượt CodeQL đứng một mình chỉ
  có một cảnh báo mỗi vị trí, nên nếu bỏ Semgrep JS/TS thì phép gộp gần như không còn tác dụng.

### 22.6 Giới hạn và phần chưa kiểm chứng

- **Nhãn mục 22.2 chưa được duyệt.** 6 mục trái với ghi chú của Juice Shop (B, D) cần xem trước.
- **Nhãn SVEN chưa được dự án kiểm lại.** "Sau khi sửa" không chứng minh cả hàm an toàn; 2 trong 20
  ca âm riêng Bandit báo cần duyệt.
- **Mỗi file SVEN được quét riêng, không có phần còn lại của kho** (mục 9 của giao thức). Với một
  lượt quét cả kho, CodeQL có thể thấy hàm bọc và nguồn mà ở đây nó không thấy, nên con số "Bandit
  bổ sung" có thể cao hơn thực tế.
- **JS/TS:**
  - một kho, một ORM, 6 lời gọi SQL có cảnh báo;
  - bộ định vị thử nghiệm không thuộc ứng dụng và không có kiểm thử;
  - chưa có tập JS/TS có nhãn thứ hai.
- **CI chưa chạy** (mục 22.7).

### 22.7 Trạng thái Git

**Kiểm ngày 2026-11-16 từ ref cục bộ, không liên lạc máy chủ:**

- `git status -sb` cho `## feat/multi-cwe-p2a...origin/feat/multi-cwe-p2a`: không lệch.
- `refs/remotes/origin/feat/multi-cwe-p2a` là `402566f`, trùng `HEAD`.
- Nhánh vì thế đã được push tới `402566f`, gồm cả ba commit P2b. Ref theo dõi chỉ đổi khi push hay
  fetch từ máy này, nên đây là trạng thái ở lần liên lạc cuối với remote.

**CI:** `ci.yml` chỉ chạy khi push lên `main` hoặc khi có pull request. Từ máy này không kiểm được có
pull request hay không, nên trạng thái CI chưa xác minh.

**Lúc ghi mục này:** mục 22 và các dòng trạng thái sửa cùng lúc chưa được commit.

## 23. Phép gộp Bandit với lời gọi SQL và giá trị Bandit sau gộp (2026-11-16)

Profile ghép thử nghiệm `multi-cwe-v0.4`, thành viên CWE-89 `sql-injection-v0.3`.

- **Cấu hình thử nghiệm:** giữ đủ CodeQL, Semgrep và Bandit, cùng luật và cấu hình như `v0.3`.
- **Khác biệt duy nhất:** phép gộp đơn vị Python `sql-call-site-v2`. Cảnh báo Bandit B608 ở câu
  gán dựng chuỗi SQL được nối với cảnh báo CodeQL hoặc Semgrep tại lời gọi thực thi chuỗi đó.
- **Không đổi:**
  - các profile đã khóa;
  - `multi-cwe-v0.3`, `sql-injection-v0.2` và luật Semgrep;
  - số đo của mục 21 và 22.
- **Không quét lại nguồn có nhãn nào:** phép gộp cũ và mới được chạy lại trên SARIF đã lưu của lượt
  quét SVEN ở mục 22.4.
- **SonarQube:** chạy độc lập, bên ngoài profile, worker và API.

### 23.1 Phép gộp mới (`sql-call-site-v2`)

Đặc tả: [profiles/sql-injection-v0.3/DETECTION.md](../../profiles/sql-injection-v0.3/DETECTION.md),
mục 2. Mã: `sql_sites.locate_sql_strings`, `string_link` và `detection.link_decisions`.

**Điều kiện nối.** Một cảnh báo B608 nằm ngoài mọi lời gọi được nối vào đơn vị của đúng một lời gọi
thực thi khi đủ cả sáu điều:

1. Vùng báo trùng một chuỗi literal (hay phần literal của f-string) mà vế phải của
   `tên = <biểu thức>` được dựng từ đó. "Dựng từ" chỉ gồm `+`, `%` và `.format()`.
2. `tên` chỉ được gán bằng câu đó trong phạm vi.
3. `tên` không xuất hiện ở phạm vi lồng nhau.
4. `tên` được đọc đúng một lần: đối số đầu của một lời gọi thực thi sau câu gán.
5. Các dòng của câu gán và của lời gọi đều là ASCII.
6. Lời gọi đó đã có cảnh báo CodeQL hoặc Semgrep.

Phạm vi là module, class hoặc hàm, nên phép nối cũng áp cho câu gán ở cấp module hay class, không
chỉ trong hàm.

**Giữ riêng.** Có phép gán lại (`+=`, tham số cùng tên, biến vòng lặp, `global`…), nhiều lời gọi
thực thi, biến còn được đọc ở chỗ khác, hay câu SQL đi vào hàm bọc chưa xác định: cảnh báo giữ đơn
vị riêng, kèm lý do.

**Truy vết.**

- Cảnh báo được nối giữ vị trí, quy tắc và nhãn CWE gốc.
- `UnitFinding.match_rule` là `explicit_link`.
- Bằng chứng đơn vị có `linked_by`: biến và câu gán.
- Lý do của đơn vị ghi dòng và biến.
- JavaScript/TypeScript và hai nhóm CWE-78, CWE-22 không đổi.

**Phát triển.** Luật được viết trên:

- kiểm thử tổng hợp: `test_sql_string_links.py`, 25 ca; `test_sql_linked_merge.py`, 5 ca, gồm một
  lượt quét lưu qua worker và API;
- năm lượt quét `v0.3` đã lưu của nguồn phát triển không nhãn.

Một lần chỉnh trước khi chốt: phần literal của f-string (pygoat). Một lần sửa sau lần chạy đầu trên
SVEN, sai lệch D1:

- **Vấn đề:** với chuỗi nhiều dòng, Bandit 1.9.4 ghi `endLine` không phải dòng cuối của chuỗi.
- **Sửa:** luật so dòng đầu, cột đầu và cột cuối, không so `endLine`.
- **Ghi lại:** `artifacts/cwe89-eval/PROTOCOL-MERGE-DEVIATIONS.md`.

### 23.2 Lệnh, phiên bản, đầu ra

**Trạng thái mã:**

- Commit `402566f` cộng thay đổi chưa commit; cây đã kiểm thử: `9d6334a10e527f4eac36ea60d210f49234cd6929`.
- Mã ứng dụng trong image worker có hash `4b17731a08fe1175`, giống cây làm việc.
- Hash profile:
  - `sql-injection-v0.3`: `5f33257e0909c8e7c5d2a27778309ff0c1bbbff9af4aa009ec43ad7cacd23c38`;
  - `multi-cwe-v0.4`: `24441fd8e0c4825a398baa19e23e4c26593dad0acfc9bba1cefcdf052091d0fc`.

**Công cụ:**

- Bandit 1.9.4, Semgrep CE 1.178.0, CodeQL 2.27.1: các cảnh báo được chạy lại phép gộp do chính các
  bản này sinh ra trong lượt quét SVEN.
- SonarQube Community Build 26.11.0.134175: image `sonarqube@sha256:65541acc…`.
- SonarScanner CLI 8.4.0.16527: image `sonar-scanner-cli@sha256:6e6eca4d…`.

**Giao thức:** `artifacts/cwe89-eval/PROTOCOL-MERGE.md`.

- sha256 `fa7cc7ea2faa67b36ca7410a1c281a2b5f1427a29e2403bee256916bc2b7a8fc`, chốt
  2026-11-16T11:16:06Z, trước lần chạy đầu của phép gộp mới trên SVEN.
- Sai lệch D1 ở `PROTOCOL-MERGE-DEVIATIONS.md`.

**Lệnh, chạy từ gốc repo:**

1. Lấy cảnh báo và đơn vị đã lưu của lượt quét SVEN:
   - `docker compose exec -T api python - bed105e3-9fea-41e3-8c3c-cbca1d0e9970 python/findings.json < artifacts/cwe89-eval/scan_artifacts.py > artifacts/cwe89-eval/sven-stored-file/findings.json`
   - tương tự với `python/units.json`.
2. Chạy lại phép gộp:
   - `cd backend && PYTHONPATH=. uv run python ../artifacts/cwe89-eval/replay_merge.py ../artifacts/cwe89-eval/sven-stored-file ../artifacts/cwe89-eval/sven-corpus-file/src MODE [--without bandit] ../artifacts/cwe89-eval/merge/replay-NAME.json`
   - `MODE` là `sql-call-site-v1` hoặc `sql-call-site-v2`; bốn lần chạy ở mục 2 của giao thức.
3. Đo, rồi phân tích sau đo:
   - `python -I artifacts/cwe89-eval/measure_merge.py`
   - `python -I artifacts/cwe89-eval/merge_posthoc.py`
4. Nguồn phát triển:
   - `python artifacts/cwe89-eval/fetch_stored_scan.py SCAN SNAPSHOT artifacts/cwe89-eval/dev-replay/NAME`, rồi `replay_merge.py` trên thư mục đó;
   - lượt quét thật: `python artifacts/cwe89-eval/scan_dev_v04.py NAME...`;
   - so sánh: `python artifacts/cwe89-eval/compare_v04.py NAME...`, `python artifacts/cwe89-eval/sarif_preserved_v04.py`.
5. SonarQube:
   - máy chủ: `docker network create cwe89-sonar`, rồi `docker run -d --name cwe89-sonarqube --network cwe89-sonar -p 127.0.0.1:9000:9000 -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true sonarqube:community`;
   - thiết lập qua API, với tài khoản `admin`:
     - đổi mật khẩu mặc định: `POST api/users/change_password`;
     - tạo dự án: `POST api/projects/create` với `project=cwe89-sven-file`;
     - tạo token: `POST api/user_tokens/generate` với `type=PROJECT_ANALYSIS_TOKEN`;
   - xác minh trước khi đo:
     - bản và phiên bản: `api/navigation/global`, `api/server/version`;
     - kho luật Python: `api/rules/repositories?language=py`;
     - luật CWE-89 và luật đang bật: `api/rules/search?languages=py&cwe=89`, `api/rules/search?qprofile=<profile mặc định>&activation=true&languages=py&cwe=89`;
     - kiểm luật taint: `api/rules/show?key=pythonsecurity:S3649`;
     - đầu ra ở `sonarqube/*.json` và `state.txt`;
   - quét: `docker run --rm --network cwe89-sonar -v <sven-corpus-file/src>:/usr/src:ro -e SONAR_HOST_URL=http://cwe89-sonarqube:9000 -e SONAR_TOKEN=… sonarsource/sonar-scanner-cli -Dsonar.projectKey=cwe89-sven-file -Dsonar.sources=. -Dsonar.inclusions=**/*.py -Dsonar.python.version=3.12 -Dsonar.scm.disabled=true`;
   - đo: `python -I artifacts/cwe89-eval/sonar_measure.py TỆP_MẬT_KHẨU`. Tệp chứa mật khẩu `admin` cục bộ và không lưu trong repo.
6. Hồi quy: `bash artifacts/cwe89-eval/final/run_all.sh`.

**Đầu ra:** `artifacts/cwe89-eval/merge/`, `dev-replay/`, `dev-v04/`, `sonarqube/`, `final/`, không
vào git.

### 23.3 Hiệu quả gộp trên cùng SARIF đã lưu (SVEN, 174 cặp)

| Lần chạy | Cảnh báo | Mục rà cả tập | Mục rà trong vùng có nhãn | Mục có cảnh báo của hơn một công cụ |
|---|---|---|---|---|
| Gộp cũ (`v0.3`), ba công cụ | 1268 | 833 | **343** | 185 |
| Gộp mới, theo giao thức lúc chốt | 1268 | 775 | 322 | 241 |
| **Gộp mới, sau sửa D1** | 1268 | **731** | **306** | 285 |

**Kiểm tra bắt buộc:**

- Chạy lại phép gộp cũ cho đúng 833 mục đã lưu: cùng ID, cùng cảnh báo trong từng mục.
- Mỗi cảnh báo nằm trong đúng một mục.
- Số ca dương và ca âm bị báo không đổi: 171 và 24.
- Cả **45/45** ca dương mà riêng Bandit bổ sung vẫn có mục rà chứa cảnh báo Bandit của ca đó.
- Không mục nào bị gạn. Điều này đúng theo cấu trúc mã: `keep_detected_v2` chỉ sinh mục ở danh sách
  rà. Bản chạy lại không giữ đánh giá của từng mục, nên trên SVEN điều này không được kiểm riêng; nó
  đã được kiểm trên sáu lượt quét thật `v0.4` (mục 23.6).

**So với mốc ước lượng 61.** Mốc 61 là số mục chỉ có Bandit, trong vùng có nhãn, ở hàm có lời gọi
thực thi.

- Phép gộp mới nối được **37** mục trong số đó; theo giao thức lúc chốt là 21.
- 24 mục còn lại đều ở hàm có lời gọi thực thi: 19 vì biến bị gán lại, 5 vì vùng báo không phải
  chuỗi được gán.
- 89 mục Bandit ở hàm qua hàm bọc không đổi: không có lời gọi thực thi nào để nối.
- Trên cả tập có 102 liên kết; 65 liên kết còn lại nối mục ở các hàm khác của cùng file.

**Lý do của 613 cảnh báo B608** (toàn bộ cảnh báo Bandit của lượt quét đều là B608):

| Lý do | Số cảnh báo |
|---|---|
| Đã nằm trong lời gọi (gộp từ `v0.3`) | 185 |
| Nối mới | 102 |
| Không lời gọi thực thi nào nhận biến (hàm bọc, `return`…) | 202 |
| Biến bị gán lại | 84 |
| Vùng báo không phải chuỗi được gán (ví dụ `q = db.query("…")`) | 22 |
| Không nằm trong câu gán đơn | 18 |

**Rà thủ công** 60 liên kết rút ngẫu nhiên (seed `20261116`) trong 102:

- Kết quả: **60 đúng, 0 sai, 0 chưa xác định** (`merge/link-review.md`).
- Ở mọi liên kết, chuỗi được báo là một phần của câu SQL gán cho biến, và lời gọi được nối chạy đúng
  biến đó.
- Kết luận chỉ nói về liên kết. Nhiều câu SQL trong mẫu chỉ ghép hằng, nên cảnh báo được nối vẫn có
  thể là cảnh báo sai.

### 23.4 Giá trị của Bandit sau khi đã gộp

Cùng dữ liệu, cùng nhãn, cùng phép gộp mới. Cấu hình hai công cụ được tính lại từ đầu vào đã bỏ cảnh
báo Bandit.

| Cấu hình (SVEN biến thể "file", 174 ca dương, 174 ca âm) | Ca dương bị báo | Ca âm bị báo | Mục rà trong vùng có nhãn | Mục rà cả tập | Giới hạn so sánh |
|---|---|---|---|---|---|
| `v0.3` (gộp cũ, CodeQL + Semgrep + Bandit) | 171 | 24 | 343 | 833 | Lượt quét đã lưu |
| Gộp mới có Bandit (`v0.4`) | 171 | 24 | 306 | 731 | Chạy lại trên SARIF đã lưu, sau sửa D1 (theo giao thức lúc chốt: 322 và 775) |
| Gộp mới bỏ Bandit (CodeQL + Semgrep) | 126 | 4 | 193 | 403 | Chạy lại, đầu vào bỏ Bandit; giống hệt gộp cũ bỏ Bandit |
| SonarQube độc lập: Community Build 26.11.0.134175, luật CWE-89 duy nhất `python:S2077` | 0 | 0 | 0 | 0 | Đã chạy ngoài Security Triage, trên cùng 251 file, cùng cách ghép với nhãn, chỉ tính kết quả SonarQube tự tạo. Bản này không có phân tích taint (S3649), nên **đối chứng phân tích injection chưa đo được**; các số 0 chỉ là kết quả của S2077 (mục 23.5) |

**Bandit bổ sung, sau gộp:**

- 45 ca dương mà CodeQL và Semgrep đều không báo (26% trong 174 ca);
- 20 ca âm báo thêm;
- **+113 mục rà** trong vùng có nhãn, từ 193 lên 306 (trước khi gộp mới là +150);
- +328 mục rà trên cả tập.

Cả 45 ca thêm đều ở hàm gọi SQL qua hàm bọc, và đến từ 12 kho (mục 22.4).

**Quy tắc chốt trước** (mục 5 của giao thức):

- Chi phí rà nền là 193/126 = 1,53 mục cho mỗi ca dương.
- Chi phí rà biên của Bandit là 113/45 = **2,51**. Ngưỡng 2 lần chi phí nền là 3,06, nên kết quả
  là **bật thường xuyên**.
- Theo kết quả lúc chốt (129/45 = 2,87), kết luận cũng như vậy. Trước khi gộp mới (150/45 = 3,33),
  quy tắc này sẽ cho "chỉ khi rà sâu".

### 23.5 Đối chứng SonarQube

**Đã xác minh trước khi đo** (`artifacts/cwe89-eval/sonarqube/state.txt`):

- **Bản:** `community`, phiên bản 26.11.0.134175.
- **Kho luật Python:** chỉ có `python` và các kho nhập kết quả ngoài (`external_*`). Không có kho
  `pythonsecurity`; luật taint S3649 không tồn tại (`api/rules/show` trả 404).
- **Luật Python gắn CWE-89:** chỉ `python:S2077` ("SQL queries should not be dynamically
  formatted"; kiểu `VULNERABILITY`, thẻ `former-hotspot`). Luật này đang bật trong profile mặc định
  "Sonar way core", là profile dự án đã dùng. Cách luật này nhận diện câu SQL không được tìm hiểu.

**Kết luận:** môi trường không có phân tích injection theo luồng dữ liệu, nên dòng đối chứng
SonarQube là **chưa đo được**. Không dùng SonarQube Cloud; mã nguồn không rời khỏi máy.

**Chú thích, không phải đối chứng injection:**

- Cùng 251 file của biến thể "file", cùng cách ghép với nhãn, chỉ tính kết quả SonarQube tự tạo.
- `python:S2077` báo **0** cảnh báo, nên 0 ca dương, 0 ca âm, 0 mục rà. Trên cùng tập, Bandit B608
  báo 613 cảnh báo. Vì sao S2077 không báo gì chưa được tìm hiểu.
- Phân tích có chạy: 251 file được đánh chỉ mục, 261 cảnh báo của các luật khác, ví dụ S5332 và
  S4502.

### 23.6 Hồi quy

**Lượt quét thật `multi-cwe-v0.4`** trên sáu nguồn phát triển không nhãn của P2b:

- Mỗi nguồn quét đúng snapshot mà lượt `v0.3` đã quét (`scan_dev_v04.py`, `queue_scan.py`).
- So sánh: `dev-v04/compare.txt`. Sáu nguồn đều **đạt**:
  - CWE-78 và CWE-22: đơn vị, báo cáo nhóm và SARIF giống hệt `v0.3`;
  - tập cảnh báo CWE-89 giống hệt theo nội dung;
  - mỗi mục `v0.3` nằm gọn trong một mục `v0.4`;
  - mọi mục ở danh sách rà, không gạn, không `suppressions`;
  - SARIF có mọi kết quả.
- `sarif_preserved_v04.py`: mỗi kết quả SARIF giữ vùng, thông điệp, nhãn CWE và quy tắc gốc của
  công cụ (`sarif-preserved-v04.json`).
- Nguồn tổng hợp được quét hai lần, do script gửi lặp; hai lượt cho cùng kết quả.

| Nguồn | Trạng thái | Cảnh báo CWE-89 | Mục `v0.3` → `v0.4` | Liên kết mới |
|---|---|---|---|---|
| nguồn tổng hợp | completed | 30 | 12 → 12 | 0 |
| pygoat | completed | 8 | 5 → 5 | 0: biến còn được đọc khi hiển thị câu SQL |
| vulpy | completed | 21 | 6 → 6 | 0: mọi B608 đã nằm trong lời gọi |
| dsvpwa | completed | 4 | 2 → 2 | 0 |
| dvpwa | completed | 3 | 2 → **1** | 1 |
| nodegoat | partial, như `v0.3` | 2 (JS) | 2 → 2 | 0: JavaScript/TypeScript không đổi |

**Bộ hồi quy** (`bash artifacts/cwe89-eval/final/run_all.sh`, đầu ra `final/run.txt`):

- Trạng thái đã kiểm thử: `402566f` cộng thay đổi chưa commit, cây
  `9d6334a10e527f4eac36ea60d210f49234cd6929` (`final/tested-state.txt`).
- Mã trong image worker: `4b17731a08fe1175`.

| # | Lệnh | Đạt | Bỏ qua |
|---|---|---|---|
| 1 | `uv run pytest -q -rs --cov` (SQLite) | 723 | 2 (nhóm tiến trình POSIX trên Windows) |
| 2 | `docker compose --profile test run --build --rm test` (PostgreSQL) | 725, độ phủ 95,67% | 0 |
| 3 | `ruff check`, `ruff format --check`, `mypy`, `pip-audit` | sạch; không lỗ hổng đã biết | — |
| 4 | `python -m unittest discover -s experiments/tests` | 153 | 0 |
| 5 | `npm run check`, `npm run build`, `npm run test:e2e` (API giả lập) | Vitest 82; build; Playwright 2 | 3 (kiểm thử stack thật, dòng 7 và 9) |
| 6 | `scripts.export_openapi` so với `frontend/openapi.json`; `scripts.check_worker` | giống hệt; worker nhận cả tám profile | — |
| 7 | `multi-cwe-full-stack.spec` (công cụ thật, `multi-cwe-v0.1`) | 1: 239 kết quả, 149 đơn vị, 64 gạn, như trước | 0 |
| 8 | `legacy_regression.py` (bốn profile cũ, công cụ thật) | 4/5 giống hệt; ca `command-injection-v0.1` khác đúng như mục 18.3 | — |
| 9 | `multi-cwe-v02-full-stack`, `multi-cwe-v03-full-stack` (PyGoat) | 2 | 0 |
| 10 | Golden, thực nghiệm, công cụ, pack và profile cũ (gồm `multi-cwe-v0.3`, `sql-injection-v0.2`, `rules/semgrep/sql-injection-v0.1`) | 0 file đổi; hash `sql-injection-v0.2` và `multi-cwe-v0.3` bằng hash đã ghim | — |

**Kiểm thử mới:**

- `test_sql_string_links.py`: 25 ca.
- `test_sql_linked_merge.py`: 5 ca.
- Một ca giao diện cho lựa chọn `multi-cwe-v0.4`.

Các golden của bốn profile cũ và của `multi-cwe-v0.1`, `v0.2` không đổi một byte.

### 23.7 Đề xuất và giới hạn

**Đề xuất: bật Bandit thường xuyên cho CWE-89 ở Python, cùng với phép gộp mới.**

- Trên tập độc lập SVEN, Bandit là nguồn duy nhất của 45/174 ca dương, cả 45 đều ở mã gọi SQL qua
  hàm bọc, nơi CodeQL và Semgrep không thấy.
- Sau khi gộp, giá là 113 mục rà thêm, 2,51 mục cho mỗi ca dương thêm, và 20 ca âm báo thêm. Đọc tay
  ở mục 22.4 cho thấy 18 trong 20 ca âm đó chỉ ghép hằng.
- **Nếu khối lượng rà là ràng buộc chính:** để Bandit "chỉ khi rà sâu" cho mã gọi thẳng `execute`.
  Ở đó Bandit không thêm ca dương nào, trên cả SVEN lẫn BenchmarkPython.
- **Việc tiếp theo nên làm:** nối thêm trường hợp biến bị gán lại một cách tuần tự (`sql = …; sql +=
  …`). Đây là 19 trong 24 mục trùng còn lại.

**Giới hạn:**

- **Dữ liệu:** một tập, quét từng file, không có phần còn lại của kho. Nhãn SVEN chưa được dự án
  kiểm lại.
- **Phạm vi phép gộp:** chỉ áp cho B608 ở Python.
- **Quy tắc đề xuất:** không mù với phân bố 89/61 đã biết; ngưỡng 2 lần là lựa chọn của người đo.
- **SonarQube:** chưa đo được.
- **Kiểm thử:** chưa có kiểm thử trình duyệt trên stack thật cho `v0.4`. Lượt quét thật chạy qua
  API và worker (mục 23.6). CI chưa chạy.

## 24. Nhóm CWE-79 cho JavaScript/TypeScript: profile `multi-cwe-v0.5` (2026-11-16)

Profile ghép thử nghiệm `multi-cwe-v0.5`: ba nhóm của `multi-cwe-v0.4` cộng nhóm **cross-site
scripting (CWE-79)** cho JavaScript/TypeScript, chỉ bằng CodeQL, chỉ phát hiện và giữ.

- **Mốc đối chứng:** `multi-cwe-v0.4` ở commit `0d0ad04`, chạy trên image worker dựng từ commit đó
  (mã ứng dụng `4b17731a08fe1175`, giữ lại dưới tên `security-triage-worker:v04-0d0ad04`) trước mọi
  thay đổi.
- **Không đổi:** `multi-cwe-v0.4` và ba thành viên của nó (cùng manifest, cùng hash), các profile đã
  khóa, golden, dữ liệu nghiên cứu, các số đo của mục 20–23.
- **Không quét bằng `v0.5`, không đo lại CWE-89:** nguồn có nhãn của CWE-89 (BenchmarkPython, Juice
  Shop), SVEN, các cặp đã đóng băng hay giữ lại. BenchmarkPython chỉ được quét lại trong bộ hồi quy
  (24.9), bằng `multi-cwe-v0.1` và `command-injection-v0.2`, không có lượt CWE-89 nào. Tập có nhãn của
  CWE-79 là một bộ dữ liệu mới, chưa dùng ở dự án (24.7).
- **Ngoài phạm vi, để các lượt đo sau:** Semgrep cho XSS, đối chứng SonarQube, CWE-79 cho Python.

### 24.1 Thành viên CWE-79 (`cross-site-scripting-v0.1`)

Đặc tả: [profiles/cross-site-scripting-v0.1/DETECTION.md](../../profiles/cross-site-scripting-v0.1/DETECTION.md).

- **Kiểu:** profile `detection` schema 1, chỉ có cấu hình JavaScript. Dùng lại nguyên đường xử lý của
  `sql-injection-v0.1`: một lượt có tên trên database dùng chung, `detection.keep_detected`, mỗi vị trí
  được báo là một đơn vị mức U, quyết định `K10_DETECTED_KEPT`, lý do giữ
  `no_filter_condition_for_family`.
- **Truy vấn:** mọi truy vấn của `codeql/javascript-queries` 2.4.6 (CodeQL 2.27.1) nằm trong
  `Security/CWE-079/`. Cách chọn chỉ theo vị trí trong gói, ghi trước khi chạy trên dữ liệu nào. Cả bảy
  thuộc bộ `javascript-code-scanning.qls`.

| Rule | Biến thể XSS | sha256 của tệp `.ql` |
|---|---|---|
| `js/reflected-xss` | phản xạ, phía máy chủ | `9c4044e9…` |
| `js/stored-xss` | lưu trữ, phía máy chủ (nguồn theo mô hình CodeQL: chủ yếu tên tệp) | `f58eaff8…` |
| `js/xss` | dựa trên DOM, phía trình duyệt | `bfbd13ad…` |
| `js/xss-through-dom` | văn bản DOM ghi lại dưới dạng HTML | `60f222e2…` |
| `js/xss-through-exception` | thông điệp ngoại lệ ghi dưới dạng HTML | `c6db7547…` |
| `js/unsafe-jquery-plugin` | tùy chọn plugin jQuery dùng như HTML | `98356c79…` |
| `js/html-constructed-from-input` | đầu vào hàm thư viện ghép vào HTML | `26c953a6…` |

- **CWE ánh xạ:** CWE-79 và CWE-116, đúng các nhãn `external/cwe/*` của bảy truy vấn. Nhãn CodeQL gắn
  (`cwe-079`, `cwe-116`) giữ nguyên ở `reported_cwes`.
- **Truy vấn có nhãn `cwe-079` nhưng không chọn:** 14 truy vấn, gói xếp vào CWE-94 (chèn mã), CWE-116
  (chất lượng bộ làm sạch), CWE-601 (chuyển hướng), CWE-915 (ô nhiễm prototype), một kiểm tra cấu hình
  Electron và bốn truy vấn thử nghiệm. Danh sách và lý do: mục 1 của DETECTION.md.
- **Cấu hình chạy:** một lượt `database analyze` cho bảy truy vấn, `--threads 1`, `--ram=2048`, giới
  hạn 600 giây. Bản đầu dùng `--threads 2`; trên dữ liệu phát triển CodeQL hết bộ nhớ khi biên dịch hai
  truy vấn cùng lúc, nên đổi về một luồng trước khi chốt (24.4).
- **Hai chỗ sửa chữ trong đặc tả trước khi chốt**, không đổi hành vi: số truy vấn thử nghiệm bị loại
  (bốn, không phải ba); và mục 4 mô tả đúng hai trạng thái lỗi như lượt tiêm lỗi cho thấy (ghi SARIF
  rồi thoát lỗi là "thất bại", cảnh báo giữ thành `F10_FAMILY_NOT_RANKED`; chỉ SARIF ghi lượt chạy
  chưa xong mới là "chạy dở"). Băm manifest cuối: `cross-site-scripting-v0.1`
  `af7af94a3c2abcdbfdae0900f42e0f0874309b2c8256ab82967b2b9839ca5439`, `multi-cwe-v0.5`
  `11dfc98179cd5172a547429eb29b219f76fd25c82e3a7455ef07150491e3953a`.

### 24.2 Thay đổi mã

- `families.py`: nhóm `cross-site-scripting` (CWE-79, `DetectionProfile`) và profile thành viên của
  nó. Không có mã xử lý riêng cho nhóm này.
- `config.py`, `schemas.py`: profile `multi-cwe-v0.5` và giá trị `cross-site-scripting` của
  `FamilyName`; `frontend/openapi.json` và `api-schema.d.ts` xuất lại.
- `task.py`: `SOFT_TIME_LIMIT` từ 12 000 lên 12 600 giây. Trường hợp xấu nhất của `multi-cwe-v0.5` là
  12 360 giây (`v0.4`: 11 760, cộng một lượt 600 giây). `TIME_LIMIT` là 14 100 giây, vẫn dưới thời
  gian hiển thị lại của broker (14 400).
- Giao diện: lựa chọn "CWE-78 + CWE-22 + CWE-89 + CWE-79 · Thử nghiệm: thêm XSS cho
  JavaScript/TypeScript" và nhãn nhóm "CWE-79 · Cross-site scripting (XSS)".
- Kiểm thử:
  - `test_xss_family.py`, 12 ca: profile; ba nhóm cũ giống `v0.4` trên cùng công cụ giả lập; cảnh báo
    XSS trùng vị trí với cảnh báo CWE-78 hay CWE-89 vẫn là đơn vị riêng; hai rule cùng vùng chung một
    đơn vị; ba kiểu lỗi của lượt XSS; rule không ghim; lưu qua worker, API, báo cáo và SARIF;
  - hai ca giao diện;
  - `multi-cwe-v05-full-stack.spec.ts`: từ chọn profile tới tải SARIF, trên stack thật;
  - `test_families.py`: ví dụ "profile chưa có nhóm" đổi từ `cross-site-scripting-v0.1`, nay đã có
    nhóm, sang một ID khác.

### 24.3 Mốc trước khi sửa

Chạy `multi-cwe-v0.4` trên bảy nguồn phát triển không nhãn, bằng image của `0d0ad04`, trước khi sửa
mã. Kết quả lưu ở `artifacts/cwe79-eval/baseline-v04/`: lượt quét, mọi đơn vị kèm cảnh báo, quyết định
gạn và trạng thái bằng chứng, báo cáo trước–sau, SARIF.

- **Năm nguồn GitHub** của P2b: pygoat, vulpy, DSVPWA, dvpwa, NodeGoat, cùng snapshot như các lượt
  `v0.3` và `v0.4` trước.
- **Nguồn tổng hợp ba nhóm** của P2a/P2b.
- **Đầu vào phát triển bốn nhóm, mới** (`artifacts/cwe79-eval/dev-input/four-families/`, snapshot
  `dbe4b64d…`): ba tệp của nguồn tổng hợp ba nhóm, thêm ba tệp:
  - `pages.js`: XSS phản xạ; một dòng có cả lệnh `exec` (CWE-78) và `res.send` HTML; một dòng có cả
    truy vấn SQL (CWE-89) và `res.send` HTML; một ca có `escape-html`;
  - `views.ts`: XSS phản xạ trong TypeScript, và một ca gửi `text/plain`;
  - `public/client.js`: URL ghi vào `innerHTML`, văn bản DOM ghi vào `innerHTML`, và một ca dùng
    `textContent`.

Mã tạo đầu vào bốn nhóm: `seed_dir.py` của mục 22. Mã ứng dụng trong image mốc là `4b17731a08fe1175`,
đúng như cây đã commit.

### 24.4 Đối chứng 1: CWE-78, CWE-22, CWE-89 so với `v0.4`

So theo nội dung, như P2b: mọi đơn vị với quyết định, lý do, trạng thái bằng chứng và cảnh báo
(lượt, rule, tệp, vùng, nhãn CWE); báo cáo của nhóm; các kết quả SARIF của nhóm; bản ghi nhóm của
lượt quét. Script `compare_v05.py`, đầu ra `compare-v05.txt`.

| Nguồn | Trạng thái `v0.4` → `v0.5` | Đơn vị CWE-78 / 22 / 89 | Ba nhóm giống `v0.4` | `v0.4` dựng lại giống mốc | Cảnh báo / đơn vị CWE-79 |
|---|---|---|---|---|---|
| bốn nhóm (tổng hợp) | completed → completed | 8 / 3 / 14 | có | có | 7 / 7 |
| ba nhóm (tổng hợp) | completed → completed | 7 / 3 / 12 | có | có | 0 / 0 |
| pygoat | completed → completed | 4 / 3 / 5 | có | có | 3 / 3 |
| vulpy | completed → completed | 1 / 1 / 6 | có | có | 0 / 0 |
| DSVPWA | completed → completed | 3 / 2 / 2 | có | có | 1 / 1 |
| dvpwa | completed → completed | 0 / 0 / 1 | có | có | 11 / 11 |
| NodeGoat | partial → partial (Semgrep, như `v0.3`) | 1 / — / 2 | có | có | 0 / 0 |

- **Đối chứng của phép đối chứng:** `v0.4` cũng được quét lại trên image mới (`dev-v04-new-image/`).
  Nó giống mốc, nên mã mới không đổi gì ở `v0.4`.
- **CodeQL không tất định ở một chỗ:** với một cảnh báo CWE-89 của vulpy, CodeQL ghi các đường dữ
  liệu (`codeFlows`) theo thứ tự khác và đánh số tệp theo thứ tự đó. Điều này xảy ra cả khi chạy lại
  chính `v0.4`. Phép so coi các đường là một tập và bỏ số thứ tự tệp, như P2b đã làm với
  `relatedLocations`. Mọi thứ khác của cảnh báo, kể cả vùng và thông điệp, giống hệt.
- **Mọi cảnh báo CWE-79:**
  - thuộc một trong bảy rule, đến từ lượt `codeql-cross-site-scripting`;
  - nằm trong đúng một đơn vị của nhóm mình, mức U, `K10_DETECTED_KEPT`, danh sách rà chính, trạng
    thái bằng chứng "chưa đủ";
  - không bị gạn, không có `suppressions`.
- **Trên đầu vào bốn nhóm:**
  - cảnh báo XSS ở dòng 23 và dòng 28 của `pages.js` là đơn vị riêng, cạnh đơn vị CWE-78 (dòng 23)
    và hai đơn vị CWE-89 (dòng 28) cùng dòng;
  - TypeScript: hai cảnh báo trong `views.ts`;
  - ba rule khác nhau báo: `js/reflected-xss` 5, `js/xss` 1, `js/xss-through-dom` 1;
  - không báo ca `escape-html` và ca `textContent`;
  - **có báo** ca `res.type("text/plain").send(...)`, mà đầu vào ghi là không có XSS: CodeQL không
    xét kiểu nội dung của phản hồi. Đây là một cảnh báo sai trên dữ liệu phát triển.
- **Trên mã thật:** 15 cảnh báo, ở pygoat (3, trong script của tệp HTML), DSVPWA (1, `dom-xss.js`)
  và dvpwa (11, tất cả trong thư viện `materialize.js` đi kèm mã). Thư viện đi kèm là một nguồn mục
  rà đáng kể: 11 trên 12 mục của dvpwa.

**Lỗi tự nhiên trước khi chốt.** Bản đầu của cấu hình dùng `--threads 2`. Trên cả bảy nguồn, lượt
CWE-79 thất bại vì CodeQL hết bộ nhớ khi biên dịch truy vấn (`dev-v05-oom/`). Ba nhóm còn lại vẫn
giống mốc trên cả bảy nguồn (`compare-v05-oom.txt`). Cấu hình được đổi sang một luồng. Một bản nữa,
`dev-v05-spec1/`, chạy với bản đặc tả trước khi sửa hai chỗ chữ (24.1); kết quả giống hệt.

### 24.5 Đối chứng 2: CWE-79 so với CodeQL chạy riêng

`standalone_codeql.sh` chạy riêng CodeQL, bên ngoài ứng dụng:

- trong một container dùng một lần, từ image worker (cùng bundle CodeQL, cùng gói truy vấn);
- trên đúng tệp nén snapshot mà ứng dụng đã quét, giải nén như worker;
- tạo database mới với tham số của `run_codeql`, rồi chạy bảy truy vấn với tham số của
  `run_codeql_evidence`.

Không dùng chung database, không có lượt nào khác. So theo tập bội (rule, tệp, dòng/cột đầu, dòng/cột
cuối); vùng không có `endLine` kết thúc ở dòng đầu, cả hai phía. Script `compare_standalone.py`, đầu ra
`compare-standalone.json`.

| Nguồn | Cảnh báo ứng dụng | CodeQL chạy riêng | Giống nhau | SARIF xuất ra so với SARIF của CodeQL | Nhãn CWE so với tag của rule |
|---|---|---|---|---|---|
| bốn nhóm | 7 | 7 | có | giống | giống |
| ba nhóm | 0 | 0 | có | giống | — |
| pygoat | 3 | 3 | có | giống | giống |
| vulpy | 0 | 0 | có | giống | — |
| DSVPWA | 1 | 1 | có | giống | giống |
| dvpwa | 11 | 11 | có | giống | giống |
| NodeGoat | 0 | 0 | có | giống | — |

- Băm của bảy tệp `.ql` CodeQL chạy riêng dùng bằng băm đã ghim trong profile.
- "SARIF xuất ra": rule, tệp, vùng và **thông điệp** của mọi kết quả CWE-79 trong SARIF hợp nhất bằng
  đúng tập kết quả trong SARIF của CodeQL chạy riêng.
- "Nhãn CWE": `reportedCwes` của mỗi kết quả bằng các tag `external/cwe/*` của rule trong SARIF của
  CodeQL.
- Theo từng kết quả, trên mọi nhóm của bảy lượt `v0.5` (`sarif_preserved_v05.py`, đầu ra
  `sarif-preserved-v05.json`): 203 kết quả SARIF, bằng đúng 203 cảnh báo đã lưu. Mỗi kết quả giữ vùng,
  thông điệp và nhãn CWE của kết quả gốc của công cụ; 59 rule Semgrep CWE-89 truy được về tệp luật đã
  ghim. Đạt cả bảy.

**Chi phí.**

- Lượt CWE-79 mất 15–18 giây trên pygoat khi bộ nhớ đệm biên dịch của worker đã có, và 200–250
  giây ở lượt đầu sau khi dựng lại worker, chủ yếu là biên dịch bảy truy vấn.
- Một lượt quét `v0.5` của nguồn GitHub phát triển mất 47–122 giây, so với 31–75 giây của `v0.4`.
- CodeQL chạy riêng, không có bộ nhớ đệm, mất 197–310 giây cho bước phân tích.

### 24.6 Luồng giao diện đến SARIF, và lỗi ở lượt CWE-79

**Luồng giao diện** (`tests/e2e/multi-cwe-v05-full-stack.spec.ts`, trên stack thật, PyGoat):

- chọn profile bốn nhóm trong biểu mẫu, nguồn GitHub, gửi;
- trang lượt quét hiện bốn nhóm; hàng CWE-79 ghi `cross-site-scripting-v0.1`, `javascript: completed`;
- lọc theo nhóm CWE-79, mở chi tiết một đơn vị;
- tải báo cáo JSON và SARIF hợp nhất.

Kết quả: đạt.

- Lượt quét `2fa2fa81…`, `completed`. Đơn vị theo nhóm: CWE-78 4, CWE-22 3, CWE-89 5, CWE-79 3; tất cả
  ở danh sách rà chính.
- SARIF có 25 kết quả, bằng số cảnh báo đã lưu. Ba kết quả CWE-79, mỗi kết quả đúng rule CodeQL, nhãn
  `cwe-079`, không bị ẩn.

**Lỗi có kiểm soát** (`xss_faults.py`, đầu ra `xss-faults.txt`):

- Một worker thứ hai nghe hàng đợi `faults`, có tệp bọc `codeql` đứng đầu `PATH`
  (`artifacts/cwe79-eval/fault/`).
- Tệp bọc gọi CodeQL thật, trừ đúng lỗi ghi trong `fault/mode`, và chỉ cho lệnh phân tích có truy vấn
  `CWE-079`.
- Nguồn: đầu vào bốn nhóm. Mỗi lượt lỗi được so theo nội dung với một lượt sạch chạy cùng cách.

| Lỗi tiêm vào | Lượt quét | Lượt `codeql-cross-site-scripting` | Nhóm CWE-79 | CWE-78, CWE-22, CWE-89 |
|---|---|---|---|---|
| không lỗi | `completed` | `completed` | 7 cảnh báo, 7 đơn vị `K10_DETECTED_KEPT`, "chưa đủ" | 8, 3, 14 đơn vị |
| thoát lỗi, chưa ghi SARIF | `partial` | `failed` | 0 cảnh báo; nhóm "thất bại" | giống lượt sạch |
| ghi SARIF rồi thoát lỗi | `partial` | `failed` | 7 cảnh báo giữ lại thành 7 đơn vị `F10_FAMILY_NOT_RANKED`, mức U, danh sách rà, "không lấy được" | giống lượt sạch |
| SARIF ghi lượt chạy chưa xong | `partial` | `partial` | 7 cảnh báo, 7 đơn vị K10 với `run_incomplete`, "không lấy được" | giống lượt sạch |

- Trong cả bốn lượt: mọi cảnh báo đã lưu nằm trong đúng một đơn vị và có trong SARIF (67 hay 60 kết
  quả), không đơn vị nào trộn hai nhóm, không kết quả CWE-79 nào bị ẩn.
- Lỗi hết bộ nhớ thật ở 24.4 là một ca "thoát lỗi, chưa ghi SARIF" xảy ra tự nhiên trên cả bảy nguồn.

### 24.7 Đo CWE-79 trên tập có nhãn: OSSF CVE Benchmark

Kết quả này là **đánh giá trên tập có nhãn**, tách khỏi nghiệm thu kỹ thuật (24.10).

**Giao thức:** `artifacts/cwe79-eval/PROTOCOL-XSS.md`.

- sha256 `714e5ae2f08aa4a2082f90c7f328bcbecf5376fe3b064a8a513be3f269c0daaa`, chốt
  2026-11-16T14:48:09Z, trước lượt quét đầu tiên trên tập này.
- `PROTOCOL-XSS.sha256` băm cùng lúc mọi thứ quyết định phép đo: script chọn ca, quét, chấm; tệp nén
  của bộ dữ liệu; mã commit đầy đủ; kết quả kiểm trùng; hai manifest.
- `ossf_scan.py` kiểm các băm đó, mã ứng dụng của worker và hai manifest worker đang dùng trước khi gửi.
  Sau lượt quét, `sha256sum -c` vẫn khớp mọi tệp.
- Hai sai lệch (`PROTOCOL-XSS-DEVIATIONS.md`), không đổi số đo nào:
  - D1: nhãn trạng thái `acquisition_failed` gồm cả lượt quét không có tệp của ngôn ngữ nào;
  - D2: đã đọc trạng thái (không đọc cảnh báo) của các lượt CodeQL khác để giải thích lượt chạy dở.

**Bộ dữ liệu.** OpenSSF CVE Benchmark ở commit `91c59fd5`: CVE thật của các dự án JavaScript/TypeScript.
Mỗi CVE có commit trước bản vá với vị trí điểm yếu (tệp, dòng) và commit bản vá.

- **Chọn ca:** danh sách CWE có CWE-79, và mọi CWE khác trong đó là CWE-116 hay CWE-20.
- **Kết quả chọn:** 49 ca, 38 kho, 50 vị trí, 87 commit. Bị loại 34 ca có CWE-79 đi cùng ô nhiễm
  prototype, chèn mã hay chuyển hướng.
- **Không trùng** với dữ liệu nào dự án đã dùng: kiểm bằng chuỗi và bằng các trường định danh.
- **Thiên lệch đã biết, ghi trước khi quét:** phần lớn lời giải thích là nguyên văn tên một truy vấn
  CodeQL, và bộ dữ liệu có tích hợp sẵn CodeQL. Số phát hiện được ở đây vì thế **không độc lập với
  công cụ**.
  - Giao thức gọi đây là "cận trên lạc quan". Kết quả không ủng hộ điều đó: CodeQL 2.27.1 không báo
    gì trong 24 tệp có nhãn.
  - Driver CodeQL của chính bộ dữ liệu chọn truy vấn theo CWE của ca, dùng bundle mới nhất lúc chạy và
    không cài thư viện phụ thuộc. Phiên bản và cấu hình đã dùng để đặt nhãn thì không biết.

**Cách đo:**

- Mỗi commit được ứng dụng tải từ GitHub và quét **một lần** bằng `multi-cwe-v0.5`. Chỉ đọc cảnh báo
  của nhóm `cross-site-scripting`.
- **Ca dương được phát hiện:** có cảnh báo CWE-79 cùng tệp, bắt đầu đúng dòng điểm yếu. Đây là quy
  tắc của chính bộ dữ liệu.
- **Ca âm bị báo:** có cảnh báo CWE-79 ở dòng điểm yếu sau khi chuyển sang bản vá bằng phép so dòng.
- **Tầng A:** lời giải thích là tên một trong bảy truy vấn trong phạm vi. **Tầng B:** lời giải thích
  khác.

**Trạng thái của 87 commit:**

| Trạng thái nhóm CWE-79 | Commit |
|---|---|
| `completed` | 73 |
| `partial` (jquery hai commit, knockout hai commit, angular.js hai commit; mọi lượt CodeQL của lượt quét đều `partial`) | 6 |
| không đo được: HTTP 404 từ codeload (fork `linxiaowu66/swagger-ui`, `apache/uima-ducc`) | 4 |
| không đo được: tệp nén vượt 50 MB (`strapi/strapi`) | 2 |
| không đo được: không có tệp của ngôn ngữ nào (`tnantoka/public`, chỉ có `bin/public` không đuôi; D1) | 2 |

**Kết quả** (`ossf-measure.txt`):

| | Ca | Không đo được | Lượt chạy dở | Đo được (commit trước bản vá `completed`) | Ca dương phát hiện | Ca dương bỏ sót |
|---|---|---|---|---|---|---|
| Tất cả | 49 | 5 | 3 (0 phát hiện) | 41 | **14** | **27** |
| Tầng A | 38 | 3 | 1 (0 phát hiện) | 34 | 14 | 20 |
| Tầng B | 11 | 2 | 2 (0 phát hiện) | 7 | 0 | 7 |

- **Tỉ lệ phát hiện:** 14/41 ca đo được; 14/34 ở tầng A, 0/7 ở tầng B.
- **Quy tắc vùng:** vùng báo chứa dòng điểm yếu cho đúng 14 ca, không thêm ca nào.
- **Rule phát hiện:** `js/reflected-xss` 7, `js/xss-through-dom` 5, `js/unsafe-jquery-plugin` 2,
  `js/stored-xss` 1, `js/html-constructed-from-input` 1. Hai ca có hai rule: CVE-2018-16484 và
  CVE-2019-12313.
- **Ca âm:** đo được 41 ca. **Bị báo: 1** (CVE-2018-16484, `nunnly/m-server`).
  - Dòng điểm yếu không đổi qua bản vá; bản vá sửa ở chỗ khác, và CodeQL vẫn báo đúng dòng đó.
  - Trong 14 ca mà ca dương được phát hiện, 1 ca âm bị báo. Trong 27 ca dương bị bỏ sót, 0 ca âm bị
    báo, nhưng số này không có nghĩa, vì ở bản lỗi CodeQL cũng không báo.
  - Cách chuyển dòng: 33 vị trí bị thay, 11 không đổi, 1 bị xóa, 5 không đo được.
- **Mục cần rà:**
  - 387 đơn vị CWE-79 (390 cảnh báo) trên 87 commit, mỗi commit tính một lần;
  - 201 đơn vị trên 39 commit trước bản vá có nhóm CWE-79 (36 `completed`, 3 chạy dở): trung vị 2 mỗi
    commit, nhiều nhất 48 (bootstrap), 13 commit không có đơn vị nào;
  - 16 đơn vị chứa cảnh báo ở vị trí có nhãn.
- **Cảnh báo ngoài tập có nhãn:** 372 trên 390, mỗi commit tính một lần: 187 ở commit trước bản vá,
  185 ở commit bản vá. Chúng chưa có nhãn, nên không phải dương tính giả đã xác minh.
  - `js/xss-through-dom` chiếm 296 trên 390 cảnh báo.
  - Trên dữ liệu phát triển, nhiều cảnh báo loại này nằm trong thư viện đi kèm mã, như
    `materialize.js` của dvpwa.

**Mô tả sau đo** (`ossf_posthoc.py`, viết sau khi xem kết quả, không đổi số nào ở trên).

- **Tệp có trong snapshot đã quét:** cả 28 vị trí bị bỏ sót (27 ca). Phép kiểm này chỉ đọc tệp nén
  đã lưu; việc CodeQL có trích xuất tệp đó hay không thì chưa kiểm.
- **24 vị trí:** CodeQL không báo cảnh báo CWE-79 nào trong cả tệp đó.
- **4 vị trí:** có cảnh báo ở dòng khác cùng tệp, gần nhất cách 8 dòng. Không ca nào là lệch dòng nhỏ.

Vậy phần bỏ sót không do cách ghép theo dòng: CodeQL 2.27.1 không báo ở các tệp đó. Lý do chưa được
kiểm; có thể là:

- tệp không được trích xuất;

- mô hình nguồn và đích của thư viện;
- mã chạy trong trình duyệt nhận dữ liệu qua API của thư viện;
- không có `node_modules` khi quét.

**Giới hạn của phép đo:**

- Nhãn không độc lập với CodeQL (xem trên); không biết phiên bản và cấu hình đã dùng để đặt nhãn.
- 41 ca đo được là một mẫu nhỏ, chỉ của các thư viện và ứng dụng JavaScript mã nguồn mở.
- Chỉ đo ở dòng điểm yếu đã biết; 372 cảnh báo còn lại chưa được rà.
- Ca âm chỉ là vị trí đã vá, không phải mã an toàn bất kỳ.
- Tệp không đuôi, kho vượt giới hạn tải và kho đã mất trên GitHub không đo được.

### 24.8 Lệnh, phiên bản, đầu ra

**Trạng thái mã:**

- Commit `0d0ad04` (`multi-cwe-v0.4` đã chốt) cộng thay đổi chưa commit. Cây `backend/`, `frontend/`,
  `profiles/`, `rules/` đã kiểm thử: `46d2573632b332fdba4a118ea2ca2874cdc22c74`.
- Mã ứng dụng trong image worker: `93c658820937f424`, giống cây làm việc. Image dùng cho đối chứng,
  lỗi tiêm, luồng giao diện và tập có nhãn được gắn tên `security-triage-worker:v05-measure`; image mốc
  là `security-triage-worker:v04-0d0ad04`.
- Hash profile:
  - `cross-site-scripting-v0.1`: `af7af94a3c2abcdbfdae0900f42e0f0874309b2c8256ab82967b2b9839ca5439`;
  - `multi-cwe-v0.5`: `11dfc98179cd5172a547429eb29b219f76fd25c82e3a7455ef07150491e3953a`;
  - ba thành viên còn lại và `multi-cwe-v0.4` không đổi.

**Công cụ:** CodeQL 2.27.1, `codeql/javascript-queries` 2.4.6, Semgrep CE 1.178.0, Bandit 1.9.4,
ESLint 10.15.0, như `tools/pins.env`.

**Lệnh, chạy từ gốc repo:**

1. Mốc: `python artifacts/cwe79-eval/scan_dev.py multi-cwe-v0.4 artifacts/cwe79-eval/baseline-v04 four-families=<scan> three-families pygoat vulpy dsvpwa dvpwa nodegoat`, trên image `0d0ad04`. Đầu vào bốn nhóm: `docker compose exec -T -e PYTHONPATH=/app api python /tmp/seed/seed_dir.py cwe79-dev-four-families /tmp/seed/four-families -- multi-cwe-v0.4`.
2. Sau khi dựng lại image: cùng lệnh với `multi-cwe-v0.5 artifacts/cwe79-eval/dev-v05` và `multi-cwe-v0.4 artifacts/cwe79-eval/dev-v04-new-image`.
3. Đối chứng 1: `python artifacts/cwe79-eval/compare_v05.py four-families three-families pygoat vulpy dsvpwa dvpwa nodegoat`; thêm `--new=dev-v05-oom --out=compare-v05-oom` cho lô hết bộ nhớ.
4. Đối chứng 2: `python artifacts/cwe79-eval/compare_standalone.py four-families three-families pygoat vulpy dsvpwa dvpwa nodegoat`; `python artifacts/cwe79-eval/sarif_preserved_v05.py`.
5. Lỗi tiêm: `MSYS_NO_PATHCONV=1 docker compose run -d --name fault-worker-xss --no-deps -v "<repo>/artifacts/cwe79-eval/fault:/fault" worker sh -c 'export PATH=/fault:$PATH; exec celery -A app.workers.celery_app:celery_app worker --concurrency=1 -Q faults -n fault@%h'`, rồi `python artifacts/cwe79-eval/xss_faults.py`.
6. Tập có nhãn:
   - chọn ca: `python -I artifacts/cwe79-eval/ossf_cases.py`; mã commit đầy đủ: `resolve_commits.py`; trùng lặp: `overlap_check.py`, `overlap_fields.py`;
   - chạy thử trước khi chốt: `python artifacts/cwe79-eval/ossf_scan.py --rehearsal=artifacts/cwe79-eval/rehearsal/targets.json --out=artifacts/cwe79-eval/rehearsal/scan`, `python -I artifacts/cwe79-eval/ossf_measure.py --cases=artifacts/cwe79-eval/rehearsal/cases.json --scans=artifacts/cwe79-eval/rehearsal/scan --out=artifacts/cwe79-eval/rehearsal/measure`;
   - quét: `python artifacts/cwe79-eval/ossf_scan.py`; chấm: `python -I artifacts/cwe79-eval/ossf_measure.py`.
7. Hồi quy: `bash artifacts/cwe79-eval/final/run_local.sh`, `bash artifacts/cwe79-eval/final/run_stack.sh`.

**Đầu ra** (`artifacts/cwe79-eval/`, không vào git): `baseline-v04/`, `dev-v05/`, `dev-v04-new-image/`,
`dev-v05-oom/`, `dev-v05-spec1/`, `compare-v05*.txt|json`, `standalone/`, `compare-standalone.json`,
`sarif-preserved-v05.json`, `xss-faults.txt|json`, `dev-input/`, `PROTOCOL-XSS.md` và `.sha256`,
`ossf-download/`, `ossf-scan/`, `ossf-measure.txt|json`, `rehearsal/`, `final/`.

### 24.9 Hồi quy

`bash artifacts/cwe79-eval/final/run_local.sh` (đầu ra `final/run-local.txt`) và
`bash artifacts/cwe79-eval/final/run_stack.sh` (đầu ra `final/run-stack.txt`), cả hai trước lượt quét
tập có nhãn.

| # | Lệnh | Kết quả |
|---|---|---|
| 1 | `uv run pytest -q -rs --cov` (SQLite) | 736 đạt, 2 bỏ qua (nhóm tiến trình POSIX trên Windows) |
| 2 | `docker compose --profile test run --build --rm test` (PostgreSQL) | 738 đạt, độ phủ 95,67% |
| 3 | `ruff check`, `ruff format --check`, `mypy`, `pip-audit` | sạch; không lỗ hổng đã biết |
| 4 | `python -m unittest discover -s experiments/tests` | 153 đạt |
| 5 | `npm run check`, `npm run build`, `npm run test:e2e` (API giả lập) | Vitest 84; build; Playwright 2 đạt, 4 bỏ qua (kiểm thử stack thật, dòng 7 và 9) |
| 6 | `scripts.export_openapi` so với `frontend/openapi.json`; `scripts.check_worker` | giống hệt; worker nhận cả chín profile |
| 7 | `multi-cwe-full-stack.spec` (`multi-cwe-v0.1`, công cụ thật) | đạt |
| 8 | `legacy_regression.py` (bốn profile cũ, công cụ thật) | 4/5 giống hệt; ca `command-injection-v0.1` khác đúng như mục 18.3 và lần chạy ở mục 23.6 |
| 9 | `multi-cwe-v02-full-stack`, `multi-cwe-v03-full-stack`, `multi-cwe-v05-full-stack` (PyGoat) | 3 đạt |
| 10 | Golden, thực nghiệm, công cụ, luật, profile cũ (gồm `sql-injection-v0.3`, `multi-cwe-v0.4`) | 0 tệp đổi; hash `sql-injection-v0.3` và `multi-cwe-v0.4` bằng hash đã ghim |

### 24.10 Nghiệm thu kỹ thuật, kết quả đánh giá, giới hạn

**Nghiệm thu kỹ thuật: đạt cả bốn điều.**

| Điều kiện | Kết quả | Bằng chứng |
|---|---|---|
| Một lượt quét thật chạy được cả bốn nhóm | Đạt. Đầu vào bốn nhóm: bốn nhóm `completed`, 32 đơn vị. PyGoat qua giao diện: bốn nhóm `completed`, 15 đơn vị | 24.4, 24.6 |
| CWE-78, CWE-22, CWE-89 khớp `v0.4` | Đạt trên 7/7 nguồn. Vẫn khớp khi lượt CWE-79 hết bộ nhớ (7/7) và khi tiêm lỗi (3/3) | 24.4, 24.6 |
| Cảnh báo XSS khớp CodeQL chạy riêng | Đạt: 22/22 cảnh báo trên 7/7 nguồn, cùng rule, vị trí và thông điệp, cùng băm truy vấn | 24.5 |
| SARIF giữ đủ cảnh báo gốc | Đạt: 203/203 kết quả của 7 lượt và 25/25 của lượt qua giao diện. Mỗi kết quả giữ rule, vùng, thông điệp và nhãn CWE gốc; không kết quả CWE-79 nào bị ẩn | 24.5, 24.6 |

Thêm: mọi mục CWE-79 ở danh sách rà chính, mức U, không gạn. Lượt CWE-79 lỗi hay dở giữ mọi cảnh báo
đã thu và ghi đúng trạng thái. Hồi quy đạt (24.9).

**Đánh giá trên tập có nhãn: báo riêng, không phải điều kiện nghiệm thu.** OSSF CVE Benchmark, 49 ca
XSS, giao thức băm trước khi quét:

- **Ca dương:** phát hiện 14 trên 41 ca đo được, bỏ sót 27.
  - tầng A (lời giải thích là tên một truy vấn trong phạm vi): 14/34;
  - tầng B: 0/7.
- **Ca âm:** 1 trên 41 vị trí đã vá vẫn bị báo; trong 14 ca dương được phát hiện, 1 ca âm bị báo.
- **Mục cần rà:** 387 đơn vị trên 87 commit; 372 trên 390 cảnh báo ở ngoài vị trí có nhãn.
- **Không đo được hay chạy dở:** 3 ca chạy dở, 5 ca không đo được.
- **Đọc kết quả:**
  - Nhãn không độc lập với CodeQL, vì lời giải thích dùng tên truy vấn của nó. Vì vậy 14/41 không phải
    độ nhạy độc lập.
  - Không coi được đây là cận trên: CodeQL 2.27.1 không báo gì trong 24 tệp có nhãn.
  - Phần bỏ sót không do cách ghép theo dòng.

**Giới hạn và việc tiếp theo:**

- **Một công cụ.** Nhóm CWE-79 chỉ có CodeQL; trên tập này nó bỏ sót 27/41 ca. Semgrep cho XSS và
  đối chứng SonarQube là các lượt đo sau. Mỗi lượt cần một giao thức mới và một tập chưa dùng: các
  commit OSSF ở đây đã được quét, nên không còn là tập độc lập cho phiên bản sau.
- **Chỉ JavaScript/TypeScript.** CWE-79 trên Python (template Jinja2, `Markup`, `HttpResponse`) chưa
  có.
- **Tải rà:**
  - `js/xss-through-dom` chiếm 296/390 cảnh báo trên tập có nhãn;
  - thư viện đi kèm mã cho phần lớn mục rà trên dvpwa (11/12).
  - Một điều kiện gạn cho CWE-79 (ví dụ theo thư viện đi kèm) chỉ được thêm với gói bằng chứng và lượt
    đo riêng.
- **Cảnh báo sai đã thấy trên dữ liệu phát triển:** `res.type("text/plain").send(...)`.
- **Phạm vi của ứng dụng:**
  - tệp JavaScript không đuôi không được nhận là JavaScript (D1);
  - kho vượt 50 MB không tải được.
- **Chi phí:**
  - một lượt quét nguồn GitHub phát triển mất 47–122 giây thay vì 31–75 giây của `v0.4`; riêng lượt
    CWE-79 mất 15–18 giây trên pygoat khi bộ nhớ đệm biên dịch đã có, 200–250 giây ở lượt đầu sau khi
    dựng lại worker;
  - giới hạn thời gian mềm của tác vụ tăng lên 12 600 giây; `TIME_LIMIT` còn dưới thời gian hiển thị
    lại của broker 300 giây. Một nhóm thêm nữa sẽ cần đổi cả thời gian đó.
- **Bộ nhớ:** CodeQL 2048 MB với hai luồng không đủ để biên dịch bảy truy vấn; cấu hình dùng một luồng.

## 25. Semgrep cho CWE-79: đo trên tập nhãn độc lập với CodeQL (2026-11-16)

Mốc: `multi-cwe-v0.5` và mục 24. Câu hỏi: thêm Semgrep vào nhóm `cross-site-scripting` thì tìm thêm
được bao nhiêu ca XSS đúng mà CodeQL bỏ sót trên JavaScript/TypeScript, và sau khi gộp cảnh báo
trùng, người dùng phải rà thêm bao nhiêu mục?

- **Không đổi:** mã ứng dụng, mọi profile (`multi-cwe-v0.5` vẫn là mốc), các số đo của mục 20–24.
- **Không quét lại:** các commit OSSF của mục 24.7, hay nguồn có nhãn nào khác của dự án.
- **Cách đo:** hai công cụ chạy bên ngoài lượt quét của ứng dụng, nhưng bằng adapter của chính ứng
  dụng, trong container của image worker. Không lượt quét nào của ứng dụng chạy trên tập có nhãn.

### 25.1 Rà lại 27 ca dương CodeQL bỏ sót trên OSSF

Chỉ đọc kết quả đã lưu, không quét lại. Chi tiết: `artifacts/cwe79-eval/semgrep-xss/ossf-missed-review.md`.

**Đã xác minh, cho cả 28 vị trí (27 ca):**

- **Tệp được trích xuất:** nhật ký tạo database có `Done extracting …/<tệp>` cho cả 28 tệp.
- **Không có lỗi trích xuất** trong SARIF: thông báo duy nhất về các tệp đó là
  `js/baseline/expected-extracted-files`, mức `none`.
- **Lượt phân tích hoàn tất.**
- **Không có cảnh báo CWE-79 ở dòng điểm yếu.** 24 tệp không có cảnh báo CWE-79 nào; 4 tệp có cảnh
  báo ở dòng khác.
- Ở CVE-2017-0931, dòng có nhãn nằm ngay trên điểm ghi HTML.

Vậy nguyên nhân không phải trích xuất hay lượt chạy dở.

**Phân loại theo phạm vi của bảy truy vấn.** Đây là nhận định từ đọc mã, không phải kết quả công cụ.

| Nhóm | Ca | Điều đọc được từ mã |
|---|---|---|
| K1. Đích quen thuộc, nguồn không thuộc mô hình | 13 | Điểm ghi là `innerHTML`, `.html()`, `dangerouslySetInnerHTML`, `res.send`/`res.end` hay `execCommand("inserthtml")`. Dữ liệu đến từ tham số hàm, props, dữ liệu tài liệu, thông điệp socket.io hay đối tượng lỗi của framework. |
| K2. Đích ngoài mã được quét, hoặc là cơ chế khuôn mẫu | 3 | Chỉ dựng chuỗi HTML hay khai báo ràng buộc (CKEditor `bind.to('href')`, typeahead, bộ hiển thị của CyberChef). |
| K3. Không phải luồng tới điểm ghi | 7, cả 7 ca bỏ sót của tầng B | Bộ làm sạch chưa đủ, tuần tự hóa, mXSS, URL `javascript:`. Một ca là đúng truy vấn `js/incomplete-html-attribute-sanitization` đã bị loại khỏi phạm vi. |
| K4. Chưa xác định | 4 | Ba ca bootstrap: tùy chọn plugin jQuery dùng như bộ chọn hay đích của `appendTo`. Prism: `location.href` ghép vào chuỗi gán cho `innerHTML`. Dạng mã có vẻ thuộc mô hình, nhưng truy vấn không báo, và database không được lưu để chẩn đoán. |

**Giả thuyết cho đợt đo mới:**

- **H1.** Luật Semgrep dạng mẫu báo điểm ghi bất kể nguồn, nên bắt được một phần loại K1.
- **H2.** Cũng vì vậy, Semgrep thêm nhiều mục rà, cả ở vị trí đã vá.
- **H3.** Semgrep không giúp được với K2 và K3.

### 25.2 Tập nhãn độc lập với CodeQL

Nhãn của OSSF không độc lập với CodeQL, nên tập mới lấy từ **GitHub Advisory Database**: advisory
npm có CWE-79, mỗi advisory một commit sửa lỗi do người bảo trì viết. Nhãn là vùng mã mà bản vá đổi,
không bước nào dùng CodeQL.

- **Chọn ứng viên** (`ghsa_candidates.py`, chỉ đọc metadata, 970 advisory):
  - chưa rút;
  - CWE chỉ gồm CWE-79 cùng 20, 80, 83, 87, 116;
  - đúng một tham chiếu commit đầy đủ;
  - không nhắc GitHub Security Lab hay CodeQL;
  - không thuộc OSSF, cả theo CVE lẫn theo kho;
  - kho và gói không có trong dữ liệu nào của dự án.
  - Kết quả: 313 ứng viên, 217 kho.
- **Dựng ca** (`build_cases.py 60`), theo thứ tự cố định `sha256("cwe79-semgrep-v1:" + GHSA ID)`,
  mỗi kho một ca:
  - commit sửa có một cha;
  - có tệp `.js/.jsx/.mjs/.cjs/.ts/.tsx`, không phải tệp kiểm thử hay bản dựng, với dòng bị xóa hay
    sửa;
  - các tệp đó đổi tổng cộng ≤ 150 dòng;
  - snapshot qua giới hạn và phép kiểm `unpack` của ứng dụng.
  - Đã xét 122 ứng viên để có **60 ca, 60 kho, 104 tệp có nhãn, 120 snapshot**.
- **Nhãn:**
  - **vùng dương:** các dòng bản vá xóa hay sửa trên commit trước bản vá, mở rộng 3 dòng mỗi phía,
    trung vị 25 dòng mỗi ca;
  - **vùng âm:** các dòng bản vá thêm hay sửa trên commit bản vá.
- **Hai lần dựng trước bị thay trước khi chạy công cụ nào:** lần đầu còn trùng 4 kho và 2 commit
  OSSF đã quét; lần hai còn một ca vượt 200 MB khi giải nén.

### 25.3 Giao thức

`artifacts/cwe79-eval/semgrep-xss/PROTOCOL-SEMGREP-XSS.md`.

- sha256 `768a447d2f95e369c9c939c28e80635fac1265ff0fb5cee61810b809a64e09a4`, chốt
  2026-11-16T16:27:53Z, trước lượt chạy công cụ đầu tiên trên tập này.
- `PROTOCOL-SEMGREP-XSS.sha256` băm 29 tệp: các script chọn, dựng, chạy và chấm; danh sách ca, việc
  và luật; trang API; tệp nén luật Semgrep. `run_measure.sh` kiểm các băm đó, bản sao container
  đọc, mã image worker và băm của 120 snapshot trước khi chạy.

**Hai cấu hình**, cùng snapshot, image `security-triage-worker:v05-measure`, adapter của ứng dụng:

- **C, CodeQL:** `run_codeql`, bảy truy vấn của `cross-site-scripting-v0.1`, một luồng, 2048 MB,
  600 giây.
- **C + S:** thêm `run_semgrep_pass`, lượt `semgrep-cross-site-scripting`, Semgrep CE 1.178.0, 600
  giây.
- **Luật Semgrep:** mọi tệp luật của `semgrep/semgrep-rules@a84ff9cc` (cây đã vendor ở P2b) có
  `metadata.cwe` nêu CWE-79 và ngôn ngữ JS/TS. Kết quả 36 tệp, mỗi tệp một luật: 23 `audit` dạng
  mẫu, 13 `vuln` dạng taint.

**Ghép với ca:**

- Cảnh báo có dòng đầu trong vùng dương là **trúng**.
- Mọi vị trí trúng được **xác nhận tay**, trên gói xét không ghi công cụ:
  - "đúng" khi dòng đó là mã có lỗ hổng mà advisory nói tới;
  - người xét là trợ lý AI thực hiện phép đo.
  - Việc giấu công cụ không trọn ở mức ca: xem D1 ở 25.4.
- Bảng chính gồm các ca không công cụ nào thất bại; bảng độ nhạy chỉ gồm ca cả hai `completed`.
- Cảnh báo ngoài vùng có nhãn giữ trạng thái chưa phân loại.

**Gộp:** hai đơn vị nối khi cùng tệp, vùng giao nhau, và mỗi vùng trải ≤ 5 dòng. Kiểm tay một mẫu
cố định tối đa 40 mục gộp trên commit trước bản vá.

**Tiêu chí tích hợp** (đạt cả hai):

- **Lợi ích:** số ca chỉ Semgrep phát hiện có xác nhận `G ≥ 3` và `≥ 10%` số ca.
- **Chi phí:** số mục rà thêm sau gộp chia `G` ≤ min(2 × số đơn vị CodeQL trên mỗi ca CodeQL phát
  hiện, 20).

### 25.4 Kết quả: CodeQL so với CodeQL + Semgrep

**Chạy:**

- 2026-11-16, 16:27:59Z đến 17:15:33Z (48 phút), ba container chạy song song, mỗi snapshot một lần.
- Không công cụ nào `failed` trên 120 snapshot. Băm của mọi tệp đã chốt vẫn khớp sau khi chạy và chấm.
- Trạng thái trên commit trước bản vá (commit bản vá cho cùng phân bố):
  - 37 ca cả hai `completed`;
  - 18 ca chỉ Semgrep `partial`;
  - 4 ca cả hai `partial`;
  - 1 ca chỉ CodeQL `partial`.
- **Một sai lệch, D1** (`PROTOCOL-SEMGREP-XSS-DEVIATIONS.md`): gói xét không ghi công cụ, nhưng
  lần chấm đầu đã in danh sách ca chỉ Semgrep trúng trước khi người xét đọc gói. Việc xét vì vậy
  không giấu được công cụ ở mức ca.

**Xác nhận tay:** 28 vị trí trúng: 25 đúng, 2 sai, 1 chưa xác định.

- Hai vị trí sai là lệnh nối một phần tử jQuery hay nút DOM, không phải chuỗi HTML.
- Vị trí chưa xác định là bước thoát ký tự HTML mà bản vá của next-auth bỏ đi.

**Ca dương, bảng chính** (60 ca, không công cụ nào thất bại):

| | Chỉ CodeQL | Chỉ Semgrep | Cả hai | Cả hai bỏ sót | CodeQL | CodeQL + Semgrep |
|---|---|---|---|---|---|---|
| Có xác nhận | 1 | **9** | 1 | 49 | **2** | **11** |
| Trúng theo cơ học | 1 | 10 | 1 | 48 | 2 | 12 |
| Độ nhạy: 37 ca cả hai `completed`, có xác nhận | 1 | 7 | 1 | 28 | 2 | 9 |
| Phụ: chỉ 13 luật `vuln`, có xác nhận | 2 | 1 | 0 | 57 | 2 | 3 |

- **CodeQL phát hiện 2 trong 60 ca:**
  - `samschurter/materialize`, với `js/html-constructed-from-input` và `js/xss-through-dom`; Semgrep
    cũng phát hiện ca này;
  - `denpiligrim/repostat`, chỉ CodeQL, `js/html-constructed-from-input` ở `dangerouslySetInnerHTML`.
- **Semgrep phát hiện thêm 9 ca:**
  - vxe-table, jupyterlab-git, QuestDB UI, lazysizes, jquery-ui, NocoDB, jquery-validation,
    GraphQL Playground, Umbraco;
  - mọi vị trí đúng của Semgrep đến từ luật dạng mẫu: `insecure-document-method` 13,
    `insecure-innerhtml` 13, `prohibit-jquery-html` 6, `jquery-insecure-method` 3;
  - ngoại lệ duy nhất là một vị trí của luật taint `raw-html-format`.
  - Giả thuyết H1 đúng cho 8 trong 9 ca thêm: điểm ghi `innerHTML`, `.html()` hay `.append()` của
    chuỗi HTML mà dữ liệu đến từ tham số, tùy chọn hay dữ liệu ứng dụng.
  - Ca thứ chín, Umbraco, có vẻ trúng tình cờ: luật `prohibit-jquery-html` khớp một template `html`
    của Lit. Dòng đó đúng là đoạn mã bản vá sửa, nên theo quy tắc đã chốt nó vẫn được ghi "đúng". Bỏ
    ca này thì `G = 8`, tiêu chí 1 vẫn đạt.
- **Ca âm:**
  - Không công cụ nào thất bại trên 60 commit bản vá. CodeQL báo 0 vị trí đã vá; Semgrep báo 6.
  - Trong 12 ca mà C + S báo trúng vị trí lỗi theo cơ học (chưa xác nhận tay), 5 vị trí đã vá vẫn
    bị Semgrep báo, vì bản vá thường giữ `innerHTML` hay `.html()` nhưng đổi dữ liệu đưa vào.
  - Trong 2 ca CodeQL phát hiện, 0 vị trí đã vá bị báo.
- **Cảnh báo ngoài vị trí có nhãn, chưa phân loại**, trên 120 commit, mỗi commit một lần:
  - CodeQL 244 trên 247 cảnh báo;
  - Semgrep 11 624 trên 11 687 cảnh báo.
- **Vì sao Semgrep `partial`** trên 22 commit trước bản vá: lỗi cú pháp ở từng tệp, ví dụ tệp đã
  thu gọn, TypeScript có decorator, fixture lỗi cố ý; và luật chạy quá giới hạn thời gian trên một
  tệp. Các tệp đó bị phân tích thiếu, các tệp khác vẫn được báo.
- **Cách ghép theo vùng có giấu bớt phát hiện không?** Kiểm sau đo: ở 49 ca cả hai bỏ sót, tìm cảnh
  báo trong tệp có nhãn của bản lỗi mà dòng của nó không còn trong tệp sau bản vá. CodeQL: 0 ca;
  Semgrep: 1 ca (`posthoc.json`). Vậy quy tắc vùng hầu như không giấu phát hiện nào. Dù vậy, "2/60"
  và "+9" vẫn chỉ là cận dưới theo quy tắc ghép đã chốt.
- **Thời gian quét**, mỗi snapshot:
  - CodeQL: trung vị 30,8 giây, tổng 5 412 giây;
  - Semgrep: trung vị 9,7 giây, tổng 2 014 giây, tức thêm khoảng 37% thời gian công cụ.

### 25.5 Hiệu quả gộp

Trên cùng các cảnh báo đã lưu, đếm trên 60 commit trước bản vá:

| | Đơn vị CodeQL | Đơn vị Semgrep | C + S trước gộp | C + S sau gộp | Sau gộp, chỉ luật `vuln` |
|---|---|---|---|---|---|
| 60 commit trước bản vá | 123 (125 cảnh báo) | 5 288 (5 855 cảnh báo) | 5 411 | 5 280 | 204 |
| Cả 120 commit | 243 | 10 564 | 10 807 | 10 544 | 404 |

- **Gộp bớt:** 131 mục trên commit trước bản vá, 2,4%. 104 mục gộp từ hai đơn vị trở lên, trong đó
  57 mục nối một cảnh báo CodeQL với cảnh báo Semgrep.
- **Truy vết** (`posthoc.py`, `units-export.json`):
  - mọi mục sau gộp của 120 commit được xuất kèm mã gốc, công cụ, luật và vùng của từng cảnh báo:
    10 544 mục, 11 934 cảnh báo;
  - mỗi cảnh báo nằm trong đúng một mục;
  - số cảnh báo đã lưu của mỗi công cụ bằng số kết quả trong SARIF đã lưu;
  - mỗi mã gốc `<lượt>:<run>:<chỉ số>` trỏ đúng một kết quả SARIF cùng luật, cùng dòng.
- **Kiểm tay 40 mục gộp** (`merge-review.md`): **47 liên kết, 36 đúng, 11 sai, 0 chưa xác định.**
  Hai kiểu sai lặp lại:
  - một cảnh báo ở bộ chọn `$(...)`, cảnh báo kia ở nội dung được ghi bằng `.html()`, `.append()`,
    `.after()` hay `.before()` trong cùng câu lệnh;
  - hai template `html` lồng nhau.
  - Cả hai kiểu đều do vùng báo của một luật Semgrep phủ cả câu lệnh: chỉ dựa vào giao vùng thì không
    tách được hai điểm ghi trong cùng một câu.
- **Kết luận về gộp:** gộp đúng phần lớn cặp CodeQL–Semgrep cùng một điểm ghi, nhưng chỉ bớt 2,4% số
  mục. Khối mục thêm của Semgrep nằm ở những điểm CodeQL không báo, nên gộp không làm nó nhỏ đi.

### 25.6 Quyết định về Semgrep

Tính trên 60 ca của bảng chính, như giao thức đã chốt:

| Tiêu chí | Giá trị | Ngưỡng | Kết quả |
|---|---|---|---|
| 1. Số ca chỉ Semgrep phát hiện có xác nhận `G` | 9 (15%) | ≥ 3 và ≥ 10% (6) | **đạt** |
| 2. Mục rà thêm sau gộp trên mỗi ca thêm | (5 280 − 123) / 9 = **573** | min(2 × 123/2, 20) = **20** | **không đạt** |

**Quyết định: không tích hợp Semgrep. Giữ CodeQL (`cross-site-scripting-v0.1` trong `multi-cwe-v0.5`)
làm cấu hình chính cho XSS.** Không tạo profile mới.

**Các phép kiểm sau đo**, không đổi quyết định:

- **Khối mục thêm tập trung ở vài kho:**
  - 74% cảnh báo Semgrep trên commit trước bản vá đến từ 5 commit nhiều jQuery;
  - `jquery-insecure-selector` 2 629 và `prohibit-jquery-html` 1 758, trên 5 855 cảnh báo.
- **Bỏ bớt commit nặng nhất, tiêu chí 2 vẫn không đạt:** bỏ 2 commit thì 179 mục mỗi ca thêm, bỏ 5
  commit thì 114, đều trên trần 20. Trung vị là 7 mục thêm mỗi commit.
- **Chỉ 13 luật `vuln`:** thêm 81 mục sau gộp nhưng chỉ tìm thêm 1 ca, nên không đạt tiêu chí 1.
- **Gộp sai làm giảm `U_CS`:** 11 trên 47 liên kết của mẫu là sai, nên con số 573 hơi thấp hơn thực
  tế.
- **Bộ luật hẹp hơn:** chỉ là giả thuyết. Mọi đề xuất bộ luật Semgrep hẹp hơn rút từ kết quả này cần
  một tập nhãn mới, vì tập này đã bị lộ.

**Đọc kết quả:**

- Semgrep có tìm thêm ca đúng mà CodeQL bỏ sót: 9 ca, so với 2 ca CodeQL tìm được trên cùng tập.
- Nhưng các ca đó đến từ luật dạng mẫu báo mọi điểm ghi HTML không phải hằng. Cái giá là hàng nghìn
  mục chưa phân loại, và vẫn báo ở chỗ đã vá. Đúng như H2.
- Tập này cũng cho thấy CodeQL bỏ sót phần lớn ca XSS có nhãn độc lập: 58/60 ca không được CodeQL phát
  hiện.

### 25.7 Lệnh, phiên bản, đầu ra

**Phiên bản:**

- image `security-triage-worker:v05-measure`
  (`sha256:57bc147c1d5514c1766baae7e88529d17704b224d09a98fcfa507ed8d7e689ff`), mã ứng dụng
  `93c658820937f424`;
- CodeQL 2.27.1, `codeql/javascript-queries` 2.4.6, bảy truy vấn của `cross-site-scripting-v0.1`;
- Semgrep CE 1.178.0, 36 tệp luật của `semgrep/semgrep-rules@a84ff9cc`.

**Lệnh, chạy từ gốc repo, thư mục `artifacts/cwe79-eval/semgrep-xss/`:**

1. **Rà OSSF:** `python artifacts/cwe79-eval/semgrep-xss/fetch_missed.py`, rồi
   `python -I …/review_missed.py`.
2. **Tập nhãn:**
   - lấy 10 trang API vào `ghsa/`;
   - `python -I …/ghsa_candidates.py`;
   - `python -I …/build_cases.py 60`;
   - kiểm `unpack` (`preflight.json`).
3. **Luật Semgrep:** `uv run --no-project --with pyyaml==6.0.3 python …/select_xss_rules.py artifacts/multi-cwe-p2b/upstream/tree`.
4. **Chạy:** `bash artifacts/cwe79-eval/semgrep-xss/run_measure.sh`. Lệnh này kiểm băm, rồi chạy
   `measure_runner.py` trong ba container.
5. **Chấm:**
   - `python -I …/score.py` xuất `score-hit-packets.txt`;
   - xét tay vào `hit-review.json`;
   - `python -I …/score.py --review=hit-review.json`;
   - kiểm tay gộp vào `merge-review.md`.

**Đầu ra** (không vào git):

- `ossf-missed-review.md`, `review/`;
- `candidates.json`, `cases.json`, `build-log.json`, `archives/`, `repos/`;
- `PROTOCOL-SEMGREP-XSS.md`, `.sha256` và `-DEVIATIONS.md`;
- `runs/`;
- `score.json`, `score.txt`, `score-hit-packets.txt`, `hit-review.json`, `hit-review-notes.json`;
- `score-merge-sample.txt`, `merge-review.md`;
- `posthoc.py`, `posthoc.json`, `units-export.json` (phân tích sau đo và bản xuất mọi mục gộp);
- `rehearsal/`.

### 25.8 Giới hạn

- **Nhãn từ bản vá, không từ vị trí lỗi được xác minh:**
  - vùng dương rộng, trung vị 25 dòng;
  - bản vá làm sạch dữ liệu ở xa điểm ghi thì điểm ghi nằm ngoài vùng.
  - Xác nhận tay loại các lần trúng tình cờ, nhưng không tìm lại các ca bị bỏ vì vùng lệch.
- **Một người xét, là trợ lý AI thực hiện phép đo**, không phải chủ đề án.
  - Gói xét không ghi công cụ, nhưng người xét đã thấy danh sách ca chỉ Semgrep trúng (D1).
  - Dạng mã ở dòng trúng cũng có thể gợi ý công cụ.
- **Ca âm** là vị trí đã vá, không phải mã an toàn bất kỳ.
- **Tập nhỏ:** 60 kho npm, mỗi kho một advisory. Phân bố khối mục thêm lệch mạnh về vài kho dùng
  nhiều jQuery.
- **Ngoài phạm vi:**
  - Semgrep chỉ dùng luật upstream ở commit đã ghim, không thử luật viết riêng hay tinh chỉnh;
  - không đo SonarQube và CWE-79 cho Python.
- **Đã chạy công cụ:** 120 commit này đã được chạy bằng CodeQL và Semgrep, nên tập không còn độc lập
  cho phiên bản sau của hai cấu hình này.

## 26. Nhóm CWE-918 cho Python và JavaScript/TypeScript: profile `multi-cwe-v0.6` (2026-11-17)

Profile ghép thử nghiệm `multi-cwe-v0.6`: bốn nhóm của `multi-cwe-v0.5` cộng nhóm **server-side
request forgery (CWE-918, SSRF)** cho Python và JavaScript/TypeScript, chỉ bằng CodeQL, chỉ phát hiện
và giữ: mọi cảnh báo SSRF vào danh sách rà chính.

- **Mốc đối chứng:** `multi-cwe-v0.5` ở commit `5a47d4e`, chạy trên image worker của commit đó (mã ứng
  dụng `93c658820937f424`, image `security-triage-worker:v05-measure`
  `sha256:57bc147c…`) trước mọi thay đổi mã (26.3).
- **Không đổi:** `multi-cwe-v0.5` và bốn thành viên của nó (cùng manifest, cùng hash), các profile đã
  khóa, golden, dữ liệu nghiên cứu, các số đo của mục 20–25.
- **Không quét lại:** nguồn có nhãn của CWE-89 (BenchmarkPython, Juice Shop, SVEN), các commit OSSF
  của mục 24.7, tập GHSA của mục 25, các cặp đã đóng băng hay giữ lại. Hai commit rendertron của
  tập SSRF đã được quét ở mục 24.7; phép đo SSRF dùng lại byte snapshot đã lưu và chỉ chạy truy vấn
  CWE-918 trên đó, không chạy lượt quét nào của ứng dụng (26.8).

### 26.1 Thành viên CWE-918 (`ssrf-v0.1`)

Đặc tả: [profiles/ssrf-v0.1/DETECTION.md](../../profiles/ssrf-v0.1/DETECTION.md).

- **Kiểu:** profile `detection` schema 1, cấu hình Python và JavaScript. Dùng lại nguyên đường xử lý
  của `sql-injection-v0.1` và `cross-site-scripting-v0.1`: lượt có tên trên database dùng chung của mỗi
  ngôn ngữ, `detection.keep_detected`, mỗi vị trí được báo là một đơn vị mức U, quyết định
  `K10_DETECTED_KEPT`, lý do giữ `no_filter_condition_for_family`.
- **Tên nhóm `ssrf`, lượt `codeql-ssrf`:** tên lượt được lưu ở cột `tool_runs.tool` (`String(32)`);
  `codeql-server-side-request-forgery` dài 34 ký tự, PostgreSQL sẽ từ chối. Không thêm migration.
- **Chọn truy vấn theo nội dung kiểm tra,** không theo nhãn CWE. Đã đọc tệp `.ql` và thư viện
  `*RequestForgery*Query.qll` mà chúng nhập, trong đúng gói CodeQL 2.27.1 của worker. Điều kiện chọn:
  một yêu cầu mạng do máy chủ gửi có URL phụ thuộc vào dữ liệu từ xa mà máy chủ nhận.

| Ngôn ngữ | Rule | Điều truy vấn kiểm | Độ chính xác (gói) | sha256 của tệp `.ql` |
|---|---|---|---|---|
| Python | `py/full-ssrf` | mọi phần URL đến từ nguồn từ xa | cao; `code-scanning` | `f48ee50c…` |
| Python | `py/partial-ssrf` | một phần URL đến từ nguồn từ xa; loại trừ đúng các yêu cầu `py/full-ssrf` báo | trung bình; chỉ `security-extended` | `799f1218…` |
| JavaScript/TypeScript | `js/request-forgery` | URL phụ thuộc vào nguồn `isServerSide()`; chỉ tiền tố hằng có `?` hay `#` chặn luồng | cao; `code-scanning` | `935b8e54…` |

| Truy vấn mang nhãn `cwe-918` nhưng không chọn | Lý do |
|---|---|
| `js/client-side-request-forgery` | Nguồn là dữ liệu phía trình duyệt (`not isServerSide()`): yêu cầu do trình duyệt gửi, không phải SSRF phía máy chủ. Đây đúng là trường hợp nhãn CWE dùng chung cho một kiểu cảnh báo khác |
| `javascript/ssrf` (thử nghiệm) | Không thuộc bộ chuẩn nào; nguồn gồm cả nguồn phía trình duyệt |
| `javascript/ssrf-ipv6-transition-incomplete-guard` (thử nghiệm) | Kiểm chất lượng hàm chặn địa chỉ nội bộ, không kiểm luồng tới yêu cầu |

- **CWE ánh xạ:** chỉ CWE-918, đúng nhãn `external/cwe/*` của ba truy vấn; nhãn gốc `cwe-918` giữ ở
  `reported_cwes`.
- **Cấu hình chạy:** mỗi ngôn ngữ một lượt `database analyze` (`--rerun`), `--threads 1`,
  `--ram=2048`, giới hạn 600 giây. Một luồng như CWE-79 (hai luồng đã làm CodeQL hết bộ nhớ khi biên
  dịch, mục 24.4).
- **Một chỗ sửa chữ trong đặc tả trước khi chốt,** không đổi hành vi. Bản đầu viết rằng
  `js/request-forgery` coi tiền tố hằng cố định máy chủ đích là chặn luồng, nên không báo trường hợp
  chỉ đường dẫn bị điều khiển. Lần chạy thử bộ chấm trên dữ liệu phát triển cho thấy nó có báo
  (`fetcher.js:29`). Đọc lại `UrlConcatenation.qll`: chỉ tiền tố có `?` hay `#`, hoặc gốc URL không
  biết và không kết thúc bằng `/`, mới chặn luồng. Đặc tả được sửa (cả câu về cấu hình luồng của hai
  truy vấn Python), image được dựng lại, và mọi lượt nghiệm thu được chạy lại trên image cuối (26.4).
  Băm manifest cuối: `ssrf-v0.1` `08c5eff0319a4d0c2a7bf5be50d089eeab7a488ff12afe1d52414b1275786ae3`,
  `multi-cwe-v0.6` `a51674f34d42b387d069133816d316c7739969543a29cd915c55e4cc6152c120`.

### 26.2 Thay đổi mã

- `families.py`: nhóm `ssrf` (CWE-918, `DetectionProfile`) và profile thành viên `ssrf-v0.1`. Không có
  mã xử lý riêng cho nhóm này.
- `config.py`, `schemas.py`: profile `multi-cwe-v0.6` và giá trị `ssrf` của `FamilyName`;
  `frontend/openapi.json` và `api-schema.d.ts` xuất lại.
- **Giới hạn thời gian, đổi cùng nhau:**
  - trường hợp xấu nhất của `multi-cwe-v0.6` là 13 560 giây (`v0.5`: 12 360, cộng hai lượt 600 giây,
    một cho mỗi ngôn ngữ);
  - `task.SOFT_TIME_LIMIT` từ 12 600 lên 13 800 giây; `TIME_LIMIT` thành 15 300 giây;
  - `celery_app` `visibility_timeout` từ 4 giờ (14 400 giây) lên 5 giờ (18 000 giây), vì
    `TIME_LIMIT` phải nằm dưới nó. Mục 24.10 đã ghi trước rằng nhóm thêm sau CWE-79 sẽ cần đổi thời
    gian này. Hệ quả: một tác vụ của worker chết giữa chừng được giao lại sau 5 giờ thay vì 4.
- Giao diện: lựa chọn "CWE-78 + CWE-22 + CWE-89 + CWE-79 + CWE-918 · Thử nghiệm: thêm SSRF cho Python
  và JavaScript/TypeScript" và nhãn nhóm "CWE-918 · Server-side request forgery (SSRF)".
- Kiểm thử:
  - `test_ssrf_family.py`, 19 ca: profile thành viên và profile ghép; giới hạn thời gian so với
    `visibility_timeout`; với từng ngôn ngữ, bốn nhóm cũ giống `v0.5` trên cùng công cụ giả lập, mọi
    cảnh báo SSRF ở nhóm riêng và không bị gạn, cảnh báo SSRF trùng vị trí cảnh báo CWE-78 hay CWE-22
    vẫn là đơn vị riêng, ba kiểu lỗi của lượt SSRF; rule không ghim; qua worker, API, báo cáo và
    SARIF cho một lượt quét có cả Python và JavaScript; lượt SSRF Python thất bại trong khi lượt
    JavaScript hoàn tất;
  - hai ca giao diện;
  - `multi-cwe-v06-full-stack.spec.ts`: từ chọn profile tới tải SARIF, trên stack thật.

### 26.3 Mốc `v0.5` trước khi sửa

Chạy `multi-cwe-v0.5` trên tám nguồn phát triển không nhãn, bằng image của `5a47d4e`, trước khi sửa
mã. Kết quả lưu ở `artifacts/cwe918-eval/baseline-v05/`: lượt quét, mọi đơn vị kèm cảnh báo, quyết
định gạn và trạng thái bằng chứng, báo cáo trước–sau, SARIF; `MANIFEST.txt` ghi image, mã ứng dụng
và băm snapshot.

- **Bảy nguồn của mục 24**, cùng snapshot: đầu vào bốn nhóm, nguồn tổng hợp ba nhóm, pygoat, vulpy,
  DSVPWA, dvpwa, NodeGoat.
- **Đầu vào phát triển năm nhóm, mới** (`artifacts/cwe918-eval/dev-input/five-families/`, snapshot
  `60b11e05…`): sáu tệp của đầu vào bốn nhóm, thêm bốn tệp:
  - `fetch_app.py` (Flask): URL toàn phần từ tham số với `requests` và `urllib`; chỉ đường dẫn bị điều
    khiển; URL hằng; URL kiểm theo danh sách cho phép; một yêu cầu và một lệnh `os.system` (CWE-78)
    trên cùng dòng;
  - `fetcher.js` (Express): URL toàn phần với `axios` và `http.get`; máy chủ bị điều khiển; chỉ đường
    dẫn bị điều khiển; URL hằng; một yêu cầu và một truy vấn SQL (CWE-89) trên cùng dòng;
  - `proxy.ts`: SSRF trong TypeScript và một URL hằng;
  - `public/loader.js`: mã trình duyệt gửi yêu cầu theo URL của trang (client-side request forgery):
    nhóm CWE-918 không được báo ở đây.
- **Mốc tái lập được:** trên bảy nguồn chung, bốn nhóm của mốc mới giống hệt các lượt `v0.5` đã ghi ở
  mục 24 (`reproduce_checks.py`).

### 26.4 Đối chứng 1: bốn nhóm cũ so với `v0.5`

So theo nội dung như mục 24.4 (`compare_v06.py`, đầu ra `compare-v06.txt`): mọi đơn vị với quyết định,
lý do, trạng thái bằng chứng và cảnh báo (lượt, rule, tệp, vùng, nhãn CWE); báo cáo của nhóm; các kết
quả SARIF của nhóm; bản ghi nhóm của lượt quét. Lượt `v0.6` chạy trên image cuối
(`security-triage-worker:v06-measure`, `sha256:272b8a94…`, mã ứng dụng `44c40c82092811be`).

| Nguồn | Trạng thái `v0.5` → `v0.6` | Đơn vị CWE-78 / 22 / 89 / 79 | Bốn nhóm giống `v0.5` | `v0.5` dựng lại giống mốc | Cảnh báo / đơn vị CWE-918 |
|---|---|---|---|---|---|
| năm nhóm (tổng hợp) | completed → completed | 9 / 3 / 16 / 7 | có | có | 11 / 11 |
| bốn nhóm (tổng hợp) | completed → completed | 8 / 3 / 14 / 7 | có | có | 0 / 0 |
| ba nhóm (tổng hợp) | completed → completed | 7 / 3 / 12 / 0 | có | có | 0 / 0 |
| pygoat | completed → completed | 4 / 3 / 5 / 3 | có | có | 1 / 1 |
| vulpy | completed → completed | 1 / 1 / 6 / 0 | có | có | 0 / 0 |
| DSVPWA | completed → completed | 3 / 2 / 2 / 1 | có | có | 0 / 0 |
| dvpwa | completed → completed | 0 / 0 / 1 / 11 | có | có | 0 / 0 |
| NodeGoat | partial → partial (Semgrep, như `v0.3`) | 1 / — / 2 / 0 | có | có | 1 / 1 |

- **Đối chứng của phép đối chứng:** `v0.5` cũng được quét lại trên image mới (`dev-v05-new-image/`).
  Nó giống mốc, nên mã mới, kể cả giới hạn thời gian và thời gian hiển thị lại mới, không đổi gì ở
  `v0.5`.
- **Không cần nới phép so:** lần này CodeQL ghi `codeFlows` theo cùng thứ tự ở mọi nguồn; phép so
  theo thứ tự ghi của P2b cũng cho "giống".
- **Lô trên image đầu (spec1):** cùng tám nguồn, cùng phép so, cũng đạt cả tám (`compare-v06-spec1.txt`).
  Lô cuối giống lô đầu trên cả năm nhóm; khác duy nhất là hai băm của đặc tả `ssrf-v0.1`
  (`policy_sha256` của mỗi đơn vị CWE-918 và `profile_sha256` của nhóm). Đối chứng `v0.5` của hai image
  giống nhau (`reproduce_checks.py`, `reproduce-checks.json`).
- **Một database cho mỗi ngôn ngữ, dùng chung:** trong cả tám lượt và lượt qua giao diện (26.10), mỗi
  ngôn ngữ có đúng một bước `codeql-create`, và bước đó ghi phục vụ cả nhóm `ssrf` bên cạnh các nhóm
  khác; lượt `codeql-ssrf` chỉ chạy truy vấn trên database đó (`db_reuse.py`, `db-reuse.txt`).
- **Mọi cảnh báo CWE-918:**
  - thuộc một trong ba rule, đến từ lượt `codeql-ssrf` của đúng ngôn ngữ;
  - nằm trong đúng một đơn vị của nhóm mình, mức U, `K10_DETECTED_KEPT`, danh sách rà chính, trạng
    thái bằng chứng "chưa đủ"; CWE ánh xạ `CWE-918`, nhãn gốc `cwe-918`;
  - không bị gạn, không có `suppressions`.
- **Trên đầu vào năm nhóm:**
  - Python 5 cảnh báo: `py/full-ssrf` ở URL toàn phần với `requests` (dòng 17) và `urllib` (22), ở
    dòng có cả lệnh `os.system` (49), và **ở ca danh sách cho phép** (43); `py/partial-ssrf` ở ca chỉ
    đường dẫn bị điều khiển (28). Không báo URL hằng.
  - JavaScript/TypeScript 6 cảnh báo `js/request-forgery`: `axios` (14), `http.get` (19), máy chủ bị
    điều khiển (23), chỉ đường dẫn bị điều khiển (29), dòng có cả truy vấn SQL (41), `proxy.ts:10`.
    Không báo URL hằng ở cả hai tệp.
  - Không cảnh báo nào ở `public/loader.js` (yêu cầu do trình duyệt gửi).
  - Cảnh báo SSRF ở dòng 49 của `fetch_app.py` là đơn vị riêng, cạnh đơn vị CWE-78 (P1) cùng dòng; ở
    dòng 41 của `fetcher.js` là đơn vị riêng, cạnh hai đơn vị CWE-89 cùng dòng.
  - **Một cảnh báo sai trên dữ liệu phát triển:** ca `if url not in ALLOWED: abort(400)` vẫn bị báo;
    CodeQL không coi phép kiểm danh sách đó là chặn luồng.
- **Trên mã thật:** 2 cảnh báo. PyGoat: `py/full-ssrf` ở `dockerized_labs/ssrf_lab/app.py:37` (bài thực
  hành SSRF của dự án). NodeGoat: `js/request-forgery` ở `app/routes/research.js:16` (lỗ hổng SSRF có
  chủ đích của NodeGoat). vulpy, DSVPWA, dvpwa: 0.

### 26.5 Đối chứng 2: CWE-918 so với CodeQL chạy riêng

`standalone_codeql_ssrf.sh` chạy riêng CodeQL bên ngoài ứng dụng, cho từng ngôn ngữ có lượt
`codeql-ssrf`:

- trong một container dùng một lần của image worker (cùng bundle CodeQL, cùng gói truy vấn);
- trên đúng tệp nén snapshot mà ứng dụng đã quét, giải nén như worker;
- tạo database mới của ngôn ngữ đó với tham số của `run_codeql` (một luồng, 2048 MB), rồi chạy đúng
  các truy vấn của `ssrf-v0.1` cho ngôn ngữ đó với tham số của `run_codeql_evidence`.

Không dùng chung database, không có lượt nào khác. So theo tập bội (rule, tệp, dòng/cột đầu, dòng/cột
cuối) giữa SARIF của lượt `codeql-ssrf` cùng ngôn ngữ trong SARIF hợp nhất của ứng dụng và SARIF của
CodeQL chạy riêng; thêm: các đơn vị đã lưu bằng đúng tập đó, thông điệp từng kết quả bằng nhau, nhãn
CWE của từng kết quả bằng tag `external/cwe/*` của rule, băm truy vấn bằng băm đã ghim
(`compare_standalone.py`, đầu ra `compare-standalone.json`).

| Nguồn | Python: ứng dụng / chạy riêng | JavaScript: ứng dụng / chạy riêng | Giống nhau | Thông điệp, nhãn CWE, băm truy vấn |
|---|---|---|---|---|
| năm nhóm | 5 / 5 (`py/full-ssrf` 4, `py/partial-ssrf` 1) | 6 / 6 | có | giống |
| bốn nhóm | 0 / 0 | 0 / 0 | có | giống |
| ba nhóm | 0 / 0 | 0 / 0 | có | giống |
| pygoat | 1 / 1 | 0 / 0 | có | giống |
| vulpy | 0 / 0 | 0 / 0 | có | giống |
| DSVPWA | 0 / 0 | 0 / 0 | có | giống |
| dvpwa | 0 / 0 | 0 / 0 | có | giống |
| NodeGoat | — (không có tệp Python) | 1 / 1 | có | giống |

- 15 lượt chạy riêng theo ngôn ngữ, 13/13 cảnh báo, cùng rule, vị trí và thông điệp. Mọi kết quả SARIF
  của lượt `codeql-ssrf` trong SARIF hợp nhất giữ nhãn gốc `cwe-918`, đúng tag của rule trong SARIF của
  CodeQL; đơn vị đã lưu chứa đúng tập cảnh báo đó.
- Năm lượt chạy riêng đầu (năm nhóm, bốn nhóm, Python của ba nhóm) chạy bằng image đầu (`v06-spec1`),
  mười lượt còn lại bằng image cuối; hai image có cùng bundle CodeQL, và băm truy vấn của cả 15 lượt
  bằng băm đã ghim. Một lượt bị dừng giữa chừng (JavaScript của ba nhóm) được xóa hết tệp và chạy lại.
- **Chi phí:** CodeQL chạy riêng, không có bộ nhớ đệm biên dịch, mất 43–55 giây cho bước phân tích
  Python và 70–81 giây cho JavaScript.

- SARIF giữ đủ cảnh báo gốc, theo từng kết quả, trên mọi nhóm của tám lượt `v0.6`
  (`sarif_preserved_v06.py`, đầu ra `sarif-preserved-v06.json`): **288 kết quả SARIF, bằng đúng 288
  cảnh báo đã lưu**; mỗi kết quả giữ vùng, thông điệp và nhãn CWE của kết quả gốc; 79 rule Semgrep
  CWE-89 truy được về tệp luật đã ghim; không kết quả nào của ba nhóm chỉ phát hiện bị ẩn. Đạt cả tám.

### 26.6 Lượt CWE-918 lỗi hoặc chạy dở

**Lỗi có kiểm soát** (`ssrf_faults.py`, đầu ra `ssrf-faults.txt|json`):

- Một worker thứ hai nghe hàng đợi `faults`, có tệp bọc `codeql` đứng đầu `PATH`
  (`artifacts/cwe918-eval/fault/`), cùng image cuối.
- Tệp bọc gọi CodeQL thật, trừ đúng lỗi ghi trong `fault/mode`, và chỉ cho lệnh phân tích có truy vấn
  `CWE-918` của ngôn ngữ đã chọn: chỉ Python, chỉ JavaScript, hay cả hai. Lỗi một ngôn ngữ trong khi
  ngôn ngữ kia hoàn tất là trường hợp mới của nhóm này: nhóm CWE-79 chỉ có một ngôn ngữ.
- Nguồn: đầu vào năm nhóm. Mỗi lượt lỗi được so theo nội dung với một lượt sạch chạy cùng cách: bốn
  nhóm kia (đơn vị, báo cáo, SARIF, bản ghi nhóm), và cảnh báo CWE-918 của từng ngôn ngữ.

| Lỗi tiêm vào | Ngôn ngữ bị lỗi | Lượt quét | Lượt `codeql-ssrf` Python / JS | Nhóm CWE-918 | Bốn nhóm kia |
|---|---|---|---|---|---|
| không lỗi | — | `completed` | completed / completed | 11 cảnh báo (5 + 6), 11 đơn vị `K10_DETECTED_KEPT`, "chưa đủ" | 9, 3, 16, 7 đơn vị |
| thoát lỗi, chưa ghi SARIF | Python | `partial` | failed / completed | 6 cảnh báo JS giống lượt sạch; 0 của Python | giống lượt sạch |
| | JavaScript | `partial` | completed / failed | 5 cảnh báo Python giống lượt sạch; 0 của JS | giống lượt sạch |
| | cả hai | `partial` | failed / failed | 0 cảnh báo | giống lượt sạch |
| ghi SARIF rồi thoát lỗi | Python | `partial` | failed / completed | 11 cảnh báo giống lượt sạch: 5 của Python giữ thành `F10_FAMILY_NOT_RANKED` mức U, "không lấy được"; 6 của JS vẫn K10 | giống lượt sạch |
| | JavaScript | `partial` | completed / failed | 11 giống lượt sạch: 6 của JS thành F10, 5 của Python vẫn K10 | giống lượt sạch |
| | cả hai | `partial` | failed / failed | 11 giống lượt sạch, cả 11 thành F10 | giống lượt sạch |
| SARIF ghi lượt chạy chưa xong | Python | `partial` | partial / completed | 11 giống lượt sạch; 5 của Python là K10 với `run_incomplete`, "không lấy được" | giống lượt sạch |
| | JavaScript | `partial` | completed / partial | 11 giống lượt sạch; 6 của JS là K10 với `run_incomplete` | giống lượt sạch |
| | cả hai | `partial` | partial / partial | 11 giống lượt sạch, cả 11 K10 với `run_incomplete` | giống lượt sạch |

- **Đạt cả mười lượt.** Trong mọi lượt: mọi cảnh báo đã lưu nằm trong đúng một đơn vị và có trong
  SARIF (83, 78, 77 hay 72 kết quả), không đơn vị nào trộn hai nhóm, mọi đơn vị CWE-918 ở danh sách rà
  chính, không kết quả CWE-918 nào bị ẩn.
- Lượt quét lỗi ghi lý do theo ngôn ngữ (ví dụ `python/codeql-ssrf: failed`) và ngôn ngữ không bị lỗi
  giữ nguyên trạng thái `completed` với đúng cảnh báo của lượt sạch.
- **SARIF giữ đủ cảnh báo đã thu được:** khi lượt CWE-918 đã ghi SARIF (thoát lỗi sau khi ghi, hay
  ghi lượt chạy chưa xong), cả 11 cảnh báo vẫn có trong SARIF hợp nhất; khi lượt lỗi trước khi ghi,
  không có cảnh báo nào để giữ, và ngôn ngữ kia vẫn xuất đủ cảnh báo của nó.
- **Lượt CWE-918 treo quá giới hạn:** một lượt riêng, ở 26.7. Ứng dụng dừng lượt Python ở 600 giây
  và ghi nó là thất bại, như dòng "thoát lỗi, chưa ghi SARIF"; các nhóm khác và lượt JavaScript
  không đổi.

### 26.7 Thời gian tăng thêm và giới hạn chạy

**Lượt `codeql-ssrf`** (`report.steps`, `timing.py`, đầu ra `timing.json`):

- khi bộ nhớ đệm biên dịch của worker đã có: Python 4,5–6,3 giây, JavaScript 4,8–5,9 giây mỗi lượt,
  trên năm nguồn GitHub và nguồn tổng hợp ba nhóm;
- ở hai lượt quét đầu sau khi dựng lại worker: Python 35–38 giây, JavaScript 33–34 giây, chủ yếu là
  biên dịch truy vấn. Cùng lúc đó lượt CWE-79 mất 160–165 giây và cả lượt quét khoảng 520–540 giây,
  vì mọi truy vấn của mọi nhóm đều phải biên dịch lại.

**Cả lượt quét,** `v0.6` so với `v0.5` trên cùng image cuối, bộ nhớ đệm đã có, hai lượt quét chạy
cùng lúc trên worker:

| Nguồn | `v0.5` (giây) | `v0.6` (giây) | Tăng thêm |
|---|---|---|---|
| ba nhóm (tổng hợp) | 62,0 | 70,3 | +8,3 |
| pygoat | 68,6 | 80,3 | +11,7 |
| vulpy | 60,9 | 73,2 | +12,3 |
| DSVPWA | 64,4 | 76,5 | +12,1 |
| dvpwa | 69,5 | 79,4 | +9,9 |
| NodeGoat (chỉ JavaScript) | 40,7 | 46,2 | +5,5 |

Tức khoảng 13–20% thời gian của một lượt quét `v0.5` trên các nguồn này. Hai nguồn tổng hợp năm và
bốn nhóm của lô `v0.6` là hai lượt quét đầu sau khi dựng lại image, nên không so được ở đây.

**Giới hạn chạy:**

- `worst_case_seconds(multi-cwe-v0.6)` = 13 560 giây = `v0.5` (12 360) + 2 × 600; kiểm thử
  `test_the_time_limits_cover_the_five_family_profile_within_the_broker_timeout` giữ đẳng thức này.
- `SOFT_TIME_LIMIT` 13 800 > 13 560; `TIME_LIMIT` = 13 800 + 1 200 + 300 = 15 300; `visibility_timeout`
  18 000 > 15 300. `test_task.py` vẫn kiểm `TIME_LIMIT < visibility_timeout` và bước dài nhất ≤
  `LONGEST_SCANNER_STEP`.
- Worker khởi động lại với cấu hình mới và nhận cả mười profile (`scripts.check_worker`, 26.10).
- **Trên worker đang chạy** (image `v06-measure`; `limits_check.py` chạy trong container worker, đọc
  mã và profile đã ghim trong image; đầu ra `limits-check.json`): tác vụ `scans.run_scan` đăng ký
  giới hạn mềm 13 800 giây và giới hạn cứng 15 300 giây; `celery inspect conf` của worker cho
  `visibility_timeout` 18 000 giây; `worst_case_seconds` của cả mười profile, lớn nhất
  `multi-cwe-v0.6` 13 560 giây, đều dưới giới hạn mềm; giới hạn cứng chừa đủ bước dài nhất (1 200
  giây) và nằm dưới `visibility_timeout`. Đạt cả năm phép kiểm.
- **Thời gian thật so với giới hạn:** lượt quét `v0.6` dài nhất đã quan sát là 539 giây (lượt đầu sau
  khi dựng lại image), khoảng 4% giới hạn mềm; lượt `codeql-ssrf` dài nhất 38 giây so với giới hạn
  600 giây của nó.
- **Giới hạn của chính lượt CWE-918, trên stack thật** (`ssrf_timeout.py`, đầu ra
  `ssrf-timeout.txt|json`): tệp bọc làm lượt phân tích CWE-918 Python treo 1 200 giây, quá giới hạn
  600 giây của lượt. Ứng dụng dừng nó ở giới hạn: lượt quét `c8b2fbbd…` dài 660,3 giây, hơn lượt tham
  chiếu sạch ngay trước trên cùng worker (65,8 giây) **594,5 giây**; trạng thái `partial`, lý do
  `python/codeql-ssrf: Evidence queries produced no SARIF output`; lượt CWE-918 JavaScript `completed`
  với đúng 6 cảnh báo của lượt sạch, có trong SARIF và không bị ẩn; bốn nhóm kia giống lượt sạch theo
  nội dung; mọi cảnh báo nằm trong đúng một đơn vị. Đạt.
- Chưa kiểm chứng: một lượt quét thật chạy tới gần giới hạn mềm của cả tác vụ (13 800 giây).

### 26.8 Hiệu quả phát hiện trên tập có nhãn: chưa đủ căn cứ

Kết quả này tách khỏi nghiệm thu kỹ thuật (26.12).

**Tập có nhãn sẵn có trong dự án:**

| Nguồn | CWE-918 | Dùng |
|---|---|---|
| OSSF CVE Benchmark @`91c59fd5` (tệp nén của mục 24.7, MIT) | 3 ca, cả 3 JavaScript | có |
| OWASP BenchmarkPython (`expectedresults-0.1.csv`) | 14 hạng mục, không có SSRF | không |
| Tập GHSA của mục 25 | chỉ CWE-79 | không |
| Dữ liệu nghiên cứu đóng băng (`experiments/`) | không được quét | không |

Không có tập SSRF nào cho Python. Đợt này không dựng tập mới.

**Giao thức:** `artifacts/cwe918-eval/labeled/PROTOCOL-SSRF.md`.

- sha256 `9f1d00fa81726fc30b8cf6550a341f51c217a261976122b560736df666993ebd`, chốt
  2026-11-17T07:50:02Z, trước lượt chạy công cụ đầu tiên trên tập này.
- `PROTOCOL-SSRF.sha256` băm cùng lúc: các script chọn ca, lấy mã, chạy, chấm; danh sách ca và việc;
  bốn tệp nén; ID image worker; manifest và cấu hình `ssrf-v0.1`, manifest `multi-cwe-v0.6`; tệp nén
  của bộ dữ liệu. `run_measure.sh` kiểm các băm đó, ID image và bản sao cấu hình trong image trước khi
  chạy; sau lượt chạy, `sha256sum -c` vẫn khớp.
- **Chốt trước:** phiên bản dữ liệu (OSSF `91c59fd5`, tệp nén sha256 `df695d19…`); phạm vi (mọi ca có
  CWE-918: 3 ca, 6 commit); cách ghép (quy tắc của mục 24.7: cảnh báo `js/request-forgery` cùng tệp,
  bắt đầu đúng dòng điểm yếu; ca âm theo phép so dòng sang commit bản vá); trạng thái mong đợi: tập này
  không đủ căn cứ để kết luận, chỉ báo như mô tả.
- **Cách chạy:** không lượt quét nào của ứng dụng. Trong container của image `v06-measure`,
  `ssrf_runner.py` giải nén bằng `unpack` của ứng dụng và gọi `run_codeql` với đúng cấu hình
  JavaScript của `ssrf-v0.1`; chỉ truy vấn CWE-918 chạy. Phép chạy này tương đương lượt `codeql-ssrf`
  của ứng dụng (26.5). Mỗi commit chạy một lần (2026-11-17T08:07:37Z–08:09:37Z).
- **Hai điểm đã biết trước khi chạy:**
  - uppy: tệp nén của cả hai commit khoảng 229 MB, vượt giới hạn 50 MB của ứng dụng: không đo được;
  - rendertron: hai commit này đã được quét một lần bằng `multi-cwe-v0.5` ở mục 24.7 (ca XSS
    CVE-2017-18352/18353 cùng commit). Phép đo dùng lại byte snapshot đã lưu và không chạy lại lượt
    quét nào của ứng dụng, nên không có lượt CWE-79 mới nào trên các commit đó.
- Không sai lệch về cách chạy hay chấm (`PROTOCOL-SSRF-DEVIATIONS.md`).

**Kết quả** (`labeled/score.txt`, `score.json`):

| CVE | Kho | Trạng thái | Ca dương (dòng điểm yếu) | Ca âm (vị trí sau bản vá) | Mục rà trước / sau bản vá |
|---|---|---|---|---|---|
| CVE-2017-18354 | rendertron | đo được | **phát hiện** (`src/renderer.js:75`, `js/request-forgery`; vùng cũng chứa dòng) | **bị báo** (dòng không đổi qua bản vá) | 1 / 1 |
| CVE-2020-15152 | ftp-srv | đo được | **bỏ sót** (không cảnh báo CWE-918 nào trong commit) | không bị báo | 0 / 0 |
| CVE-2020-8205 | uppy | không đo được (vượt 50 MB) | — | — | — |

- **Ca dương:** tìm được 1, bỏ sót 1, trên 2 ca đo được; 1 ca không đo được.
- **Ca âm:** bị báo 1 trên 2 ca âm đo được.
- **Mục cần rà:** 2 đơn vị trên 4 commit (1 trước bản vá, 1 sau bản vá), cả 2 ở vị trí có nhãn; 0 cảnh
  báo ngoài vị trí có nhãn.

**Mô tả sau đo**, viết sau khi xem kết quả, không đổi số nào:

- rendertron: bản vá chỉ thêm kiểm giao thức `^https?` trong `isRestricted` (`src/main.js`); dòng 75
  của `src/renderer.js` (`Page.navigate({url: url})`) không đổi. CodeQL không coi phép kiểm đó là chặn
  luồng, và sau bản vá ứng dụng vẫn render mọi URL http(s) khi không cấu hình `renderOnly`. Ca âm bị
  báo vì vậy không hẳn là cảnh báo sai.
- ftp-srv: điểm yếu là `net.Socket.connect({host, port, family})` với host và port lấy từ lệnh `PORT`
  của kết nối điều khiển FTP. Đích không phải yêu cầu HTTP, nguồn không phải dữ liệu yêu cầu HTTP: nằm
  ngoài mô hình nguồn và đích của `js/request-forgery`.

**Vì sao chưa đủ căn cứ:**

- 2 ca đo được, 2 kho, chỉ JavaScript; Python không có ca nào.
- Nhãn không độc lập với CodeQL: cả ba lời giải thích là nguyên văn `@name` của truy vấn thử nghiệm
  `javascript/ssrf`, truy vấn không thuộc `ssrf-v0.1`.
- Ca âm là vị trí đã vá, không phải mã an toàn bất kỳ; ở rendertron bản vá không loại hẳn SSRF.

**Phần đánh giá hiệu quả còn thiếu cho CWE-918:** một tập có nhãn độc lập với CodeQL, có cả Python và
JavaScript/TypeScript, đủ lớn để báo số ca dương tìm được và bỏ sót, số ca âm bị báo và số mục rà với ý
nghĩa thống kê. Cách dựng khả thi theo mục 25: advisory CWE-918 của GitHub Advisory Database (pip và
npm), mỗi advisory một commit sửa, nhãn từ bản vá, giao thức băm trước khi chạy. Việc này cần chủ đề án
quyết định.

Đã thực hiện ở mục 27 (64 advisory GHSA, 24 Python và 40 JS/TS).

### 26.9 Phiên bản, lệnh, đầu ra

**Trạng thái mã:**

- Commit `5a47d4e` cộng thay đổi chưa commit. Cây `backend/`, `frontend/`, `profiles/`, `rules/` đã
  kiểm thử: `7b2a5273e0f16556cfbd1efcc9829788f1e75598`.
- Mã ứng dụng trong image worker: `44c40c82092811be`, giống cây làm việc.
- Image:
  - mốc: `security-triage-worker:v05-measure` (`sha256:57bc147c…`), `security-triage-api:v05-measure`;
  - cuối: `security-triage-worker:v06-measure` (`sha256:272b8a94b39275dff0ce2cb0725a02382ef6d5ecdb74675352704fd6e9f65ae1`),
    dùng cho lô cuối, CodeQL chạy riêng, lỗi tiêm, luồng giao diện và tập có nhãn;
  - đầu (đặc tả trước khi sửa chữ): `security-triage-worker:v06-spec1` (`sha256:397ececa…`).
- Hash profile:
  - `ssrf-v0.1`: `08c5eff0319a4d0c2a7bf5be50d089eeab7a488ff12afe1d52414b1275786ae3`;
  - `multi-cwe-v0.6`: `a51674f34d42b387d069133816d316c7739969543a29cd915c55e4cc6152c120`;
  - bốn thành viên còn lại và `multi-cwe-v0.5` (`11dfc981…`) không đổi.

**Công cụ:** CodeQL 2.27.1, `codeql/python-queries` 1.8.11, `codeql/javascript-queries` 2.4.6, Semgrep
CE 1.178.0, Bandit 1.9.4, ESLint 10.15.0, như `tools/pins.env`.

**Lệnh, chạy từ gốc repo** (thư mục `artifacts/cwe918-eval/`):

1. Đầu vào năm nhóm: `docker compose cp artifacts/cwe918-eval/dev-input/five-families api:/tmp/seed918/five-families`,
   `docker compose cp artifacts/cwe89-eval/seed_dir.py api:/tmp/seed918/seed_dir.py`, rồi
   `docker compose exec -T -e PYTHONPATH=/app api python /tmp/seed918/seed_dir.py cwe918-dev-five-families /tmp/seed918/five-families -- multi-cwe-v0.5`
   (kết quả `dev-input/five-families-seed.json`).
2. Mốc, trên image `v05-measure`: `python artifacts/cwe918-eval/scan_dev.py multi-cwe-v0.5 artifacts/cwe918-eval/baseline-v05 five-families=<scan> four-families three-families pygoat vulpy dsvpwa dvpwa nodegoat`.
3. Sau khi dựng lại image (`docker compose up -d --build`): cùng lệnh với
   `multi-cwe-v0.6 artifacts/cwe918-eval/dev-v06` và `multi-cwe-v0.5 artifacts/cwe918-eval/dev-v05-new-image`
   (lô đầu đã được lưu thành `dev-v06-spec1/`, `dev-v05-new-image-spec1/`).
4. Đối chứng 1: `python artifacts/cwe918-eval/compare_v06.py five-families four-families three-families pygoat vulpy dsvpwa dvpwa nodegoat`;
   lô đầu: thêm `--new=dev-v06-spec1 --control=dev-v05-new-image-spec1 --out=compare-v06-spec1`;
   tái lập: `cd artifacts/cwe918-eval && python reproduce_checks.py`.
5. Đối chứng 2: `python artifacts/cwe918-eval/compare_standalone.py five-families four-families three-families pygoat vulpy dsvpwa dvpwa nodegoat`;
   `python artifacts/cwe918-eval/sarif_preserved_v06.py`.
6. Thời gian: `python artifacts/cwe918-eval/timing.py`.
7. Lỗi tiêm: `bash artifacts/cwe918-eval/fault/start_fault_worker.sh`, rồi
   `python artifacts/cwe918-eval/ssrf_faults.py`; dừng worker: `docker rm -f fault-worker-ssrf`.
8. Tập có nhãn: `python -I artifacts/cwe918-eval/labeled/ossf_ssrf_cases.py`,
   `python -I artifacts/cwe918-eval/labeled/fetch_archives.py`; chạy thử trên dữ liệu phát triển
   (`labeled/rehearsal/`); chốt giao thức; `bash artifacts/cwe918-eval/labeled/run_measure.sh`.
9. Hồi quy: `bash artifacts/cwe918-eval/final/run_local.sh`, `bash artifacts/cwe918-eval/final/run_stack.sh`.
10. Lượt qua giao diện: `python artifacts/cwe918-eval/scan_dev.py multi-cwe-v0.6 artifacts/cwe918-eval/ui-v06 pygoat=<scan>`,
    rồi `compare_v06.py --new=ui-v06 --out=compare-v06-ui pygoat`,
    `compare_standalone.py --dev=ui-v06 --out=compare-standalone-ui pygoat`,
    `python artifacts/cwe918-eval/db_reuse.py`.
11. Giới hạn chạy: `docker compose exec -T -e PYTHONPATH=/app worker python - < artifacts/cwe918-eval/limits_check.py`,
    `docker compose exec -T worker celery -A app.workers.celery_app:celery_app inspect conf`; lượt treo:
    `bash artifacts/cwe918-eval/fault/start_fault_worker.sh`, rồi `python artifacts/cwe918-eval/ssrf_timeout.py`.

**Đầu ra** (`artifacts/cwe918-eval/`, không vào git): `dev-input/`, `baseline-v05/` (kèm
`MANIFEST.txt`), `dev-v06/`, `dev-v05-new-image/`, `dev-v06-spec1/`, `dev-v05-new-image-spec1/`,
`compare-v06*.txt|json`, `reproduce-checks.json`, `standalone/`, `compare-standalone.json`,
`sarif-preserved-v06.json`, `timing.json`, `ssrf-faults.txt|json`, `fault/`, `ui-v06/`,
`compare-v06-ui.*`, `compare-standalone-ui.json`, `db-reuse.txt`, `limits-check.json`,
`ssrf-timeout.txt|json`, `ssrf-timeout-scan.json`, `labeled/`
(`PROTOCOL-SSRF.*`, `cases.json`, `jobs.json`, `archives/`, `runs/`, `score.txt|json`, `rehearsal/`),
`final/`.

### 26.10 Hồi quy

`bash artifacts/cwe918-eval/final/run_local.sh` (đầu ra `final/run-local.txt`) và
`bash artifacts/cwe918-eval/final/run_stack.sh` (đầu ra `final/run-stack.txt`), sau lô cuối, trên cây
`7b2a5273…` và image cuối.

| # | Lệnh | Kết quả |
|---|---|---|
| 1 | `uv run pytest -q -rs --cov` (SQLite) | 756 đạt, 2 bỏ qua (nhóm tiến trình POSIX trên Windows) |
| 2 | `docker compose --profile test run --build --rm test` (PostgreSQL) | 758 đạt, độ phủ 95,67% |
| 3 | `ruff check`, `ruff format --check`, `mypy`, `pip-audit` | sạch; không lỗ hổng đã biết |
| 4 | `python -m unittest discover -s experiments/tests` | 153 đạt |
| 5 | `npm run check`, `npm run build`, `npm run test:e2e` (API giả lập) | Vitest 86; build; Playwright 2 đạt, 5 bỏ qua (kiểm thử stack thật, dòng 7 và 9) |
| 6 | `scripts.export_openapi` so với `frontend/openapi.json`; `scripts.check_worker` | giống hệt; worker nhận cả mười profile |
| 7 | `multi-cwe-full-stack.spec` (`multi-cwe-v0.1`, công cụ thật) | đạt |
| 8 | `legacy_regression.py` (bốn profile cũ, công cụ thật) | 4/5 giống hệt; ca `command-injection-v0.1` khác đúng như mục 18.3: bản lưu ngày 14/11 không có `candidate`, `adjudication`, `kept_because`, nên `evidence_state` là `not_assessed`; khóa đơn vị, mức, quyết định giống |
| 9 | `multi-cwe-v02-full-stack`, `multi-cwe-v03-full-stack`, `multi-cwe-v05-full-stack`, `multi-cwe-v06-full-stack` (PyGoat) | 4 đạt |
| 10 | Golden, thực nghiệm, công cụ, luật, profile cũ (gồm `cross-site-scripting-v0.1`, `multi-cwe-v0.5`) | 0 tệp đổi; hash của `sql-injection-v0.3`, `multi-cwe-v0.4`, `cross-site-scripting-v0.1`, `multi-cwe-v0.5` bằng hash đã ghim; mã ứng dụng của worker bằng cây làm việc (`44c40c82092811be`) |

**Luồng giao diện của `v0.6`** (`tests/e2e/multi-cwe-v06-full-stack.spec.ts`, stack thật, PyGoat): chọn
profile năm nhóm trong biểu mẫu, nguồn GitHub, gửi; trang lượt quét hiện năm nhóm, hàng CWE-918 ghi
`ssrf-v0.1`, `python: completed`, `javascript: completed`; lọc theo nhóm CWE-918, mở chi tiết đơn vị;
tải báo cáo JSON và SARIF hợp nhất. Kết quả: **đạt**. Lượt quét `2e740f05…`, `completed`; đơn vị theo
nhóm: CWE-78 4, CWE-22 3, CWE-89 5, CWE-79 3, CWE-918 1, tất cả ở danh sách rà chính; SARIF 26 kết quả,
bằng số cảnh báo đã lưu; 1 kết quả CWE-918 (`py/full-ssrf`, nhãn `cwe-918`, không bị ẩn).

**Đối chiếu chính lượt quét qua giao diện,** không quét lại (thư mục `ui-v06/`):

- snapshot do giao diện tải về có băm `19db7dc2…`, đúng snapshot PyGoat của mốc;
- bốn nhóm cũ giống mốc `v0.5` theo nội dung, cảnh báo CWE-918 qua mọi phép kiểm của 26.4
  (`compare_v06.py --new=ui-v06 --out=compare-v06-ui pygoat`: đạt);
- cảnh báo CWE-918 giống CodeQL chạy riêng trên cùng snapshot, Python 1/1, JavaScript 0/0
  (`compare_standalone.py --dev=ui-v06 --out=compare-standalone-ui pygoat`: đạt);
- tệp SARIF trình duyệt đã tải (`final/e2e-v06/report.sarif`) có đúng 26 kết quả của SARIF xuất qua
  API, cùng lượt, rule, vị trí, thông điệp và nhãn (`db_reuse.py`).

### 26.11 Năm nhóm CWE của `multi-cwe-v0.6`

Bảng dùng lại kết quả đã lưu của các đợt trước; không nhóm nào được đo lại. "Bằng chứng tích hợp" là
bằng chứng kỹ thuật (luồng quét, đối chứng, lỗi tiêm); "bằng chứng trên tập có nhãn" là số đo hiệu
quả phát hiện hay gạn, ghi kèm giới hạn của tập.

Bảng cập nhật với kết quả CWE-918 trên tập GHSA ở 27.8.

| Nhóm (thành viên) | Ngôn ngữ hỗ trợ | Công cụ đang dùng | Bằng chứng tích hợp | Bằng chứng trên tập có nhãn | Giới hạn |
|---|---|---|---|---|---|
| CWE-78 `command-injection` (`command-injection-v0.3`) | Python, JavaScript/TypeScript | Semgrep, Bandit (Python), ESLint + eslint-plugin-security (JS/TS), CodeQL; bằng chứng an toàn Semgrep và CodeQL; bộ định vị lời gọi; chính sách ưu tiên v0.2; gạn G1–G4 | Mỗi nhóm bằng lượt quét riêng profile đó trên BenchmarkPython và golden `multi-cwe-v0.1` (mục 16–18); `v0.2`…`v0.5` không đổi nhóm này (mục 20–24); `v0.6` giống `v0.5` trên 8/8 nguồn, kể cả khi lượt CWE-918 lỗi (26.4, 26.6) | Giai đoạn CWE-78 trước đây, BenchmarkPython 20 site: CodeQL 11 TP/2 FP/2 FN (research.md §3.1); 84 package npm có nhãn: 11/133 ứng viên JS là cảnh báo sai, gạn đúng 1, gạn nhầm 0; held-out `pairs-v1` (16 cặp, mở một lần): báo 9/9 vị trí lỗi đã biết, 0 bị gạn | Held-out chỉ có nhãn dương; hiệu quả gạn trên JS rất thấp; bộ định vị JS v1 chưa phủ mọi dạng bí danh |
| CWE-22 `path-traversal` (`path-traversal-v0.2`) | Python | CodeQL + gói bằng chứng an toàn v0.2 | Như CWE-78 (mục 16–18); `v0.6` giống `v0.5` trên 8/8 nguồn (26.4) | Mã thật, nhãn chủ đề án xác minh: v0.2 loại 4/43 FP (khoảng 9%), giữ 7/7 TP; Đợt B (11 cặp CVE): CodeQL không báo vị trí CVE nào (research.md §3.5, §3.10) | Chỉ Python; chỉ gạn, không tăng phát hiện; nhãn do một người xác minh, không mù |
| CWE-89 `sql-injection` (`sql-injection-v0.3`) | Python, JavaScript/TypeScript | CodeQL, Semgrep (37 file luật thượng nguồn), Bandit B608/B610/B611 (Python); gộp trong một lời gọi SQL Python và nối B608 với lời gọi | Mục 20, 21, 23; `v0.6` giống `v0.5` trên 8/8 nguồn (26.4) | BenchmarkPython 16 ca `sqli`: CodeQL 0, Semgrep 5 đúng/0 sai, Bandit 5 đúng/11 sai; Juice Shop 2 vị trí: CodeQL và Semgrep đều báo 2/2; SVEN 174 cặp: Bandit +45 ca dương/+20 ca âm; gộp `v0.4` 343 → 306 mục (mục 21, 22, 23) | Chỉ phát hiện và giữ; JS/TS chưa gộp giữa công cụ; các tập nhỏ hoặc là tập phát triển |
| CWE-79 `cross-site-scripting` (`cross-site-scripting-v0.1`) | JavaScript/TypeScript | CodeQL, 7 truy vấn `Security/CWE-079/` | Mục 24 (ba nhóm cũ giống `v0.4`, XSS giống CodeQL chạy riêng, lỗi tiêm); `v0.6` giống `v0.5` trên 8/8 nguồn (26.4) | OSSF (49 ca, nhãn không độc lập với CodeQL): 14/41 ca đo được; 60 advisory npm, nhãn độc lập: CodeQL 2/60; Semgrep thêm 9 ca nhưng 573 mục rà mỗi ca thêm, không tích hợp (mục 24.7, 25) | Chỉ JS/TS; CodeQL bỏ sót phần lớn ca có nhãn độc lập; nhiều mục rà ở thư viện đi kèm; chỉ phát hiện và giữ |
| CWE-918 `ssrf` (`ssrf-v0.1`) | Python, JavaScript/TypeScript | CodeQL: `py/full-ssrf`, `py/partial-ssrf`, `js/request-forgery` | `v0.6`: năm nhóm chạy trong một lượt quét thật, kể cả qua giao diện tới SARIF; bốn nhóm cũ giống `v0.5` trên 8/8 nguồn; 13/13 cảnh báo CWE-918 giống CodeQL chạy riêng; SARIF giữ 288/288 kết quả; 9/9 lượt lỗi tiêm theo ngôn ngữ đạt, cùng lượt sạch (26.4–26.7, 26.10) | **Chưa đủ căn cứ:** OSSF, 3 ca JavaScript (nhãn mang tên một truy vấn CodeQL thử nghiệm): 2 đo được, 1 tìm được, 1 bỏ sót, 1/2 ca âm bị báo, 2 mục rà; 1 ca vượt 50 MB; không có ca Python (26.8) | Một công cụ; chỉ yêu cầu HTTP phía máy chủ theo mô hình CodeQL (socket thô, phép kiểm danh sách cho phép hay giao thức không được nhận ra); `py/partial-ssrf` độ chính xác trung bình; JS không tách toàn phần/một phần; chỉ phát hiện và giữ |

### 26.12 Nghiệm thu kỹ thuật, trạng thái đánh giá, giới hạn

**Nghiệm thu kỹ thuật: đạt cả năm điều.**

| Điều kiện | Kết quả | Bằng chứng |
|---|---|---|
| Profile mới chạy được cả năm nhóm trong một lượt quét thật | Đạt. Đầu vào năm nhóm: năm nhóm `completed`, 46 đơn vị (CWE-918: Python 5, JavaScript 6). PyGoat qua giao diện, từ chọn profile tới tải SARIF: năm nhóm `completed`, 16 đơn vị (CWE-918: 1), SARIF 26 kết quả; chính lượt này cùng snapshot với mốc, giống `v0.5` ở bốn nhóm và giống CodeQL chạy riêng ở CWE-918. Mỗi ngôn ngữ một database dùng chung | 26.4, 26.10 |
| Bốn nhóm cũ khớp `v0.5` | Đạt trên 8/8 nguồn, ở cả lô đầu và lô cuối; vẫn khớp lượt sạch khi lượt CWE-918 lỗi hay dở (9/9 lượt lỗi: Python, JavaScript hay cả hai, ba kiểu lỗi) và khi lượt CWE-918 Python treo quá giới hạn 600 giây | 26.4, 26.6, 26.7 |
| Cảnh báo CWE-918 khớp CodeQL chạy riêng | Đạt: 13/13 cảnh báo trên 8/8 nguồn, 15 lượt theo ngôn ngữ; cùng rule, vị trí và thông điệp, cùng băm truy vấn; nhãn CWE gốc giữ nguyên | 26.5 |
| SARIF giữ đủ cảnh báo gốc | Đạt: 288/288 kết quả của 8 lượt; mỗi kết quả giữ lượt (nguồn: `codeql-ssrf` của đúng ngôn ngữ cho CWE-918), rule, vùng, thông điệp và nhãn CWE gốc; không kết quả CWE-918 nào bị ẩn. SARIF trình duyệt tải về bằng SARIF xuất qua API (26/26). Lượt CWE-918 lỗi hay dở: SARIF giữ mọi cảnh báo đã thu được | 26.5, 26.6 |
| Kiểm thử hồi quy đạt | Đạt: SQLite 756 (+2 bỏ qua), PostgreSQL 758, tĩnh sạch, thực nghiệm 153, Vitest 86, năm kiểm thử trình duyệt trên stack thật; bốn profile cũ như các lần trước; 0 tệp khóa hay golden đổi | 26.10 |

Thêm, theo yêu cầu kiểm giới hạn chạy: worker đang chạy áp đúng giới hạn mới (mềm 13 800, cứng 15 300,
`visibility_timeout` 18 000 giây), mọi profile có trường hợp xấu nhất dưới giới hạn mềm, và một lượt
CWE-918 treo bị dừng ở giới hạn 600 giây của nó mà không ảnh hưởng nhóm nào khác (26.7). Thời gian tăng
thêm khi bộ nhớ đệm đã có: 5–12 giây mỗi lượt quét.

**Trạng thái đánh giá hiệu quả phát hiện, theo nhóm** (không phải điều kiện nghiệm thu):

| Nhóm | Trạng thái |
|---|---|
| CWE-78 | Đã đo trên dữ liệu phát triển có nhãn và một tập giữ lại chỉ có nhãn dương (9/9 vị trí lỗi đã biết được báo). Chưa có tập độc lập có cả nhãn âm cho `command-injection-v0.3` |
| CWE-22 | Đã đo hiệu quả gạn trên mã thật (nhãn chủ đề án xác minh: loại 4/43 cảnh báo sai, giữ 7/7 TP). Không đo lại trong đợt này |
| CWE-89 | Đã đo trên tập phát triển có nhãn (BenchmarkPython, Juice Shop) và tập Python độc lập SVEN; các tập nhỏ; JS/TS chưa có tập độc lập |
| CWE-79 | Đã đo trên OSSF (nhãn không độc lập) và trên 60 advisory npm có nhãn độc lập (CodeQL 2/60) |
| CWE-918 | **Chưa đủ căn cứ.** Tập sẵn có duy nhất cho 2 ca đo được (JavaScript): 1 tìm được, 1 bỏ sót, 1 ca âm bị báo, 2 mục rà; Python không có ca nào. Cần một tập độc lập (26.8) |

**Giới hạn:**

- **Một công cụ.** Nhóm CWE-918 chỉ có CodeQL. Semgrep cho SSRF và đối chứng khác chưa được xét.
- **Mô hình của CodeQL:** chỉ yêu cầu HTTP do máy chủ gửi tới URL bị điều khiển; kết nối socket thô
  (như ftp-srv) nằm ngoài. Phép kiểm danh sách cho phép (`if url not in ALLOWED`) và phép kiểm giao thức
  (rendertron) không được coi là chặn luồng.
- **`py/partial-ssrf`** có độ chính xác "trung bình" theo gói; trên dữ liệu đã quét chỉ có một cảnh
  báo của nó (đầu vào tổng hợp).
- **Không phân biệt toàn phần hay một phần ở JavaScript:** một rule cho cả hai.
- **Tải rà:** trên năm nguồn GitHub phát triển chỉ có 2 cảnh báo; chưa có số đo tải rà trên kho lớn.
- **Chi phí:** thêm 5–12 giây mỗi lượt quét khi bộ nhớ đệm biên dịch đã có; trường hợp xấu nhất
  thêm 1 200 giây; thời gian hiển thị lại của broker tăng lên 5 giờ.
- **Thời gian hiển thị lại:** một nhóm thêm nữa với lượt 600 giây mỗi ngôn ngữ vẫn vừa 5 giờ (trường
  hợp xấu nhất 14 760 giây, giới hạn cứng khoảng 16 500 < 18 000), nhưng mọi thay đổi giới hạn vẫn
  phải đổi cùng lúc ba giá trị.

## 27. Đánh giá độc lập CWE-918 trên advisory GHSA (pip và npm), `multi-cwe-v0.6` (2026-11-17)

Mốc kỹ thuật là mục 26. Đợt này trả lời ba câu hỏi, tách riêng Python và JavaScript/TypeScript:

1. trên commit trước bản vá, hệ thống phát hiện được bao nhiêu ca;
2. trên commit bản vá, còn báo ở bao nhiêu vị trí tương ứng;
3. người dùng phải rà bao nhiêu mục.

- **Không đổi:** mã ứng dụng, mọi profile và mọi số đo của mục 20–26.
- **Không quét lại nguồn có nhãn đã đo.** Kho của mọi tập dữ liệu của dự án bị loại khỏi tập này.
- **Đầu ra:** `artifacts/cwe918-eval/ghsa/`, không vào git.

### 27.1 Kiểm kê và chọn ca

**Nguồn.**

- GitHub Advisory Database, `GET /advisories?ecosystem={pip,npm}&cwes=918&type=reviewed`, đủ mọi trang.
- Chốt lúc **2026-11-17T11:25:54Z** (`advisories/`).
- Kết quả: 271 advisory pip và 311 advisory npm, tức 580 advisory khác nhau; 2 advisory có ở cả hai hệ.

**Quy tắc chọn ứng viên** (`inventory.py`, chỉ đọc metadata). Loại advisory khi:

- đã rút;
- có CWE khác thuộc loại có đích riêng (path traversal, chèn mã hay lệnh, XSS, SQL injection, giải
  tuần tự, XXE, tải tệp, chèn khuôn mẫu);
- không có đúng một commit sửa với mã đầy đủ;
- nhắc GitHub Security Lab hay CodeQL;
- CVE hay kho thuộc OSSF CVE Benchmark;
- kho hay gói có trong dữ liệu của dự án.

Một commit sửa được nhiều advisory tham chiếu chỉ được tính một lần.

| | pip | npm |
|---|---|---|
| Advisory | 271 | 311 |
| Đã rút | 10 | 10 |
| CWE khác có đích riêng | 14 | 9 |
| Không có commit đầy đủ / nhiều hơn một commit | 99 / 19 | 114 / 40 |
| Nhắc GitHub Security Lab hay CodeQL | 4 | 0 |
| CVE hay kho thuộc OSSF | 0 | 6 |
| Kho hay gói trong dữ liệu dự án | 73 | 20 |
| **Trùng commit sửa với advisory trước** | 3 | 6 |
| **Ứng viên** | **49 (39 kho)** | **106 (60 kho)** |

Ở pip, 73 advisory bị loại vì trùng dữ liệu dự án. Phần lớn là kho của các đợt nghiên cứu CWE-78 trên
Python (`experiments/wave-c/inventory.json` 38, `wave-b` 9) và kho của mục 25.

**Dựng ca** (`build_cases.py 40`):

- **Thứ tự** cố định theo `sha256("cwe918-ghsa-v1:" + GHSA ID)`; trần 40 ca mỗi ngôn ngữ.
- **Commit:** commit sửa có một cha; bản vá đổi tệp mã của ngôn ngữ đó, tối đa 400 dòng.
- **Phạm vi phân tích: cả kho**, trong giới hạn của ứng dụng (50 MB, 20 000 mục, 200 MB khi giải nén).
- **Mỗi kho một ca cho mỗi ngôn ngữ.** Advisory khác của kho đã có ca không được dùng: pip 8 (vllm 4,
  lemur 3, GeoNode 1), npm 33 (openclaw 19, directus 3, ip-address 2, n8n-mcp 2, …). Vì vậy mỗi ca là một
  kho khác nhau, và nhiều advisory của một kho không bị đếm thành nhiều quan sát.

| | Python | JavaScript/TypeScript |
|---|---|---|
| Ứng viên đã xét (kho) | 48 (38) + 1 có ở cả hai hệ | 105 (59) + 1 có ở cả hai hệ |
| **Giữ** | **24 ca, 24 kho** | **40 ca, 40 kho** |
| Kho đã có ca | 8 | 33 |
| Không có đúng một cha / đổi quá 400 dòng | 5 / 5 | 6 / 5 |
| **Vượt giới hạn của ứng dụng (bị chặn)** | 3 (crewAI, label-studio, pydantic-ai) | 8 advisory, 6 kho (Rocket.Chat, backstage, angular, nocobase, next.js, budibase) |
| Không tải được / không có tệp đủ điều kiện | 1 / 2 | 1 / 1 |
| Không xét vì đã đủ 40 ca | 0 | 11 advisory của 9 kho (5 kho chưa có ca) |

- **Hai lần dựng:** ở lần đầu, 2 ứng viên không tải được vì lỗi của bộ dựng (kho thiếu remote). Dựng lại
  theo cùng quy tắc: dtale được giữ, vrite bị loại vì đổi 10 757 dòng.
- **Kiểm `unpack`:** 128 snapshot qua `unpack` của ứng dụng (`preflight-out/preflight.json`).

### 27.2 Nhãn

Nhãn được gán **trước khi chạy CodeQL** trên tập này, chỉ từ advisory, bản vá và mã của hai commit
(`LABELING.md`, `packets/`).

- **Vị trí:** lời gọi thư viện gửi yêu cầu hay mở kết nối tới đích mà kẻ tấn công điều khiển, cả khoảng
  dòng của biểu thức lời gọi trên commit trước bản vá. Nhãn `Có lỗi`, mức chắc chắn `cao` hay `trung bình`.
- **Nhãn sau bản vá** của cùng vị trí:
  - `An toàn` khi bản vá chặn đích tại lời gọi đó, kể cả khi tắt tính năng theo mặc định;
  - `Chưa xác định` khi chỉ chặn một phần.
- **Cả ca `chưa xác định`** khi commit không khớp advisory, advisory không phải SSRF phía máy chủ, hay
  không đủ căn cứ.
- **Loại điểm yếu:** `request_sink`, `validator` (thư viện kiểm tra, không gửi yêu cầu), `other` (yêu cầu
  gián tiếp: dependency, chương trình ngoài, trình duyệt, SDK). **Chỉ ca `request_sink` có nhãn vào mẫu số
  phát hiện.**
- **Ánh xạ vị trí giữa hai commit:** so dòng hai phiên bản của tệp (`difflib`). Dòng giữ nguyên ánh xạ
  sang dòng mới; dòng bị thay ánh xạ sang các dòng thay nó; dòng bị xóa không ánh xạ.
- **Người gán:**
  - người gán thứ nhất: bốn tác nhân phụ (AI), mỗi tác nhân một lô, cho 63 ca; ca dtale, thêm ở lần dựng
    thứ hai, do trợ lý chính gán;
  - người gán thứ hai: trợ lý chính (AI) gán độc lập một mẫu cố định 12 ca.
- **Đồng thuận trên 12 ca:**
  - nhãn cả ca 12/12;
  - loại điểm yếu 10/12;
  - vị trí 11/14;
  - mức chắc chắn 7/11 vị trí trùng;
  - nhãn sau bản vá 9/11 vị trí trùng.
- **Phân xử** (11 ca, kèm lý do, trước khi khóa): 7 ca của mẫu, cùng hai quy tắc nhất quán áp cho mọi lô.
  Contentful, peertube, hackmd-mcp và happy-dom chuyển sang `other`; plate chuyển nhãn sau bản vá sang
  `An toàn`. Quyết định ghi lúc 12:21:20Z, trước khi khóa lúc 12:21:51Z.

| | Python | JavaScript/TypeScript |
|---|---|---|
| Ca | 24 | 40 |
| **`request_sink` có nhãn (mẫu số chính)** | **20** (32 vị trí; 15 ca có vị trí `cao`) | **23** (72 vị trí, n8n-mcp 44; 14 ca có vị trí `cao`) |
| `other` / `validator` | 1 / 0 | 6 / 6 |
| Cả ca `chưa xác định` | 3 (TaskWeaver, django-select2, nanobot) | 5 (openclaw, specifyjs, sveltejs/kit, lobe-chat, kysely) |

Bốn ca `chưa xác định` có commit không khớp advisory (nanobot, openclaw, lobe-chat, kysely). Ba ca không
phải SSRF dù mang CWE-918 (django-select2, specifyjs, sveltejs/kit).

**Nguồn URL** (sửa đổi 1, gán trước khi đọc kết quả):

- **Người gán:** trợ lý chính và Codex, độc lập; đồng thuận 58/64; 6 ca bất đồng do trợ lý chính phân xử.
- **Phạm vi chính, Python (20 ca):** yêu cầu web 12, nội dung bên ngoài 3, tham số thư viện 2, đầu vào công
  cụ AI 2, tệp cấu hình 1.
- **Phạm vi chính, JS/TS (23 ca):** yêu cầu web 12, tham số thư viện 5, nội dung bên ngoài 4, đầu vào công
  cụ AI 1, socket 1.

### 27.3 Giao thức, detector, cách chạy

**Giao thức** (`PROTOCOL-GHSA-SSRF.md`).

- sha256 `f644076df90d75ba…`, khóa **2026-11-17T12:21:51Z**, trước lượt chạy CodeQL đầu tiên trên tập.
- `PROTOCOL-GHSA-SSRF.sha256` băm 58 tệp:
  - script chọn, dựng, chạy, chấm;
  - trang advisory;
  - danh sách ca và việc;
  - nhãn và quyết định phân xử;
  - snapshot chạy thử;
  - cấu hình `ssrf-v0.1` và `multi-cwe-v0.6`.
- 128 tệp nén được ghim bằng băm trong `cases.json`.

**Sửa đổi 1** (`PROTOCOL-GHSA-SSRF-AMENDMENT-1.md`, sha256 `5f6896d8…`).

- Khóa **12:37:25Z**, khi phép đo đang chạy nhưng **trước khi đọc kết quả nào**.
- Chỉ thêm, không đổi kết quả chính:
  - trường nguồn URL;
  - bảng 64 advisory và 21 ca báo riêng;
  - hai mẫu số;
  - phép kiểm đường dữ liệu sau đo;
  - các con số thay cho phần tổng hợp chưa đúng giao thức của `score.py`.

**Sai lệch D1** (`PROTOCOL-GHSA-SSRF-DEVIATIONS.md`).

- Codex rà `score.py` trước khi chấm, trợ lý chính kiểm lại.
- **Lệch:** phần tổng hợp của `score.py` đếm câu hỏi 2 theo ca, chưa theo vị trí; mục rà chỉ tính trên cặp
  hoàn tất; thời gian gộp theo ngôn ngữ của ca.
- **Xử lý:** `score.py` không sửa; số đúng giao thức lấy từ bản ghi chi tiết bằng `report.py`.

**Detector**, không đổi suốt đợt đo.

- Image `security-triage-worker:v06-measure` (`sha256:272b8a94…`); `run_measure.sh` kiểm ID image và băm
  cấu hình trong image.
- Cấu hình `ssrf-v0.1`:
  - CodeQL 2.27.1;
  - `py/full-ssrf`, `py/partial-ssrf` (`codeql/python-queries` 1.8.11);
  - `js/request-forgery` (`codeql/javascript-queries` 2.4.6);
  - một luồng, 2048 MB, 600 giây cho tạo database và 600 giây cho phân tích.
- **Cách chạy** (`ghsa_runner.py`):
  - adapter `run_codeql` của ứng dụng chạy trong container của image, như mục 26.8. Mục 26.5 đã cho thấy
    cách này cho cùng cảnh báo với lượt `codeql-ssrf` (13/13);
  - mỗi snapshot chạy mọi ngôn ngữ có trong nó, như ứng dụng.
- **Chạy thử** trên dữ liệu phát triển riêng (`rehearsal/`: đầu vào năm nhóm và một bản vá viết tay).

**Chạy.**

- Bốn container tách rời, mỗi snapshot một lần, 2026-11-17T12:21:57Z–13:14:46Z.
- 132 việc (4 việc làm nóng không chấm); 0 lỗi chuẩn bị, 0 lỗi hạ tầng; `reruns.json` ghi một lần kiểm
  lúc 13:14:46Z, không việc nào phải chạy lại.
- Băm của giao thức và sửa đổi vẫn khớp sau lượt chạy.

| Lượt theo ngôn ngữ của ca | Python (48 lượt) | JS/TS (80 lượt) |
|---|---|---|
| `completed` | 48 | 70 |
| `partial` | 0 | 8 (MagicMirror, n8n-mcp, happy-dom, sveltejs/kit, mỗi ca hai commit: lỗi cú pháp ở tệp không có nhãn) |
| `failed` | 0 | 2 (angular-cli, hai commit: CodeQL hết bộ nhớ khi nhập TRAP ở 2048 MB) |

### 27.4 Kết quả theo giao thức

Mẫu số chính là ca `request_sink` có nhãn với cặp đo hoàn tất.

| | Python | JavaScript/TypeScript |
|---|---|---|
| Ca đủ điều kiện | 20 | 23 |
| Cặp đo hoàn tất | 20 | 21 (2 cặp `partial`: MagicMirror, n8n-mcp, đều không phát hiện) |
| **Câu 1: phát hiện / bỏ sót** | **1 / 19** (dtale) | **2 / 19** (TerriaJS, Flowise) |
| Câu 1, mẫu số là tổng số advisory | 1/24 advisory có cảnh báo ở vị trí có nhãn | 2/40 |
| Ca phát hiện theo mức chắc chắn | 1 ca `cao` | 2 ca `cao` |
| **Câu 2: vị trí đã vá vẫn bị báo** (vị trí được phát hiện) | **1/1** (nhãn `An toàn`, ánh xạ giữ nguyên) | **2/2** (nhãn `An toàn`, ánh xạ giữ nguyên) |
| Cảnh báo trong vùng bản vá (phụ, cơ học) | 0 | 0 |
| **Câu 3: mục rà CWE-918 trên commit trước bản vá** | **5** trên 24 commit (1 ở vị trí có nhãn, **4 chưa phân loại**) | **33** trên 39 commit đo được (`completed` 31, `partial` 2; 2 ở vị trí có nhãn, **31 chưa phân loại**) |
| Commit trước bản vá có ít nhất một mục | 4/24 (tối đa 2) | 9/39 (tối đa 12, 9router) |
| Mục rà trên commit bản vá | 5 | 33 |
| Mục của ngôn ngữ còn lại trong snapshot | 0 | 0 |
| Thời gian mỗi lượt (theo ngôn ngữ của lượt): tạo DB / phân tích, trung vị | 10,3 s / 13,1 s (56 lượt, tổng 1 956 s) | 11,0 s / 14,4 s (114 lượt, tổng 6 442 s) |

**Hai mẫu số:** 1/20 ca Python có lời gọi trong kho, 1/24 advisory Python; 2/21 ca JS/TS có lời gọi
trong kho và cặp hoàn tất (2/23 ca trong phạm vi), 2/40 advisory JS/TS.

### 27.5 Bảng sau đo: nguồn URL, cả 64 advisory, đường dữ liệu

Các bảng này theo sửa đổi 1. Nguồn URL và quy tắc kiểm đường dữ liệu được chốt trước khi đọc kết quả;
việc xét đường dữ liệu làm sau đo. Không bảng nào đổi kết quả chính.

**Phát hiện theo nguồn URL** (ca phát hiện / cặp hoàn tất, phạm vi chính):

| Nguồn | Python | JavaScript/TypeScript |
|---|---|---|
| yêu cầu web | **1/12** | **2/11** (1 ca dở) |
| tham số thư viện | 0/2 | 0/5 |
| nội dung bên ngoài | 0/3 | 0/4 |
| đầu vào công cụ AI | 0/2 | 0/1 |
| tệp cấu hình | 0/1 | — |
| socket | — | 0/0 (1 ca dở) |

**21 ca ngoài phạm vi chính** (lý do; đo được nghĩa là cặp hoàn tất):

- **Python, 4 ca, đều đo được:**
  - 3 `chưa xác định`;
  - 1 `other` (PlaywrightCapture).
- **JS/TS, 17 ca:**
  - 5 `chưa xác định`: 4 đo được, sveltejs/kit `partial`;
  - 6 `other`: 5 đo được, happy-dom `partial`;
  - 6 `validator`: 5 đo được, angular-cli `failed`.
- Không ca nào trong 21 ca có cảnh báo ở vị trí có nhãn. Có cảnh báo ở chỗ khác: openclaw 4, sentry-javascript
  4, peertube 3, happy-dom 2, lobe-chat 1 (chưa phân loại).

**Đường dữ liệu của cảnh báo trúng** (`dataflow-review.json`, căn cứ là `codeFlows` trong SARIF):

| Ca | Trước bản vá | Sau bản vá | Căn cứ |
|---|---|---|---|
| dtale | khớp | khớp | `request.args["url"]` của `web_upload` → `load_csv`/`load_json`/`load_excel` → `handle_path` → `requests.get` |
| TerriaJS | khớp | khớp | `req.url` của route `/proxy/<url>` → `request(...)`; bốn đường đã ghi đều từ đây |
| Flowise | khớp | khớp | `req.query.url` của dịch vụ fetch-links → `secureFetch`; advisory nêu mọi đường dùng hàm bảo vệ, kể cả fetch-links. Đường HTTP Node của PoC (`secureAxiosRequest`) không bị báo |

Cả 3/3 ca trúng đều khớp đường advisory mô tả, ở cả hai phía. Sau bản vá, CodeQL vẫn báo cùng đường. Phép
kiểm mới (so khớp miền đúng, cờ cấu hình, sửa `isDeniedIP`) không phải barrier của truy vấn: điều này đã
xác minh trên danh sách barrier của gói đã ghim.

### 27.6 Rà lại các ca bất nhất

`posthoc-review.json`, `posthoc-material.txt`. Chỉ dùng hiện vật đã lưu và gói truy vấn đã ghim trong image.

- **Phạm vi rà:** 40 ca không được phát hiện, gồm 38 ca bỏ sót có cặp hoàn tất (19 + 19) và 2 ca JS/TS
  dở (MagicMirror, n8n-mcp).
- **Tệp có nhãn đều nằm trong database ở cả 40 ca** (`extracted-files.txt`). Trích xuất thiếu không phải
  nguyên nhân.
- **Gói đã ghim:** truy vấn chỉ nhận `ActiveThreatModelSource`, mô hình đe dọa mặc định `remote` (`request`,
  `response`). `database`, `file`, `environment`, `commandargs` thuộc `local`.
- **Không có mô hình trong gói:**
  - JS: h3/Nuxt, Hono, Cloudflare Workers, MCP SDK, ofetch, undici;
  - Python: swob, MCP/fastmcp, `acme`.
- **Có mô hình trong gói:**
  - JS: Express, Next.js (kể cả App Router), socket.io, `fetch`, axios, `net`/`tls`;
  - Python: Flask, Django, DRF, FastAPI, Starlette, Tornado, requests, httpx, aiohttp, urllib, http.client,
    pycurl.

| Nguyên nhân bỏ sót | Python (19) | JS/TS (21, gồm 2 dở) | Trạng thái |
|---|---|---|---|
| A. Nguồn ngoài mô hình đe dọa mặc định: tham số thư viện, tệp cấu hình, giá trị đọc lại từ cơ sở dữ liệu | 5 (pyjwt, glances, safeurl, recurly; lemur kèm C) | 9 (webfinger, frontmcp, i18next, google-translate, undici, plate, novu; papra kèm C; Hemmelig kèm B) | đã xác minh |
| B. Framework nhận yêu cầu không có mô hình | 3 (swift/swob, meta-ads-mcp, fastmcp) | 4 (opennextjs/Cloudflare, og-image/h3, ckan-mcp; nuxt-api-party kèm C) | đã xác minh |
| D. Lời gọi qua `getattr` động; cùng hàm có cảnh báo ở lời gọi `session.get` kế bên | 1 (GeoNode) | 0 | đã xác minh |
| E. Framework và thư viện có mô hình, không có cảnh báo tại lời gọi | 10 (vllm, lmdeploy, MISP, local-deep-research, InvenTree, calibre-web, chainlit, firefighter, web3, zeep) | 8 (directus, summarize, cors-proxy, 9router, cypress-request, swagger-typescript-api, MagicMirror, n8n-mcp) | **giả thuyết** |

- **Đã xác minh: 9/19 ca Python và 13/21 ca JS/TS.** Mỗi ca có hai căn cứ:
  - kênh nguồn hay framework của chính ca, đọc trong mã của commit;
  - phép kiểm trên gói đã ghim: có hay không mô hình, mô hình đe dọa nào.
- **Giả thuyết** (luồng đứt ở chỗ chưa xác minh được, không quét lại để xác minh):
  - dispatch đa hình hay import động: MISP, local-deep-research;
  - mô hình pydantic và client lưu trong thuộc tính: vLLM, lmdeploy;
  - validator ngầm của DRF: InvenTree;
  - lời gọi qua `getattr` không có đối chứng: firefighter;
  - URL lấy từ nội dung đã phân tích: web3, zeep, swagger-typescript-api;
  - hàm được tiêm: summarize.
- **Chưa rõ, dù có hiện vật gợi ý:**
  - calibre-web: có cảnh báo Flask ở `cps/kobo.py:94`;
  - 9router: có 12 cảnh báo ở các route App Router khác.
- **Vị trí `An toàn` vẫn bị báo** (dtale, TerriaJS, Flowise): đã xác minh như 27.5.
- **Lượt không hoàn tất:** lỗi cú pháp ở tệp không có nhãn (`partial`), CodeQL hết bộ nhớ (angular-cli);
  đã xác minh trên SARIF và nhật ký.

### 27.7 Phiên bản, lệnh, đầu ra

Chạy từ gốc repo, thư mục `artifacts/cwe918-eval/ghsa/`:

1. **Kiểm kê:**
   - tải `GET /advisories?ecosystem=ECO&cwes=918&type=reviewed&per_page=100` theo header `Link` vào
     `advisories/`;
   - `python -I …/inventory.py`.
2. **Dựng ca:** `python -I …/build_cases.py 40`; rồi `preflight.py` trong container (`docker run … /ghsa/preflight.py`).
3. **Nhãn:**
   - `python -I …/make_packets.py`;
   - gán nhãn vào `labels/batch-*.json`, `labels/review-main.json`, `labels/adjudication.json`;
   - `python -X utf8 -I …/merge_labels.py`.
4. **Chạy thử:** `python -I …/rehearsal/make_rehearsal.py`, `ghsa_runner.py` trên `rehearsal/jobs.json`,
   `score.py --base=…/rehearsal`.
5. **Khóa:** `python -I …/make_jobs.py`, `bash …/freeze.sh`.
6. **Đo:** `bash …/run_measure.sh` (kiểm băm, image và 128 tệp nén, chạy bốn container); sau khi chạy:
   `python -I …/rerun_infrastructure.py`.
7. **Chấm:**
   - `python -X utf8 -I …/score.py` (đã khóa);
   - `…/report.py`;
   - `…/posthoc.py`;
   - `…/posthoc_review.py`.

**Đầu ra.**

- **Kiểm kê và dựng ca:** `candidates.json`, `cases.json`, `build-log.json`, `archives/`, `repos/`,
  `diffs/`, `packets/`.
- **Nhãn:** `labels/`, `labels.json`, `label-review.json`, `source/`.
- **Giao thức:** `PROTOCOL-GHSA-SSRF*.md|sha256`.
- **Lượt chạy:** `runs/<kho>@<commit>/` (`result.json`; mỗi ngôn ngữ: SARIF, nhật ký, `extracted-files.txt`),
  `reruns.json`.
- **Chấm và rà:** `score.json|txt`, `report.json|txt`, `dataflow-material.txt`, `dataflow-review.json`,
  `posthoc-material.*`, `posthoc-review.json`.

### 27.8 Năm nhóm CWE: kết quả trên dữ liệu có nhãn

Bảng này cập nhật bảng 26.11 với cột mới. Bằng chứng của bốn nhóm cũ dùng lại số đã lưu, không đo lại.
Mỗi phép đo ghi mẫu số riêng của nó.

| Nhóm (thành viên) | Ngôn ngữ | Công cụ | Bằng chứng tích hợp | Kết quả trên dữ liệu có nhãn | Giới hạn |
|---|---|---|---|---|---|
| CWE-78 (`command-injection-v0.3`) | Python, JS/TS | Semgrep, Bandit (Python), ESLint + eslint-plugin-security (JS/TS), CodeQL; bằng chứng an toàn; gạn G1–G4 | Mục 16–18; `v0.6` giống `v0.5` trên 8/8 nguồn, kể cả khi lượt CWE-918 lỗi (26.4, 26.6) | BenchmarkPython 20 site: CodeQL 11 TP / 2 FP / 2 FN; 84 package npm: 11/133 ứng viên JS sai, gạn đúng 1, gạn nhầm 0; held-out `pairs-v1` (16 cặp): 9/9 vị trí lỗi được báo, 0 bị gạn | Held-out chỉ có nhãn dương; gạn trên JS rất thấp |
| CWE-22 (`path-traversal-v0.2`) | Python | CodeQL + bằng chứng an toàn v0.2 | Mục 16–18; 26.4 | Mã thật, nhãn chủ đề án: loại 4/43 FP, giữ 7/7 TP; Đợt B (11 cặp CVE): CodeQL không báo vị trí CVE nào | Chỉ Python; chỉ gạn |
| CWE-89 (`sql-injection-v0.3`) | Python, JS/TS | CodeQL, Semgrep (37 tệp luật), Bandit B608/B610/B611; gộp trong lời gọi SQL Python | Mục 20, 21, 23; 26.4 | BenchmarkPython 16 ca: CodeQL 0, Semgrep 5 đúng / 0 sai, Bandit 5 đúng / 11 sai; Juice Shop 2/2; SVEN 174 cặp: Bandit +45 ca dương / +20 ca âm; gộp 343 → 306 mục | Các tập nhỏ hay tập phát triển; JS/TS chưa có tập độc lập |
| CWE-79 (`cross-site-scripting-v0.1`) | JS/TS | CodeQL, 7 truy vấn | Mục 24; 26.4 | OSSF (nhãn không độc lập): 14/41 ca đo được; 60 advisory npm, nhãn độc lập: CodeQL 2/60; Semgrep +9 ca nhưng 573 mục mỗi ca thêm (mục 24.7, 25) | Chỉ JS/TS; CodeQL bỏ sót phần lớn ca có nhãn độc lập |
| CWE-918 (`ssrf-v0.1`) | Python, JS/TS | CodeQL: `py/full-ssrf`, `py/partial-ssrf`, `js/request-forgery` | Mục 26: năm nhóm trong một lượt quét thật tới SARIF; 13/13 cảnh báo giống CodeQL chạy riêng; SARIF 288/288; 9/9 lượt lỗi tiêm | **GHSA, nhãn độc lập (mục 27):** Python **1/20** ca (1/24 advisory), JS/TS **2/21** cặp hoàn tất (2/40 advisory); vị trí đã vá vẫn bị báo 1/1 và 2/2; mục rà trên commit trước bản vá: Python 5 trên 24 commit (4 chưa phân loại), JS/TS 33 trên 39 (31 chưa phân loại). OSSF (mục 26.8, 2 ca JS): 1/2 | Chỉ một công cụ; nguồn chỉ thuộc mô hình đe dọa `remote` (yêu cầu tới máy chủ, phản hồi của máy khách) của framework và thư viện có mô hình; không nhận phép kiểm tự viết của bản vá; ca dương lẫn ca âm đều ít |

### 27.9 Kết luận cho đồ án

Mỗi kết luận ghi kèm phạm vi dữ liệu hỗ trợ nó.

1. **CodeQL (`ssrf-v0.1`) phát hiện rất ít ca SSRF có nhãn độc lập.**
   - Python: 1/20 ca có lời gọi trong kho. JS/TS: 2/21 ca có cặp hoàn tất.
   - Phạm vi: 64 advisory GHSA pip/npm có commit sửa, mỗi kho một ca, kho dưới 50 MB, nhãn do AI gán (đồng
     thuận đo trên 12 ca). Tập lệch về kho nhỏ và vừa và về advisory mới: 47/64 công bố năm 2025–2026, nhiều máy chủ MCP và ứng dụng AI.
2. **Một nửa số ca bỏ sót có nguyên nhân đã xác minh, đều nằm ngoài mô hình của truy vấn:**
   - nguồn ngoài mô hình đe dọa `remote`: tham số thư viện, tệp cấu hình, cơ sở dữ liệu;
   - framework hay thư viện gửi yêu cầu không có mô hình: h3, Hono, Cloudflare Workers, swob, MCP SDK,
     ofetch, `acme`;
   - lời gọi qua `getattr` động.
   - Phạm vi: 22 trên 40 ca không được phát hiện (38 ca bỏ sót có cặp hoàn tất và 2 ca dở; Python 9/19,
     JS/TS 13/21), mỗi ca có phép kiểm trên chính ca đó. 18 ca còn lại chỉ có giả thuyết.
3. **Ngay ở ca "yêu cầu web", trường hợp truy vấn nhắm tới, CodeQL chỉ phát hiện 1/12 ca Python và 2/11 ca
   JS/TS.**
   - Phạm vi: nguồn URL do AI gán (đồng thuận 58/64) và khóa trong sửa đổi 1 trước khi đọc kết quả; bảng
     tách theo nguồn là bảng sau đo.
   - Không suy rộng: các ca này lẫn framework có và không có mô hình.
4. **Khi phát hiện, cảnh báo đi đúng đường advisory mô tả, nhưng vẫn báo sau bản vá.**
   - 3/3 ca trúng khớp đường dữ liệu.
   - 3/3 vị trí đã vá (nhãn `An toàn`) vẫn bị báo, vì phép kiểm của bản vá không phải barrier của truy
     vấn.
   - Phạm vi: chỉ 3 ca; không đủ để ước lượng tỉ lệ báo sai sau bản vá.
5. **Tải rà thấp.**
   - Python: 5 mục trên 24 commit trước bản vá; 20/24 commit không có mục nào.
   - JS/TS: 33 mục trên 39 commit; 30/39 commit không có mục nào.
   - Đa số mục là **chưa phân loại**: 4/5 và 31/33 nằm ngoài vị trí có nhãn. Riêng một kho (9router) có 12
     mục.
   - Phạm vi: chỉ nhóm CWE-918 của `multi-cwe-v0.6`, không gồm bốn nhóm còn lại.
6. **Chi phí thấp.** Trung vị mỗi lượt theo ngôn ngữ: khoảng 23 giây (Python) và 27 giây (JS/TS), gồm tạo
   database. Trong ứng dụng, database dùng chung với nhóm khác, nên phần thêm chỉ là phần phân tích, như
   mục 26.7.
7. **Không ngôn ngữ nào bị chặn hoàn toàn**, nhưng có phần không đo được:
   - 9 kho vượt giới hạn của ứng dụng (Python 3, JS/TS 6): 7 kho quá 50 MB, nocobase và next.js quá 20 000
     mục;
   - 2 kho không tải được;
   - 1 ca `validator` thất bại vì hết bộ nhớ ở 2048 MB;
   - 2 ca JS/TS trong phạm vi chính chỉ có lượt `partial` (4 ca nếu tính cả happy-dom và sveltejs/kit,
     ngoài phạm vi).
   - Muốn ước lượng cho kho lớn cần nâng giới hạn của ứng dụng, hoặc đo riêng với phạm vi thư mục con.

**Giới hạn:**

- người gán nhãn và người xét đường dữ liệu là trợ lý AI, không phải chủ đề án;
- nhãn sau bản vá không đồng nhất hoàn toàn giữa các lô (mục 9.1 của giao thức);
- tập nhỏ: 20 và 23 ca trong mẫu số;
- ca âm chỉ là vị trí đã vá;
- tập này đã chạy CodeQL nên không còn độc lập cho phiên bản sau của cấu hình.

### 27.10 Công cụ hỗ trợ đã dùng

| Công cụ | Việc | Kết quả và phần đã kiểm chứng |
|---|---|---|
| Tác nhân phụ (4) | Gán nhãn lần một theo `LABELING.md`, mỗi lô 15–16 ca | 63 nhãn (ca thứ 64, dtale, do trợ lý chính gán); trợ lý chính kiểm khoảng dòng của mọi nhãn, gán lại độc lập 12 ca và phân xử 11 ca |
| Codex (plugin `codex`) | Rà `score.py` theo giao thức trước khi chấm | 5 điểm, đều ở phần tổng hợp; trợ lý chính kiểm trên mã, ghi D1, tính lại bằng `report.py` |
| Codex | Phân loại nguồn URL độc lập | Đồng thuận 58/64; 6 ca do trợ lý chính phân xử |
| LSP Pyright | Kiểm script khi viết | Báo một import thừa ở `score.py` trước khi khóa; đã sửa |
| Không dùng | fp-check, variant-analysis, semgrep-rule-creator, audit-context-building, vulnerability-triage-brocards, `static-analysis` (cả `codeql`, `semgrep`, `sarif-parsing`); Superpowers, Serena, Context7 | Quét bằng skill sẽ là một detector khác với detector đã ghim. Sáu mục của phép kiểm đường dữ liệu và 40 ca bỏ sót được xét trực tiếp trên SARIF, nhật ký, mã và gói truy vấn |
