# BÀN GIAO NGỮ CẢNH NGHIÊN CỨU — SECURITY TRIAGE / SEMGREP + CODEQL

> **Cập nhật sau bàn giao (20/10/2026):** vòng resource-derived đã có kết quả phát triển:
> strict loại thêm 0, scoped loại 8 cảnh báo RC-M3 thuộc một nguyên nhân gốc, có điều kiện.
> Quyết định tiếp tục: khóa hai chế độ, giữ strict mặc định và chuyển sang đánh giá độc lập;
> xem [quyết định mới](experiments/v03-interprocedural-guard/DECISION_2026-10-20.md) và
> [giao thức đợt C](experiments/wave-c/PROTOCOL.md). Nội dung lịch sử bên dưới được giữ nguyên.
> Đợt C chưa tải source/chạy scanner; bản khóa tại máy chưa thay cho cổng commit/publish.

**Thời điểm tổng hợp:** 20/10/2026. **Mục đích:** để một agent mới tiếp quản nghiên cứu, không lặp lại các hướng đã bị dữ liệu bác bỏ và tiếp tục từ trạng thái kỹ thuật mới nhất.

> **Quy ước về độ tin cậy:** Các con số và việc chạy lệnh bên dưới chủ yếu là **kết quả do agent đang làm trên máy người dùng báo lại trong cuộc hội thoại**, không phải do người viết bản bàn giao trực tiếp chạy trên repository. Các tập tin cục bộ chưa commit không mặc nhiên có trên GitHub. Những quyết định, nhận xét và giới hạn đều lấy từ lịch sử trao đổi. `SPEC(1).md` được đính kèm trong hội thoại là **một phiên bản trung gian**, không phải đặc tả mới nhất sau các sửa đổi được người dùng báo ở những lượt sau.

## 1. Đích nghiên cứu và các nguyên tắc không thay đổi

- **Đề tài:** nghiên cứu và triển khai cách giảm cảnh báo sai (FP) của phân tích tĩnh bảo mật mã Python, xuất phát từ việc kết hợp **Semgrep** và **CodeQL**, hiện tập trung vào **CodeQL + kiểm chứng bằng chứng an toàn**. Hệ thống thử nghiệm có FastAPI, PostgreSQL, Celery, Redis, lưu hiện vật kiểu S3 và giao diện React, nhưng giao diện/hạ tầng không phải điểm ưu tiên ở giai đoạn nghiên cứu này.
- Bốn loại điểm yếu ban đầu: **CWE-22** (vượt thư mục), **CWE-78** (lệnh hệ điều hành), **CWE-79** (XSS), **CWE-643** (XPath). **v0.3 chỉ xử lý CWE-22**.
- Mục tiêu chính hiện tại: giảm FP của **cảnh báo đã được sinh ra** mà không loại mất cảnh báo đúng (TP). Việc CodeQL không phát hiện một lỗ hổng vì thiếu mô hình nguồn/đích là vấn đề **bỏ sót phát hiện (FN)**, không phải kết quả giảm FP.
- **Không áp đặt kết luận có lợi cho cách kết hợp hai công cụ.** Nếu Semgrep không bổ sung TP hoặc không giúp giảm FP có ý nghĩa, nói rõ và để Semgrep làm nguồn ứng viên phụ/đối chứng. Không bổ sung AI, học máy, công cụ mới hoặc viết sanitizer chỉ để có số đẹp.
- Ưu tiên **0 TP bị loại nhầm**, chứng minh trên mọi đường được báo đến cùng sink, xử lý thiếu bằng chứng bằng **giữ cảnh báo**. Báo riêng các ca `unknown`, cảnh báo mã kiểm thử và nguyên nhân gốc.
- Một quy tắc được xây bằng mlflow/Django thì hai dự án này là **dữ liệu phát triển**, không được coi là tập đánh giá độc lập của v0.3. Dữ liệu từ BenchmarkPython và phản ví dụ đã dùng nhiều vòng cũng là kiểm thử hồi quy, không phải một tập kiểm tra còn nguyên tính độc lập.
- **Không tự sửa bản khóa lịch sử.** Tệp/commit dùng cho kiểm chứng tái lập phải được giữ; sai lệch thì lập ghi chú hoặc khóa mới. Không tự nhận đã commit/chạy ở máy người dùng khi không thực sự có quyền truy cập.

## 2. Lịch sử thay đổi hướng nghiên cứu — theo thời gian

| Chặng | Giả thuyết/cách làm | Kết quả, quyết định |
|---|---|---|
| Khởi đầu | **Semgrep → CodeQL** nối tiếp để thẩm định cảnh báo CWE-78 | Bị bác bỏ: recall của cả chuỗi không vượt được recall Semgrep. Trên OWASP Python, CodeQL độc lập F1 khoảng 0,85, Semgrep → thẩm định dù hoàn hảo bị chặn gần 0,70; Semgrep không thêm TP mà CodeQL bỏ sót trong phép thử ban đầu. |
| Thí điểm mở rộng | Chạy **song song Semgrep + CodeQL**, hợp nhất theo tệp/vị trí sink/đối số/CWE; so sánh bốn ô chỉ bên này/chỉ bên kia/cả hai/cả hai bỏ sót | CodeQL có lợi thế đáng kể, Semgrep bổ sung một ít TP CWE-78 nhưng thêm FP; không có bằng chứng cho việc “đổi chéo” bằng chứng tùy ý giữa hai công cụ. |
| Đối chứng E/F | **E:** chính logic kiểm tra an toàn nhúng vào truy vấn CodeQL. **F:** hậu kiểm trên hợp cảnh báo CodeQL+Semgrep; có thể thử chính sách F′ thận trọng với Semgrep-only | Không được tuyên bố F tốt hơn nếu chỉ bằng E. Phải so sánh trên tập ứng viên giống nhau khi có thể, ghi độ phủ và trường hợp không đo được. |
| v0.1 | Thêm nhiều guard/barrier vào CodeQL mặc định | Giảm FP cực mạnh trên BenchmarkPython nhưng **không an toàn** trên phản ví dụ độc lập: 10 ca nguy hiểm bị loại nhầm. Không được sử dụng v0.1 làm cơ chế chính. |
| v0.2 | Thu hẹp guard, kiểm tra ranh giới đường dẫn, hạn chế trường hợp ngoại lệ | Không mất TP trong tập kiểm tra đã chạy; ít FP hơn bị loại so với v0.1 nhưng hợp lý hơn. Trở thành đường cơ sở an toàn hơn. |
| Đợt A, dự án thật | Flask-Admin và Paperless-ngx tại commit cố định | Cực ít cảnh báo CWE-22/643 liên quan; dừng theo điều kiện đặt trước. Flask-Admin có 3 cảnh báo CWE-22, chung 1 nguyên nhân gốc; Paperless-ngx không có CodeQL cảnh báo thuộc 4 CWE. |
| Đợt B, dự án thật | 11 cặp **phiên bản có lỗi/đã vá** chọn từ GitHub Advisory, quét 22 phiên bản | **CodeQL không cảnh báo tại vị trí CVE trong cả 11 cặp.** Đợt B không đo được giảm FP tại vị trí CVE; dùng 60 cảnh báo khác xuất hiện ngoài CVE để gán nhãn, đồng thời làm lộ giới hạn độ phủ. |
| Vòng gán nhãn | Rà bằng luồng dữ liệu, kiểm tra guard và đối chiếu lỗ hổng được công bố | Có 33 FP được đề xuất/xác minh ở mã sản phẩm trên 44 cảnh báo, trong đó **19 FP thuộc guard liên thủ tục** trên mlflow + Django; RC-M6 buộc phải giữ vì có đường dùng chuỗi chưa chuẩn hóa. |
| v0.3 | Chứng minh validator liên thủ tục, nhánh ngoại lệ, tính chất giá trị và hợp đồng gốc của sink | Đã có QL lõi và thử nghiệm phản ví dụ. **Đến lần báo cáo mới nhất: 0/26 cảnh báo mlflow và 0/9 cảnh báo Django được loại** trên dữ liệu phát triển vì không chứng minh được `AllowedRoot`; **không có TP/unknown bị loại**. Nút thắt hiện tại là **xác định gốc hợp lệ cho sink**, không phải đơn thuần nhận diện validator. |

## 3. BenchmarkPython và đối chứng công cụ

**OWASP BenchmarkPython 0.1:** 463 test case: 160 có lỗ hổng, 303 an toàn; chia bằng hash tên test trong từng CWE:
- Phát triển: 235 (82 có lỗ hổng, 153 an toàn).
- Kiểm tra: 228 (78 có lỗ hổng, 150 an toàn).
- Các test tạo tự động có thể rất giống nhau giữa hai nửa, vì vậy đây **không chứng minh tổng quát hóa trên mã thực tế**.

**Kết quả thí điểm trên nửa phát triển** (TP/FP/FN):

| CWE | Semgrep | CodeQL | Hợp cảnh báo |
|---|---|---|---|
| 22 | 1/0/32 | 24/31/9 | 24/31/9 |
| 78 | 7/4/0 | 5/2/2 | 7/4/0 |
| 79 | 0/12/16 | 0/6/16 | 0/12/16 |
| 643 | 0/0/26 | 9/22/17 | 9/22/17 |
| **Tổng** | **8/16/74** | **38/61/44** | **40/69/42** |

Bốn ô (tính theo test/CWE): chỉ Semgrep TP 2 FP 8; chỉ CodeQL TP 32 FP 53; cả hai TP 6 FP 8; cả hai bỏ sót FN 42, TN 84. Bandit CWE-78 cho tổng TP/FP/FN trùng Semgrep, nhưng tổng số giống nhau **không chứng minh phát hiện từng ca giống nhau**. CWE-79 CodeQL bỏ sót Flask route đặt bên trong `init(app)`, có 0 TP trong phát triển; cảnh báo header ≠ phản hồi HTML body.

### v0.1 và v0.2

| Tập | CodeQL mặc định TP/FP | v0.1 TP/FP | v0.2 TP/FP |
|---|---:|---:|---:|
| Phát triển | 38/61 | 38/0 | **38/5** |
| Kiểm tra | 37/53 | 37/0 | **37/4** |

- v0.1 lọc 61/61 FP phát triển và 53/53 FP kiểm tra nhưng **loại nhầm 10 ca nguy hiểm** trong bộ phản ví dụ độc lập → không an toàn.
- v0.2 lọc **56/61 FP (91,8%)** phát triển và **49/53 (92,5%)** kiểm tra, 0 mất TP trên benchmark; không loại nhầm ca nguy hiểm đã kiểm tra. 9 FP còn lại liên quan prefix `str(p).startswith(str(testfiles))` không kiểm tra ranh giới; benchmark gán nhãn an toàn nhưng trường hợp thư mục anh em `testfiles-x` vẫn có rủi ro thật. Phải giữ cả hai góc nhìn, không sửa nhãn benchmark để đẹp số.
- Bộ phản ví dụ Flask ban đầu có 47 ca, 45 có ích/được dùng (2 không được CodeQL mặc định phát hiện); một số ca an toàn bị bỏ sót do `abort()` không được mô hình hóa là không quay về.
- Với CodeQL cần **`--rerun`** khi thay thư viện truy vấn để tránh kết quả cache làm sai phép đo.

## 4. Đợt A — Flask-Admin và Paperless-ngx

- Flask-Admin commit **`4f8be4580b082c6047492baa801f3f08642c9a75`**: CodeQL mặc định **3 cảnh báo CWE-22**, v0.2 **không loại**; Semgrep khoảng **22 cảnh báo kiểu API XSS**. Đường đi chung: `request.args.getlist("path")` → `_normalize_path` → `is_in_folder` → các thao tác file. `is_in_folder` dùng `.startswith(base_path)` thiếu ranh giới nên có nguy cơ với thư mục anh em cùng tiền tố; cần điều kiện truy cập và bố trí hệ thống tệp. Ba cảnh báo được đánh dấu `true_positive_conditional`, `owner_reviewed`, `not_independently_confirmed`, cùng **một** `root_cause_id`. Kết quả **3 cảnh báo ≠ 3 lỗ hổng độc lập**; nhãn từng luồng đã rà nhưng chưa có kiểm chứng khai thác end-to-end.
- Paperless-ngx commit **`d4a57204ebabd5ab674771ab606a66ea90f9370a`**: CodeQL **0** cảnh báo trong 4 CWE; Semgrep khoảng 8 XSS và 2 mẫu gọi thực thi lệnh; không đủ dữ liệu giảm FP.
- Mã trích xuất toàn bộ 168/168 và 410/410 tệp; đợt A dừng vì không đủ cảnh báo relevant FP theo điều kiện dừng có trước.
- Đường dẫn tham chiếu: `experiments/wave-a/` và dữ liệu thô `artifacts/wave-a/`. Không giả định các tệp chưa commit đã lên GitHub.

## 5. Đợt B — thiết kế mẫu và quét thực tế

### Cách lấy mẫu

- Bộ lọc GitHub Advisory đã rà soát: 534 bản tin; 323 ứng viên hợp lệ; 186 loại do thiếu commit vá, 25 đã rút. Chọn PyPI, CWE-22/CWE-643, không rút, có commit vá; riêng CWE-643 rà tất cả ứng viên (chỉ 2 bản tin); CWE-22 chọn theo thứ tự **hash** đến 10 cặp, không chọn dựa trên việc công cụ có phát hiện hay không. Một ứng viên xrootd bị loại do bản vá chỉ sửa C++.
- Tổng **11 cặp:** CWE-22 gồm `mcp-atlassian`, `copier`, `microsoft/apm`, `dosage`, Django `archive.extract`, `asyncssh`, `mlflow`, `changedetection.io` (mốc 2024), `AstrBot`, `datamodel-code-generator`; CWE-643: `smolagents` dùng Selenium XPath.
- Mỗi cặp dùng **commit vá trên nhánh mặc định và cha thứ nhất** làm commit lỗi; không có commit merge. Django là **CVE-2021-3281 / GHSA-fvgf-6h6h-3322**, cặp `6822aa5c` → `05413afa` (main); bản vá 2021 dùng `startswith` thiếu ranh giới. Bản vá hoàn chỉnh sau này **CVE-2025-59682 / GHSA-q95w-c7qg-hrff** đổi sang `commonpath` (CWE-23 nên không qua bộ lọc chỉ CWE-22). Không mặc định bản đã vá 2021 an toàn tuyệt đối.
- Giao thức/danh sách được khóa với **`LOCK.sha256`**, mốc commit **`cff13ff`**. Lịch sử có bước phục hồi `SELECTION_PROTOCOL.md`, `inventory.yaml` để trùng hash trong bản khóa; về sau người dùng báo hai commit đó đã thực hiện, nhưng các sửa đổi v0.3 mới nhất **chưa commit**.

### Thực nghiệm

- 22/22 lượt chạy hoàn tất; CodeQL 2.27.1, `python-all` 7.2.6, `python-queries` 1.8.11, truy vấn mặc định/v0.2 với `--rerun`, `Evidence.ql`, `Coverage.ql`; Semgrep 1.178.0, 61 quy tắc.
- **11/11 cặp đều “không có cảnh báo tại vị trí CVE” ở cả bản lỗi lẫn bản vá.** Không được đưa các cặp này vào mẫu số giảm FP **tại vị trí CVE**. Nguyên nhân thiếu mô hình nguồn/đích/lan truyền chỉ là suy luận dựa trên phân tích độ phủ, **chưa được kiểm chứng độc lập toàn bộ 11 ca**. Ví dụ Selenium `find_elements(By.XPATH)` không được coi là sink XPath, tham số công cụ LLM/MCP, Quart request, tên member archive, cấu hình template, HTTP response, `$ref`... thường không nhận diện là nguồn; mlflow có nguồn nhận diện trong file CVE nhưng 3 cảnh báo ở hàm khác, không đúng vị trí lỗ hổng.
- Có **60 cảnh báo CodeQL duy nhất ngoài vị trí CVE**, lặp lại giữa bản lỗi và bản vá, **không đếm đôi**: mlflow 27 CWE-22 +1 CWE-79; Django 9 CWE-22 +11 CWE-79; changedetection.io 8 CWE-22 +4 CWE-79.

### Nhãn cuối trên 60 cảnh báo

| Phạm vi | Tổng | TP | TP có điều kiện | FP | Unknown | Nguyên nhân gốc |
|---|---:|---:|---:|---:|---:|---:|
| **Mã sản phẩm** | **44** | **4** | **3** | **33** | **4** | **13** |
| **Mã kiểm thử** | **16** | — | — | — | — | **7** |

- 16 cảnh báo trong mã kiểm thử có `manual_label=test_code`; cột `technical_label` riêng (trước đó 10 kỹ thuật TP, 6 kỹ thuật FP), **không gộp vào tỷ lệ lỗ hổng sản phẩm**.
- v0.2 **loại đúng 1/33 FP trong mã sản phẩm**, giữ **7/7 TP+TP_conditional**, chưa loại nhầm TP nào theo nhãn đã khóa. `unknown` không tính như TP hay FP. Ca loại đúng liên quan `Path(...).resolve()` của `validate_path_within_directory` (bản thân chuẩn hóa không truy cập file).
- **19/33 FP mã sản phẩm thuộc guard liên thủ tục**, có ở mlflow và Django, là động lực của v0.3. Các loại khác: đường callback/đa hình không khả thi ở mlflow, khóa thuộc tập do server sinh ở changedetection.io.
- RC-M1 (mlflow): ban đầu 9 FP, sau phát hiện handler bị bỏ qua giá trị trả về → **7 FP tạm giữ, 2 chuyển thành `RC-M6` unknown**. Một phát hiện mới hơn cho thấy `self.artifact_dir` bắt nguồn từ `artifact_location` trong request lưu tại store; tính tin cậy của gốc cần xem lại, vì vậy **7 FP RC-M1 đã khóa không phải kết luận bất biến**. Không sửa âm thầm nhãn cũ; dùng bảng rà soát hoặc phiên bản nhãn mới có lịch sử.
- RC-M2 (mlflow, 7 FP): luồng callback không khả thi; `list_all` thực tế nhận `filter_func` mặc định, không lambda bị CodeQL nối nhầm.
- RC-M3 (mlflow, 8 FP): `uuid.UUID(session_id)` được kiểm tra trước khi sử dụng chuỗi gốc; thử trên Unicode, không có chuỗi hợp lệ chứa ký tự cấu thành traversal được báo; validator thất bại thì dừng trước sink. `SESSION_DIR = Path(tempfile.gettempdir()) / "mlflow-assistant-sessions"` ở commit mlflow **`6e801f4259`**.
- RC-M4 (mlflow, 2 unknown): endpoint localhost cố ý nhận đường dẫn tùy ý, phụ thuộc mô hình đe dọa (localhost và khả năng vượt ranh giới).
- RC-M5 (mlflow, 1 FP): `resolve()`/`is_relative_to()` ngay tại hàm, v0.2 loại đúng.
- RC-M6 (mlflow, 2 unknown, **nhạy cảm**): `get_logged_model_artifact_handler` gọi `validate_path_is_safe()` nhưng **bỏ giá trị trả về** sau `_decode`, tiếp tục dùng chuỗi gốc; có lớp kiểm tra thứ hai ở kho local, còn các kho khác chưa xác minh. **Không công bố chuỗi đầu vào/chi tiết khai thác**; bản đầy đủ trong `artifacts/wave-b/private/RC-M6_note.md` bị gitignore. Nếu thành lỗ hổng thật thì báo kín cho maintainer trước công bố.
- RC-D2 (Django, 4 FP): `safe_join` với guard ba nhánh; còn các 3 cảnh báo TP sản phẩm trong `admindocs` liên quan CVE về sau.
- changedetection.io: 1 TP ở `group=".."` liên quan advisory về sau; 2 `filename=".."` được gán `TP_conditional` do đường thoát một cấp phụ thuộc tệp tồn tại; RC-C4 XSS `TP_conditional` (CSRF không tương đương escape đầu ra). Chi tiết tình huống còn tồn tại trong phiên bản mới giữ riêng trong `artifacts/wave-b/private/RC-C4_note.md`. Không khẳng định end-to-end khai thác đã xác nhận.
- **Nhãn được tạo bởi người biết quyết định v0.2**, có nguy cơ thiên lệch; cần kiểm chứng độc lập khi khả thi.

Tệp liên quan: `experiments/wave-b/results/wave_b_labels.csv`, `wave_b_label_summary.json`, `root_causes.json`, `build_labels.py`, `LABELS_LOCK.sha256`, các truy vấn `qreview/`, `RESULTS.md`; dữ liệu thô `artifacts/wave-b/wave-b-raw.tar.gz` **không commit**.

## 6. Phương pháp kỹ thuật v0.3 đã thống nhất

### Mục đích

Tập trung vào **CWE-22 và guard ở hàm khác chặn bằng ngoại lệ**, trên đường dữ liệu đến sink. Một validator được công nhận chỉ khi **mọi đường quay về bình thường** đảm bảo thuộc tính an toàn; nếu `except` nuốt lỗi rồi đi tiếp thì không có bằng chứng. Tại bên gọi, sink phải dùng **đúng giá trị được chứng minh**, hoặc một phép biến đổi đã được chứng minh bảo toàn; mọi luồng CodeQL báo đến cùng sink phải an toàn. Đường chưa rõ nghĩa/không thể phân giải → **giữ cảnh báo**.

### Các thuộc tính

- `SafeRel(v)`: chuỗi đường dẫn tương đối và không có thành phần `..`; chỉ là thuộc tính trung gian, **không tự loại cảnh báo**.
- `Segment(v)`: một thành phần đường dẫn an toàn (ví dụ ID đã qua UUID), không có dấu phân cách; cũng **không tự loại**.
- `Contained(v,B)`: đường dẫn được chứng minh nằm dưới gốc B trong hệ quy chiếu tương ứng; **chưa đủ để loại** nếu chưa chứng minh `AllowedRoot(sink,B)`.
- Nên tách `ProvenContained(path,B)` khỏi `AllowedRoot(sink,B)`: containment được chứng minh bằng phân tích mã, còn chính sách gốc của sink phải có bằng chứng độc lập hoặc suy luận hạn chế với giả định đã công bố.
- **Không dùng `Contained(v,"/")` một mình để loại**; không suy hợp đồng từ một phép `join(B,v)` đơn thuần; không tự coi thuộc tính/tên tham số đáng tin chỉ vì tên đẹp.
- Symlink có sẵn, thay đổi hệ thống tệp và TOCTOU: phải nêu giới hạn. Nếu dựa trên containment từ vựng, ghi rõ điều kiện A-SYM; nếu dùng `resolve/realpath`, ghi bằng chứng canonical. Các phép duyệt thư mục `listdir/scandir/iterdir` có symlink thuộc chặng riêng, không tự bảo toàn.

### Biến thể và các lỗi đã xử lý

- Ban đầu dự định dùng flow state CodeQL (`NotNormalized`, `NormalizedUnchecked`, `Validated(...)`). Cài đặt thực tế **không dùng trạng thái taint**, vì bước taint mặc định có thể mang trạng thái qua cả biến đổi chưa được công nhận như `unquote`. Thay bằng **bằng chứng trên nút CFG/SSA, validator summary và điều kiện ở đối số sink**. Đây là quyết định kỹ thuật đã thực hiện, không yêu cầu ép quay lại flow state.
- Không mặc định giá trị qua hàm khác là an toàn; chỉ công nhận hàm có tóm tắt chứng minh identity hoặc biến đổi thuộc danh sách đóng. Phải xử lý gán lại biến, SSA phi, nhánh ngoại lệ, luồng kiểm tra thất bại nhưng được bắt, phương thức bị ghi đè, nhiều đường đến cùng sink.
- Django `safe_join`: với điều kiện `not A and B and C: raise`, khi return bình thường có `A or not B or not C`, **cả ba nhánh phải độc lập kéo theo cùng containment**. `A`: `final` nằm dưới `base + sep`; `not B`: `final == base`; `not C`: `base` là gốc POSIX. Trường hợp gốc `/` không được tự coi là an toàn theo chính sách ứng dụng.
- Trong phiên bản mới, bổ sung nhận diện `PurePosixPath(s).is_absolute()` hoặc `s.startswith("/")` sai là tương đối (trên POSIX không suy tương tự từ `PureWindowsPath`), biến phi sau gán có điều kiện và phân giải `staticmethod`, method thường, `classmethod` với độ lệch đối số. Vẫn yêu cầu phân giải duy nhất; ghi đè không phân giải → giữ.

### Quy tắc `trusted_root` gần nhất

- Chế độ **strict** có T1–T4: gốc từ danh sách nguồn có thể chứng minh, ổn định, tuyệt đối đã chuẩn hóa và không phải `/`. T1 chặng đầu chỉ nhận **hằng**, biến module chỉ gán một lần và phép `join/Path` của chúng. Tham số, `self.artifact_dir`, dict, biến môi trường không tự công nhận.
- Giới hạn thực tế: gốc mlflow `SESSION_DIR` gọi `tempfile.gettempdir()` nên **không qua T1 hẹp**; Django `document_root` là tham số không truy được nơi tạo; mlflow `artifact_dir` có thể bắt nguồn từ request. Chỉ mở rộng T1 theo những quy tắc nguồn gốc tổng quát có kiểm chứng.
- Chặng 1 không mặc định bảo toàn qua f-string/cộng chuỗi với prefix; ưu tiên `os.path.join(B,v)` và `Path(B)/v` với điều kiện giá trị an toàn, gốc tin cậy, tính chất đúng với sink.

## 7. Các mức hợp đồng của sink — quyết định mới nhất

Từ đặc tả chỉ có `sinkAllowedRoot` khai báo trong model pack kiểm thử, v0.3 tiến tới ba loại nguồn:

1. **Explicit**: hợp đồng độc lập đã khai báo, ví dụ `policy/cex_sink_policy.model.yml` trong bộ phản ví dụ. Chỉ dùng trong kiểm thử nếu nguồn do người thiết kế fixture quy định trước; không được điền hậu nghiệm theo nhãn FP.
2. **API-derived**: hợp đồng từ API có tham số gốc theo ngữ nghĩa được xác minh (ví dụ `send_from_directory(directory,path)`). Có thể không tăng FP được loại vì API đã tự guard; vẫn có ích để kiểm chứng kỹ thuật.
3. **Resource-derived / scoped** (**hướng được chọn trong quyết định cuối**): thử suy luận gốc từ một tài nguyên do ứng dụng quản lý, chẳng hạn `SESSION_DIR` dành cho các tệp phiên, **nhưng chỉ khi có bằng chứng độc lập** về nguồn gốc, tính ổn định, mục đích lưu trữ, đường tới sink và không có chính sách mâu thuẫn. Không đơn thuần lấy gốc từ `join(B,v)` hoặc từ tên biến. Cần báo tách `strict` (chỉ hợp đồng mạnh) và `scoped` (thêm suy luận có giả định).

**Quyết định sau cùng:** chọn **hướng 3** trong ba lựa chọn của lượt 20/10: thử một vòng **hẹp, giới hạn thời gian/phạm vi**, về `resource-derived AllowedRoot`, ưu tiên RC-M3. **Không** mở toàn bộ thuộc tính/tham số theo mức C ngay; **không** chuyển trực tiếp sang dự án mới ngay trước khi thử nút thắt hợp đồng. Nếu một vòng này không tạo được hợp đồng đủ chặt và FP giảm thực tế, **ghi nhận 0 và chuyển sang thiết kế đánh giá**; không nới vô hạn chỉ để tăng số FP.

### Sáu điều kiện tối thiểu của `resource-derived`

1. Gốc sinh từ trạng thái server/nguồn được kiểm chứng đáng tin, không bị người dùng của mô hình đe dọa chi phối.
2. Gốc ổn định từ lúc kiểm chứng đến lúc dùng; đường dẫn tuyệt đối chuẩn hóa, khác `/`, đáp ứng giả định symlink.
3. Có bằng chứng **ngoài phép nối** về vai trò thư mục đó là nơi quản lý loại tài nguyên cần truy cập: mã khởi tạo thư mục, lưu/đọc tài nguyên, vòng đời tài nguyên; không chỉ tên `SESSION_DIR` hay `artifact_dir`.
4. Sink dùng đúng đường dẫn đã được bảo vệ hoặc phép biến đổi bảo toàn được chứng minh.
5. Không có hợp đồng chính sách khác xung đột hoặc yếu tố phân quyền chưa giải quyết.
6. Không có đường CodeQL báo đến cùng sink mà chưa được kiểm chứng.

Bằng chứng `scoped` phải công bố giả định; không đánh đồng với chứng minh phân quyền tuyệt đối. Nếu thiếu điều kiện → giữ cảnh báo.

## 8. Phản ví dụ và các lần thử v0.3

### Tiến hóa bộ thử

- Ban đầu: 12 ca an toàn + 14 ca nguy hiểm.
- Sau bốn sửa đổi đặc tả: 12 + 21.
- Sau bổ sung hợp đồng và gốc tin cậy: **13 ca an toàn + 24 ca nguy hiểm**, CodeQL mặc định phát hiện 24/24 nguy hiểm; v0.2 không loại nhầm; 0 failures trên 29.929 đầu vào thử (thử hữu hạn, không chứng minh tổng quát).
- Tiếp đó thêm ca `ipg_14_good` đối chứng với `ipg_17_bad` (cùng mã nguồn, **khác hợp đồng** `BASE`/`PUBLIC_ROOT`); tiếp tục có các ca g16–g19 và b25–b26 để sửa ba lỗi nhận diện. Agent mới **phải đọc inventory/kỳ vọng mới nhất trong repo**; không suy ra tổng ca hiện tại bằng cách cộng theo tin nhắn vì nhiều tên được đổi hoặc xây lại.
- `ipg_17_bad`: dù đường dẫn thuộc `PUBLIC_ROOT`, sink chỉ cho `BASE`, phải **giữ**; `ipg_14_good` cho phép PUBLIC_ROOT, có thể **loại**. Quy tắc policy từ model pack được checker và QL đọc cùng tệp; cần có **oracle nhãn độc lập** để tránh hai bên cùng hiểu sai hợp đồng mà vẫn báo “đạt”. Không hợp đồng → giữ cảnh báo.
- Các ca nguy hiểm trọng yếu: thiếu dấu phân cách trong `startswith(base)`, gốc `/`, gốc từ nguồn request khác, bỏ giá trị trả về sau giải mã như RC-M6, phép biến đổi `../`, bắt ngoại lệ rồi đi tiếp, gọi động/phương thức bị ghi đè, và một sink có cả luồng được kiểm chứng lẫn luồng không.

### Kết quả đã được báo

- **Bước (a),(b)** `Segment`/`SafeRel`: bộ phản ví dụ báo 0 UNSOUND, 0 VACUOUS, 5 MISSED (g3,g4,g13,g14 cần `Contained`; g11 bool-validator ngoài phạm vi); 10 sink bị loại, tất cả `lexical (A-SYM)`; tập con **29 ⊆ 39 ⊆ 41** (v0.3 ⊆ v0.2 ⊆ mặc định) trên một bộ. Pilot không thay đổi. Khi đó BenchmarkPython/tập phát triển chưa chạy do chưa có hợp đồng.
- **Bước (a),(b),(c) và sửa ba lỗi nhận diện tiếp theo:** QL có **11 validator summary trên mlflow**, gồm `validate_path_is_safe` và chuỗi method của trình quản lý phiên. Phản ví dụ: 0 UNSOUND, 0 VACUOUS; các ca g16–g19 được loại có hợp đồng; b25–b26 vẫn giữ. Pilot không đổi, kiểm tra chuỗi tập con đạt. BenchmarkPython: không loại cảnh báo nào, 0 TP mất. **mlflow: 0/26 cảnh báo còn lại được v0.3 loại; Django: 0/9**. Các TP/unknown được kiểm thử trong phạm vi hiện có đều được giữ, gồm hai RC-M6. 
- Lý do: **không có `AllowedRoot` có thể chấp nhận trên những sink thực tế**. Kể cả bổ sung đúng các nguồn gốc T1 mức C cho ba trường hợp đã khảo sát vẫn chưa giải quyết: `artifact_dir` nghi không đáng tin; `document_root` không truy được nơi gọi; `SESSION_DIR` gốc có thể tin nhưng sink `open`/`write_text` thiếu hợp đồng độc lập.
- Không được suy ra “v0.3 không có ích trên mọi mã thực tế” từ vài dự án phát triển; chỉ nói **đã quan sát 0 FP được loại trong tập phát triển hiện tại**. Kết quả phản ví dụ tốt là độ an toàn trong phạm vi thử, không chứng minh hiệu quả trên dữ liệu sản phẩm.

### Tệp đã được người dùng/agent báo tạo (chưa chắc đã commit)

- `experiments/v03-interprocedural-guard/SPEC.md`, `README.md`, `ql/IpgGuard.qll`, `counterexamples/`, `validators.py` (trong counterexamples), `policy/cex_sink_policy.model.yml`.
- `scripts/check_semantics.py`, `scripts/run_cex.sh`, `scripts/subset_check.py`, `results/cex_baseline_v02.json`, `results/cex_stage1_ab.json`, `results/cex_stage1_abc.json`, `results/dev_stage1_abc.json`, `EXPECTATIONS.sha256` và các tệp phụ khác. Đọc `git status`, `find` để xác minh đúng đường dẫn và tên trước khi sử dụng. **Các thay đổi gần đây chưa commit** theo báo cáo cuối cùng của người dùng.

## 9. Sai lệch bản khóa v0.2 — đã điều tra nhưng còn giới hạn

- Hai script `gen.py` và `evaluate_cex.py` không khớp **`FREEZE_v0.2.sha256`** cũ từ commit `a2bb650`. Theo báo cáo, đó là hậu quả của định dạng Ruff sau khóa; blob preformat không còn tìm được trong Git, kể cả blob mồ côi. `SafetyEvidence.qll` vẫn khớp.
- So lại bằng bản hiện có: 11/11 hash truy vấn phù hợp đợt A; 5/5 JSON chấm điểm khớp; từng ca phản ví dụ pilot v0.1 và v0.2 khớp; BenchmarkPython 1136/1136 kết quả v0.1 và 1184/1184 v0.2 khớp; 4.883 dòng chứng cứ từ hai dạng `Evidence.ql` giống nhau. `Evidence.ql` sau định dạng chỉ khác xuống dòng, không thay đổi các dòng bằng chứng trong phép thử nêu trên.
- Đã tạo theo báo cáo: `experiments/owasp-bp-pilot/FREEZE_DEVIATION.md`, `scripts/verify_post_format.sh`, `FREEZE_v0.2_postformat.sha256`, chỉnh README. **Không thay bản khóa lịch sử**.
- **Chưa chạy lại đợt A/B hoàn toàn** ở thời điểm điều tra; A có hash truy vấn trực tiếp. B không lưu hash truy vấn gốc, nên chỉ suy luận phép đo không đổi, **chưa xác minh trực tiếp**. Một lượt sau ghi “20 phiên bản còn lại của đợt B chưa chạy lại” — đây là công việc còn tồn, không có nghĩa 20 phiên bản chưa từng được quét.

## 10. Các quy tắc chống kết luận sai khi phát triển

1. **Không nhầm FP với FN:** 11/11 vị trí CVE không được cảnh báo chủ yếu phản ánh giới hạn phát hiện, không là bằng chứng v0.2/v0.3 giảm FP.
2. **Không giả định mặc định bản vá = an toàn hoặc mọi cảnh báo sau vá = FP.** Django bản vá 2021 còn lỗi prefix sau này được công bố. Advisory xác thực một lỗ hổng tại vị trí cụ thể, không gán nhãn mọi cảnh báo của repo.
3. **Không tính mỗi SARIF row là lỗ hổng độc lập.** Phân nhóm root cause. Định nghĩa đơn vị nhãn đợt B: một sink với toàn bộ luồng CodeQL báo tới nó. Cảnh báo ở bản lỗi/bản vá giống nhau không nhân đôi.
4. **Không giấu trường hợp v0.3 không chứng minh được.** `unknown`/không có hợp đồng → giữ; báo tỷ lệ sink có hợp đồng, không có, loại được, và FP trên phần đủ điều kiện.
5. **Không chọn repository đánh giá hậu nghiệm** vì đã biết công cụ báo FP và v0.3 loại được. Chọn/khóa trước quét, tách mẫu phát triển và độc lập. Dữ liệu theo advisory tốt cho kiểm tra TP, nhưng không đảm bảo có FP sau vá; có thể chọn mẫu từ cảnh báo thực tế với quy tắc chọn trước, công bố thiên lệch.
6. **Giữ v0.2 là đối chứng:** kiểm `R_v0.3 ⊆ R_v0.2 ⊆ R_mặc định` theo (CWE,tệp,dòng,cột sink), đồng thời so sánh tác động Semgrep nếu có cơ sở. 0 UNSOUND trên phản ví dụ, 0 TP benchmark bị loại là tiêu chí hồi quy, không phải chứng nhận tuyệt đối.
7. **Mỗi cảnh báo bị loại cần có bằng chứng:** validator, SSA/CFG, nhánh ngoại lệ, gốc tin cậy, `AllowedRoot`, phép biến đổi, giả định lexical/canonical, mã/hàm/đường tới sink. Không dùng tên `validate_*` thay chứng minh.
8. **Nhãn cũ không được sửa ngầm.** Khi phát hiện gốc `artifact_dir` có thể bị tác động bởi người dùng, mở nhánh rà soát RC-M1, ghi nhãn phiên bản/độ tin cậy mới và lý do; không viết lại lịch sử để phù hợp code.
9. **Bảo mật có trách nhiệm:** RC-M6 và RC-C4 có dấu hiệu nguy cơ trong mã có thể còn được triển khai, không đưa chi tiết khai thác vào repo công khai; ghi chú riêng gitignore; ưu tiên xác minh trong môi trường được phép rồi báo kín nếu phù hợp.
10. **Ưu tiên nghiên cứu hơn dựng giao diện:** không dành thời gian cho FE, Redis/Celery/DB/AI trước khi khóa quy tắc và có đánh giá định lượng có thể tái lập.

## 11. Quyết định hiện hành và kế hoạch agent mới PHẢI bắt đầu từ đây

**Quyết định hiện hành (lượt mới nhất, 20/10/2026): chọn mở rộng `AllowedRoot` theo `resource-derived` thật hẹp, thử một vòng có điểm dừng, ưu tiên RC-M3. Không nới tất cả gốc ở mức C. Nếu không tìm được bằng chứng đủ mạnh, chốt kết quả giảm FP = 0 trên dữ liệu phát triển và chuyển sang đánh giá độc lập thay vì nới vô hạn.**

### Các việc thực hiện theo thứ tự

1. **Kiểm tra hiện trạng repo thay vì giả định:** `git status`, `git log`, phiên bản mới nhất của `SPEC.md`, `IpgGuard.qll`, policy pack, test fixture, kết quả khóa và hash. Các file theo trao đổi cuối chưa commit; giữ nguyên thay đổi người dùng. Xác nhận CLI CodeQL, quy tắc, phiên bản, lệnh `--rerun` và tên test.
2. **Đóng băng kết quả strict hiện tại:** ghi hash QL/policy/spec, đầu ra tập phát triển (0/26 mlflow, 0/9 Django), phản ví dụ, trường hợp giữ RC-M6, subset chain. Không trình bày 0 như một thất bại cần che giấu.
3. **Soạn đặc tả bổ sung NGẮN cho `resource-derived AllowedRoot`:** tách `proved`/`scoped`/`unknown`, thiết kế chứng cứ độc lập ngoài `join`, đáp ứng sáu điều kiện mục 7; xác định ranh giới không được phép (gốc request-controlled, gốc thay đổi, thiếu chứng minh nguồn).
4. **Bổ sung phản ví dụ và khóa kỳ vọng trước chạy:** module-level resource root ổn định, thư mục tạm có ngữ nghĩa rõ, gốc từ request khác, gốc bị thay đổi, mâu thuẫn chính sách, sai gốc, nhánh chưa kiểm tra, symlink nếu xét. Một ca không có bằng chứng → bắt buộc giữ. Bảo đảm bộ chấm nhãn không chỉ phụ thuộc vào cùng tệp model pack với QL.
5. **Triển khai đúng MỘT quy tắc suy luận nguồn gốc có thể tái sử dụng**, ưu tiên loại tài nguyên phiên máy chủ như `SESSION_DIR`. Không hardcode mlflow; không tự công nhận `self.artifact_dir` hay `document_root` chưa truy được. Chạy riêng strict và scoped, so số FP/TP bị ảnh hưởng; đánh dấu mọi lần loại dựa trên giả định mới.
6. **Chạy toàn bộ hồi quy:** phản ví dụ v0.3 và pilot, BenchmarkPython, tập phát triển, subset chain; giữ `RC-M6`, TP và unknown. Tách lỗi CodeQL không phát hiện sink ban đầu (VACUOUS) khỏi lỗi hậu kiểm.
7. **Đánh giá điều kiện dừng:** nếu không suy ra được `AllowedRoot` đủ chứng cứ hoặc không loại được FP nào trong phạm vi một vòng, ghi nhận và **ngừng thêm quy tắc**, chuyển hướng thiết kế đánh giá độc lập (hướng 2 cũ). Nếu có hiệu quả trên tập phát triển, chuyển sang mẫu repository mới chọn/khóa trước, không tái dùng mlflow/Django để tuyên bố hiệu quả độc lập.
8. **Sau đó** xem xét các tồn đọng ít ưu tiên hơn: `werkzeug.safe_join` trả `None`, đối số keyword, bảo toàn qua các kiểu method, duyệt thư mục/symlink, rà nhãn RC-M1, chạy lại các phần đợt B thiếu xác thực hash khi thật sự cần. Chỉ làm khi có giả thuyết và phản ví dụ tương ứng.

### Điều kiện dừng/tiêu chí chấp nhận

- 0 trường hợp nguy hiểm được v0.3 loại nhầm **trên các bộ phản ví dụ đã chạy**, 0 ca VACUOUS, 0 TP benchmark bị loại (kiểm thử hồi quy, không chứng minh bảo đảm tuyệt đối).
- Giữ tất cả TP/TP_conditional/unknown trong tập phát triển, nhất là **hai RC-M6**.
- Chuỗi tập con theo sink identity đạt trên toàn bộ tập đã chạy.
- Mọi cảnh báo loại được có hồ sơ chứng minh `ProvenContained + AllowedRoot`, nguồn chứng minh gốc, điều kiện ngoại lệ và giả định; không có bước taint bất kỳ nào được coi là bảo toàn mặc nhiên.
- Báo **riêng** số loại bởi chế độ strict so với scoped; không gộp hai chế độ để tuyên bố an toàn như nhau.
- Không sửa nhãn/kết quả đã khóa hoặc chọn tập đánh giá sau khi xem kết quả để làm tăng chỉ tiêu.

## 12. Thông tin cần yêu cầu/kiểm tra khi tiếp quản

- `git status --short`, `git log -5 --oneline`, nhánh hiện tại, đường dẫn repository và tên remote; các SHA hiện tại.
- Bản mới nhất trên ổ đĩa của `experiments/v03-interprocedural-guard/SPEC.md`, `ql/IpgGuard.qll`, model pack, expectation và các script; tệp `SPEC(1).md` trong hội thoại là bản **cũ hơn**.
- Các bảng gán nhãn được khóa và bảng rà soát mới nhất của RC-M1; bản nguồn/đích cụ thể để kiểm tra quyết định.
- Log và hash đầu vào của `cex_stage1_abc.json`, `dev_stage1_abc.json`, lịch sử `FREEZE_DEVIATION.md`, kết quả đợt B đã lưu. Các tệp dưới `artifacts/private/` chỉ nên sử dụng nội bộ trong môi trường có quyền truy cập thích hợp.

### Đoạn chỉ dẫn ngắn có thể đưa nguyên văn cho agent kế tiếp

> Bạn đang tiếp quản dự án giảm FP của Semgrep/CodeQL ở Python. Đọc kỹ tài liệu bàn giao này và **mã repo hiện tại** trước khi đề xuất sửa. Đường chính là CodeQL + kiểm chứng an toàn, v0.3 CWE-22. Các bộ thử v0.3 hiện báo 0 UNSOUND và giữ các TP/unknown, nhưng trên tập phát triển v0.3 loại **0/26 mlflow và 0/9 Django** vì không có hợp đồng `AllowedRoot`; validator đã nhận diện được nên đừng quay lại giải bài toán này như thể chưa làm. Quyết định mới nhất: thử **một vòng giới hạn** `resource-derived AllowedRoot` dựa trên chứng cứ độc lập về tài nguyên server, trước hết RC-M3/`SESSION_DIR`, giữ hai chế độ strict và scoped, khóa phản ví dụ trước khi chạy; không lấy `join(B,v)` hay tên thuộc tính làm hợp đồng. Giữ RC-M6/unknown, không hardcode cho mlflow, không dùng dữ liệu phát triển làm kiểm tra độc lập. Nếu không có quy tắc đủ chặt và kết quả giảm FP đáng tin, ghi nhận 0, dừng mở rộng và thiết kế đánh giá độc lập. Không sửa bản khóa/nội dung bảo mật riêng hoặc tuyên bố đã chạy/commit khi chưa xác minh.
