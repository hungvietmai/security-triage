# Tổng quan nghiên cứu

Điểm vào duy nhất cho trạng thái nghiên cứu. Cập nhật ngày 2026-10-27, ứng với commit
`8e99ecc` (nhánh `feat/research-safety-evidence`). Mọi số liệu dưới đây dẫn từ báo cáo
đã commit; mỗi mục có liên kết tới nguồn.

Nhiều tài liệu nghiên cứu bị khóa bằng SHA-256 và không được sửa, kể cả
[RESEARCH_LOG.md](../experiments/RESEARCH_LOG.md) (dừng ở mục ngày 2026-10-08). Vì vậy,
trạng thái mới chỉ được cập nhật ở đây và trong các tài liệu "sống" (xem
[mục 7](#7-quy-ước-tài-liệu)).

## 1. Câu hỏi nghiên cứu hiện tại

> Bằng chứng an toàn viết trong CodeQL có loại được cảnh báo sai (FP) **CWE-22** (vượt
> thư mục) trên mã **Python** mà không loại nhầm cảnh báo đúng (TP) hay không?

- **Đầu vào:** cảnh báo của truy vấn CodeQL mặc định (CodeQL 2.27.1, `python-queries`
  1.8.11, `python-all` 7.2.6).
- **Cơ chế:** thêm barrier hoặc loại trừ sink khi chứng minh được điều kiện an toàn.
  Thiếu bằng chứng, đường đi chưa phân giải được hoặc giả định không rõ thì **giữ cảnh báo**.
- **Ưu tiên:** không loại nhầm TP quan trọng hơn số FP loại được.
- **Ngoài phạm vi:** tầng này chỉ loại cảnh báo, nên recall không thể tăng. Lỗ hổng mà
  CodeQL bỏ sót vì thiếu mô hình nguồn/sink là bài toán phát hiện (FN), không phải giảm FP.
- **Semgrep** chỉ còn vai trò đối chứng: ở CWE-22 nó không cung cấp bằng chứng nào mà
  CodeQL thiếu (xem [mục 3.2](#32-benchmarkpython-bốn-cwe-1510)).

## 2. Diễn tiến

| # | Giai đoạn | Thời gian | Kết luận chính | Trạng thái |
|---:|---|---|---|---|
| 1 | CWE-78, Semgrep → thẩm định bằng CodeQL (JS + Python) | 24/09–08/10 | Recall của chuỗi bị chặn bởi Semgrep; CodeQL đơn lẻ tốt hơn | Dừng; mã vẫn chạy trong ứng dụng |
| 2 | BenchmarkPython, 4 CWE, ba công cụ | 15/10 | FP tập trung ở CodeQL (CWE-22/643); Semgrep không bổ sung bằng chứng | Hoàn tất |
| 3 | Bằng chứng an toàn v0.1 → v0.2 | 15–16/10 | v0.1 loại nhầm 10 phản ví dụ nên bị bỏ; v0.2 không loại nhầm | v0.2 là baseline |
| 4 | Đợt A: 2 dự án thật | 16/10 | Quá ít cảnh báo, chạm điều kiện dừng | Hoàn tất |
| 5 | Đợt B: 11 cặp CVE lỗi/vá | 16–21/10 | CodeQL không báo vị trí CVE nào; v0.2 loại 1/33 FP | 17/60 nhãn chờ duyệt |
| 6 | v0.3 strict/scoped (guard liên thủ tục) | 17–20/10 | Dev: strict loại thêm 0, scoped loại 8 (một nguyên nhân gốc) | Đóng băng |
| 7 | Đợt C: đánh giá độc lập, công bố giao thức trước khi quét | 21/10 | v0.3 loại thêm **0** so với v0.2 | Chờ owner review |
| 8 | Tự rà kỹ thuật + bản thử v0.2.1 | 21/10 | `failed_acceptance` trên nhãn tự rà; v0.2.1 giữ lại ca bị loại | Chỉ là dữ liệu phát triển |

## 3. Kết quả theo giai đoạn

### 3.1 Giai đoạn CWE-78 (lịch sử)

Thiết kế: [giao thức v1.0.0](../experiments/EVALUATION_PROTOCOL.md) và
[Amendment 01–05](../experiments/amendments/). Chi tiết theo ngày nằm trong
[RESEARCH_LOG.md](../experiments/RESEARCH_LOG.md).

- **OWASP BenchmarkPython, 20 site CWE-78** ([báo cáo](../experiments/reports/owasp-python-development/REPORT.md)):
  Semgrep 7 TP / 7 FP / 6 FN; CodeQL 11 / 2 / 2. Một bộ lọc chỉ loại trên ứng viên Semgrep
  đạt F1 tối đa 0,70, trong khi CodeQL đơn lẻ đạt 0,85. Vì vậy
  [Amendment 01](../experiments/amendments/AMENDMENT_01_QT.md) chuyển ứng viên chính sang CodeQL.
- **11 package npm thật** (batch [01](../experiments/reports/development-batch-01/REPORT.md),
  [02](../experiments/reports/development-batch-02/REPORT.md),
  [03](../experiments/reports/development-batch-03/REPORT.md)): không xác nhận được FP nào trong phạm vi.
- **Sản phẩm của giai đoạn này**: bộ gộp `reconcile-v0.1` và chính sách ưu tiên
  [priority v0.1](../experiments/policy/PRIORITY_V0_1.md) (P1–P4/U, không xóa cảnh báo).
  Trên 20 site OWASP: TP rơi vào P1 = 7, P2 = 4; FP rơi vào P1 = 2, P3 = 5. Đây là phần
  ứng dụng web đang chạy (xem [architecture.md](architecture.md)).
- **pairs-v1** ([pairs/README.md](../experiments/pairs/README.md)): 50 cặp lỗi/vá được khóa
  nguồn (Ray lỗi tải do vượt 50 MiB). Vị trí lỗi đã xác định cho 26/34 cặp phát triển và
  9/16 cặp held-out. **Chưa quét cặp nào**, nên tập held-out này vẫn chưa được mở.
- Toàn bộ nhãn của giai đoạn này do assistant viết, chưa có người duyệt.

### 3.2 BenchmarkPython bốn CWE (15/10)

Nguồn: [owasp-bp-pilot/README.md](../experiments/owasp-bp-pilot/README.md), phần 1–2.
Dữ liệu gồm 463 ca tổng hợp (CWE-22/78/79/643), chia theo hash thành nửa phát triển
(235 ca: 82 lỗi / 153 an toàn) và nửa kiểm tra (228 ca: 78 / 150).

| Cấu hình | Phát triển TP / FP / FN | Kiểm tra TP / FP / FN |
|---|---|---|
| A — Semgrep (61 rule cộng đồng) | 8 / 16 / 74 | 7 / 9 / 71 |
| B — CodeQL mặc định | 38 / 61 / 44 | 37 / 53 / 41 |
| C — A ∪ B | 40 / 69 / 42 | 37 / 59 / 41 |
| E — CodeQL + bằng chứng v0.1 | 38 / 0 / 44 | 37 / 0 / 41 |
| F — C + bộ quyết định | 40 / 8 / 42 | 37 / 6 / 41 |

- Gần như mọi FP thuộc nhóm chỉ CodeQL báo, ở CWE-22 và CWE-643. Semgrep không có rule
  XPath, và rule path traversal của nó chỉ bắt `open(request…)` trực tiếp.
- Đưa Semgrep vào (cấu hình F) làm giảm precision so với E.
- **Giới hạn:** hai nửa sinh từ cùng một bộ mẫu, nên kết quả nửa kiểm tra không đo được khả
  năng tổng quát sang mã thật.

### 3.3 Phản ví dụ và v0.2 (15–16/10)

Nguồn: [owasp-bp-pilot/README.md](../experiments/owasp-bp-pilot/README.md), phần 3. Bộ phản
ví dụ gồm 47 hàm Flask viết từ ngữ nghĩa của từng điều kiện an toàn.

| Phiên bản | UNSOUND (ca nguy hiểm bị loại) | MISSED | VACUOUS | Đạt |
|---|---:|---:|---:|---:|
| v0.1 (đóng băng) | **10** | 4 | 2 | 31 |
| v0.2 | **0** | 4 | 2 | 41 |

- v0.1 bị bỏ vì loại nhầm 10 ca nguy hiểm, ví dụ `startswith` không có dấu phân cách hay
  `..` kết hợp `os.path.join` với đường dẫn tuyệt đối.
- **v0.2 trên BenchmarkPython:** nửa kiểm tra còn 37 TP / 4 FP (loại 49/53 FP, tức 92,5%),
  **không mất TP** ở cả hai nửa. Chín FP còn lại đều dùng `startswith` không có dấu phân cách,
  và nhãn "an toàn" của OWASP cho các ca này còn tranh cãi.
- Query: [ql_v02/](../experiments/owasp-bp-pilot/ql_v02/). Khóa:
  `FREEZE_v0.2.sha256` và `FREEZE_v0.2_postformat.sha256` (xem
  [FREEZE_DEVIATION.md](../experiments/owasp-bp-pilot/FREEZE_DEVIATION.md)).

### 3.4 Đợt A — hai dự án thật (16/10)

Nguồn: [wave-a/README.md](../experiments/wave-a/README.md).

- **Flask-Admin:** 3 cảnh báo CWE-22 cùng một nguyên nhân (`is_in_folder` dùng `startswith`
  không có dấu phân cách). Nhãn `true_positive_conditional`, đã được chủ đề án duyệt.
  v0.2 không loại cảnh báo nào.
- **Paperless-ngx:** CodeQL không có cảnh báo nào trong bốn CWE.
- Đợt dừng theo điều kiện dừng đặt trước vì quá ít cảnh báo.

### 3.5 Đợt B — 11 cặp CVE lỗi/vá (16–21/10)

Nguồn: [wave-b/results/RESULTS.md](../experiments/wave-b/results/RESULTS.md); cách chọn mẫu ở
[SELECTION_PROTOCOL.md](../experiments/wave-b/SELECTION_PROTOCOL.md).

- **CodeQL không báo vị trí CVE nào trong cả 11 cặp**, ở cả bản lỗi lẫn bản vá. Phân tích
  độ phủ cho thấy nguồn (tham số tool MCP, tên member archive, request Quart…) hoặc sink
  (Selenium XPath) không được mô hình hóa.
- Có 60 cảnh báo khác, nằm ngoài vị trí CVE:

  | Phạm vi | Cảnh báo | TP | TP có điều kiện | FP | unknown | v0.2 loại đúng FP | v0.2 loại nhầm TP |
  |---|---:|---:|---:|---:|---:|---:|---:|
  | Mã sản phẩm | 44 | 4 | 3 | 33 | 4 | 1/33 | 0/7 |
  | Mã kiểm thử | 16 | 10 | 0 | 6 | 0 | 0/6 | 0/10 |

- 19/33 FP của mã sản phẩm do **guard liên thủ tục** (mlflow, Django). Đây là lý do làm v0.3.
- **RC-M6** (mlflow, 2 unknown) có thể là lỗ hổng thật. Chi tiết được giữ ngoài Git cho tới
  khi xác minh và báo kín cho maintainer.
- **Trạng thái nhãn:** 43/60 cảnh báo đã có quyết định của chủ đề án (14 trong số đó là tạm
  thời); 17 vẫn chờ duyệt.

### 3.6 v0.3 strict/scoped (17–20/10)

Nguồn: [v03-interprocedural-guard/README.md](../experiments/v03-interprocedural-guard/README.md),
[SPEC.md](../experiments/v03-interprocedural-guard/SPEC.md),
[quyết định](../experiments/v03-interprocedural-guard/DECISION_2026-10-20.md).

- Chứng minh guard ở hàm khác chặn bằng ngoại lệ. Ba thuộc tính trung gian là `Segment`,
  `SafeRel` và `Contained`. Chỉ được loại khi có thêm `AllowedRoot` (hợp đồng gốc của sink).
- **strict** (mặc định) chỉ dùng hợp đồng khai báo hoặc hợp đồng cục bộ. **scoped** thêm
  hợp đồng suy từ tài nguyên, dưới bốn giả định S-TEST, S-TMP, S-PURPOSE và S-ENV.
- Trên dữ liệu phát triển mlflow/Django: strict loại thêm 0; scoped loại 8 cảnh báo RC-M3,
  tất cả cùng một nguyên nhân gốc trên một repository.
- **Nút thắt** là chứng minh `AllowedRoot`, không phải nhận diện validator.
- Cả hai chế độ đã đóng băng bằng `FREEZE_v0.3_dual.sha256`.

### 3.7 Đợt C — đánh giá độc lập (21/10)

Nguồn: [giao thức](../experiments/wave-c/PROTOCOL.md),
[kết quả](../experiments/wave-c/results/study-001/RESULTS.md),
[quyết định](../experiments/wave-c/DECISION_2026-10-21.md),
[báo cáo tổng hợp](../experiments/wave-c/closeout/REPORT.md). Giao thức được công bố trước
khi quét (biên nhận ở [publication.json](../experiments/wave-c/publication.json)).

- 12 repository được chọn theo hash từ advisory PyPI CWE-22. Có 7 repository quét xong;
  3 vượt giới hạn 50 MiB (pytorch/serve, khoj, open-webui) và 2 bị từ chối vì archive chứa
  symlink (linuxfabrik/lib, scout).
- **Số sink trên 7 lượt quét:** `none` = 8 → `v0.2` = 5 → `strict` = 5 → `scoped` = 5.
- v0.3 **loại thêm 0/5** sink; `AllowedRoot` nhận diện được 0/5. Cả 5 sink còn lại đều thuộc
  một repository (atomic-agents-stack). Ba sink v0.2 loại đều ở pipecat và không phải đóng
  góp của v0.3.
- Đã chạy 105 lệnh scanner/diagnostic, tổng 3.358,2 giây; đối chiếu được 2.783 tệp `.py`.
- **Tự rà kỹ thuật** ([REVIEW.md](../experiments/wave-c/closeout/self-review/REVIEW.md)):
  nhãn đề xuất thành 2 FP có điều kiện và 6 unknown. Evaluator trả `failed_acceptance` vì
  v0.2 đã loại một ca nay được xếp unknown. Đây chưa phải TP bị loại đã được xác nhận.

### 3.8 Bản thử v0.2.1 (21/10, chỉ là phát triển)

Nguồn: [v021-normalization/README.md](../experiments/v021-normalization/README.md).

- Bỏ loại trừ sink `Path.resolve`/`os.path.realpath` dựa trên kiểm tra containment phía sau.
- Kết quả: giữ lại sink pipecat `run.py:215:18`, nâng tổng số sink từ 5 lên 6 trên 7 repository
  của đợt C. Không mất sink cũ trong các hồi quy đã chạy.
- Vì dữ liệu đợt C đã được dùng để sửa, kết quả này **không** được tính là kiểm chứng độc lập.

## 4. Những gì được phép kết luận

**Có thể nói, kèm điều kiện:**

- Trên benchmark tổng hợp, v0.2 loại 92,5% FP của CodeQL ở nửa kiểm tra mà không mất TP.
- Guard ngây thơ là không an toàn: v0.1 loại nhầm 10 phản ví dụ nguy hiểm.
- Trên mã thật, bằng chứng an toàn loại được rất ít FP: đợt B 1/33; đợt C v0.2 loại 3/8 sink
  (nhãn chưa duyệt) và v0.3 loại thêm 0.
- Hai nút thắt quan sát được: độ phủ mô hình nguồn/sink của CodeQL (0/11 vị trí CVE ở đợt B)
  và việc chứng minh gốc hợp lệ của sink (`AllowedRoot` 0/5 ở đợt C).

**Chưa thể nói:**

- Tỷ lệ giảm FP trên mã thật: chưa có mẫu số FP đã được duyệt, nên giá trị là N/A (không phải 0%).
- v0.2 hoặc v0.3 an toàn tổng quát, hoặc tổng quát hóa ra ngoài các mẫu đã đo.

## 5. Việc còn mở

1. **Owner review đợt C**, theo [START_HERE.md](../experiments/wave-c/closeout/owner-review/START_HERE.md).
   - Lượt 1: rà 8 sink rồi chạy evaluator đã khóa.
   - Lượt 2: sau ít nhất 7 ngày kể từ lượt 1, rồi hòa giải hai lượt.
2. **Đợt B:** duyệt 17 cảnh báo còn chờ (RC-M4, M5, M7, D1, D2, C1, C2).
3. **RC-M6:** xác minh trong môi trường cô lập; nếu đúng là lỗ hổng, báo kín cho mlflow.
4. **Đợt C:** kiểm tra near-duplicate ở mức ngữ nghĩa giữa các snapshot.
5. **Chọn baseline v0.2 hay v0.2.1.** Mọi đánh giá mới cần giao thức mới và dữ liệu chưa từng xem.
6. **Tích hợp ứng dụng:** worker vẫn chạy profile CWE-78 (`command-injection-v0.1`).
   Phương pháp CWE-22 v0.2/v0.3 chưa có trong ứng dụng.
7. **Tập held-out CWE-78** (16 cặp, chưa quét): quyết định chính thức bỏ hay dùng tiếp.
8. **Script bị khóa trên Windows:** code chưa khóa đã được sửa để đọc/ghi UTF-8 (27/10), nhưng
   các script bị khóa vẫn dùng bảng mã mặc định. Trên Windows phải chạy chúng với `PYTHONUTF8=1`.

## 6. Quy tắc bất biến

- Không thực thi source của dự án được quét, không cài dependency của nó, không chạy exploit.
- **Giới hạn archive:** 50 MiB tải về, 200 MiB giải nén, 20.000 mục. Từ chối path traversal
  và symlink trỏ ra ngoài gốc.
- **Phiên bản đã ghim:** Semgrep 1.178.0; CodeQL 2.27.1; `python-all` 7.2.6;
  `python-queries` 1.8.11; `javascript-queries` 2.4.6 ([tools/pins.env](../tools/pins.env)).
  Luôn dùng `--rerun` khi thay thư viện truy vấn.
- **Khóa trước khi chạy:** giao thức, mẫu, query và evaluator được khóa trước khi quét.
  Không sửa file đã khóa; mọi thay đổi phải tạo phiên bản và khóa mới kèm lý do.
- **Giữ thất bại:** lỗi tải, lỗi quét và kết quả bất lợi được giữ nguyên, không thay mẫu.
- **Dữ liệu đã xem là dữ liệu phát triển.** Nhãn tách khỏi đầu vào scanner. Đánh giá độc lập
  phải dùng dữ liệu chọn và khóa trước khi quét.

## 7. Quy ước tài liệu

- **Tài liệu sống**, phải phản ánh trạng thái hiện tại:
  - [README.md](../README.md), [docs/](.) và [experiments/README.md](../experiments/README.md);
  - các hướng dẫn `AGENTS.md`;
  - các tệp trạng thái chưa khóa như [closeout/STATUS.md](../experiments/wave-c/closeout/STATUS.md).
- **Tài liệu khóa:** tài liệu có SHA-256 nằm trong một manifest khóa (`*.sha256` hoặc profile
  scan). Không sửa, không đổi tên. Danh sách và cách kiểm tra nằm trong
  [experiments/README.md](../experiments/README.md#tài-liệu-bị-khóa).
- **Hồ sơ lịch sử:** báo cáo, amendment và nhật ký có ngày. Giữ nguyên nội dung; trạng thái
  mới chỉ cập nhật ở tài liệu sống.
- **Ngôn ngữ:**
  - Tiếng Việt: tài liệu tổng quan và nghiên cứu.
  - Tiếng Anh: hướng dẫn cho agent (`AGENTS.md`) và README nằm cạnh mã.
  - Hồ sơ lịch sử giữ nguyên ngôn ngữ gốc.
- [SECURITY_TRIAGE_AGENT_HANDOFF_2026-10-20.md](../SECURITY_TRIAGE_AGENT_HANDOFF_2026-10-20.md)
  ở thư mục gốc là ảnh chụp ngày 20/10, đã bị khóa bởi đợt C. Trạng thái hiện tại xem ở tài liệu này.
