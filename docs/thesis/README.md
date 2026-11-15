# Hồ sơ đề án

Đề án thạc sĩ định hướng ứng dụng **"Xây dựng quy trình sàng lọc và thẩm định cảnh báo lỗ hổng
kết hợp Semgrep và CodeQL"**. Thư mục này chứa bản thảo ba chương, bảng đối chiếu với đề cương và
những gì cần để trình diễn. Cập nhật: 2026-11-15, nhánh `feat/cwe22-triage`: mọi thay đổi đã commit cục bộ, kể cả phần
phiên bản 0.3. Chưa push gì.

| Tài liệu | Dùng cho |
|---|---|
| [chuong-1-tong-quan.md](chuong-1-tong-quan.md) | Chương 1, đúng đề mục 1.1–1.5 của đề cương; trích dẫn đã đối chiếu với nguồn |
| [chuong-2-thiet-ke.md](chuong-2-thiet-ke.md) | Chương 2, đúng đề mục 2.1–2.6; giải trình điều chỉnh so với đề cương |
| [chuong-3-thuc-nghiem.md](chuong-3-thuc-nghiem.md) | Chương 3, đúng đề mục 3.1–3.5; mọi số liệu tái lập được |
| [ket-luan.md](ket-luan.md) | Phần Kết luận |
| [tai-lieu-tham-khao.md](tai-lieu-tham-khao.md) | Danh mục tài liệu tham khảo đã sửa theo nguồn; giữ số thứ tự của đề cương |
| [commitments.md](commitments.md) | Đối chiếu từng cam kết của đề cương với hiện trạng và minh chứng |
| [chapter-2-notes.md](chapter-2-notes.md), [chapter-3-results.md](chapter-3-results.md) | Ghi chú nguồn cho Chương 2 và 3: căn cứ mã nguồn, bảng số liệu chi tiết trên dữ liệu phát triển |
| [../demo/README.md](../demo/README.md) | Ảnh và kịch bản trình diễn trên ứng dụng chạy thật |
| [PROGRESS.md](PROGRESS.md) | Việc đã làm và bước tiếp theo, để tiếp tục khi gián đoạn |
| [../../profiles/command-injection-v0.3/PRIORITY_V0_3.md](../../profiles/command-injection-v0.3/PRIORITY_V0_3.md) | Đặc tả phiên bản 0.3: phạm vi tệp của Semgrep, bộ định vị v1, quy tắc gạn G4 |

Ba chương và phần Kết luận là văn bản đầy đủ theo đề mục của đề cương, viết bằng Markdown. Việc
còn lại để thành quyển nộp là của chủ đề án: duyệt nội dung, chuyển sang mẫu trình bày của
Học viện, và sửa danh mục tài liệu tham khảo theo bảng đối chiếu ở cuối Chương 1 (đề cương ghi
sai tác giả của [1], [6], [8]; không tìm thấy bài [9]).

## Quy trình đã cài đặt

**Phát hiện rộng → chuẩn hóa và gộp cảnh báo trùng → thẩm định và gạn cảnh báo sai → báo cáo
trước–sau.** CWE-78 (JavaScript/TypeScript và Python) là kịch bản chính; CWE-22 trên Python là
minh họa bổ sung.

## Chạy và trình diễn

```bash
# 1. Dựng toàn bộ ứng dụng (lần đầu tải CodeQL, Node.js, Bandit, ESLint theo phiên bản ghim)
docker compose up --build -d --wait --wait-timeout 900

# 2. Mở http://localhost:5173, tạo dự án, tạo lượt quét với profile
#    "CWE-78 · Command injection (thêm Bandit, ESLint)" cho nguồn GitHub:
#    owner OWASP-Benchmark, repo BenchmarkPython,
#    commit f1291485808b66e20ddb6b01b10dc71b3df8c8ba
#    (khoảng 1–3 phút; đây là dữ liệu phát triển)

# 3. Trên trang lượt quét: bấm "Đã gạn" để xem ứng viên bị gạn và mở lại cảnh báo gốc;
#    cuộn tới "Báo cáo trước–sau"; tải báo cáo JSON và SARIF hợp nhất.

# 4. Dựng lại các bảng của Chương 3 từ báo cáo đã lưu (không cần stack)
python experiments/evaluation/before_after.py \
  experiments/evaluation/inputs/owasp-benchmarkpython-v0.2 \
  --labels experiments/labels/owasp-python-cwe78-expectations.json
python experiments/evaluation/independent-secbench/configurations.py \
  experiments/evaluation/independent-secbench/labels.json \
  experiments/evaluation/independent-secbench/inputs
python experiments/evaluation/independent-secbench/configurations.py \
  experiments/evaluation/independent-python/labels.json \
  experiments/evaluation/independent-python/inputs
```

Kịch bản trình diễn tự động và ảnh chụp: [../demo/README.md](../demo/README.md).
Kiểm tra mã: xem [../../README.md](../../README.md#kiểm-tra) và kết quả đã ghi ở
[../validation.md](../validation.md).

## Bảng tiêu chí

Chỉ đánh dấu **Đạt** khi có đầu ra đã kiểm chứng trong repo. Cột trạng thái ghi rõ phạm vi dữ
liệu: *phát triển* là dữ liệu đã xem khi xây dựng quy trình; *độc lập* là mã chưa từng quét hay
đọc, có giao thức và nhãn băm trước khi quét.

| Tiêu chí | Trạng thái | Minh chứng |
|---|---|---|
| Đối chiếu đề cương, lập bảng cam kết | Đạt | [commitments.md](commitments.md) |
| Giữ tên đề tài và bố cục ba chương; có văn bản ba chương | Đạt: văn bản đầy đủ mọi đề mục, trích dẫn đã đối chiếu. Chưa chuyển sang mẫu trình bày của Học viện | [chuong-1](chuong-1-tong-quan.md), [chuong-2](chuong-2-thiet-ke.md), [chuong-3](chuong-3-thuc-nghiem.md), [ket-luan](ket-luan.md) |
| Giải trình trong Chương 2 việc bổ sung nguồn ứng viên ngoài Semgrep | Đạt | [chuong-2 §2.2](chuong-2-thiet-ke.md#22-thiết-kế-tổng-thể-quy-trình-phân-tích-nhiều-bước), [§2.4.1](chuong-2-thiet-ke.md#241-nguyên-tắc-thẩm-định-có-trọng-tâm) |
| Tập ứng viên là hợp Semgrep và CodeQL trên cùng phiên bản mã, tái dùng SARIF | Đạt | [pipeline.py](../../backend/app/scanners/pipeline.py), [sarif.py](../../backend/app/scanners/sarif.py); 97 báo cáo đã lưu của lượt quét thật |
| Gộp cảnh báo cùng một vấn đề, giữ nguồn gốc; ca chưa chắc chắn giữ riêng | Đạt, kèm một khiếm khuyết đã đo: trên dữ liệu độc lập, 4/43 cảnh báo đúng dòng lỗi không gộp được vào lời gọi và nằm ở hàng U | [adjudicate.py](../../backend/app/triage/adjudicate.py), [test_adjudicate.py](../../backend/tests/triage/test_adjudicate.py); OWASP: 51 cảnh báo → 20 ứng viên; [posthoc-missed.json](../../experiments/evaluation/independent-secbench/results/posthoc-missed.json) |
| Đo đóng góp riêng của từng nguồn | Đạt (phát triển và độc lập) | Cột "chỉ công cụ này báo" của báo cáo; độc lập: 3 vị trí chỉ CodeQL báo, 3 vị trí chỉ ESLint báo ([chuong-3 §3.3.2](chuong-3-thuc-nghiem.md#332-mức-giảm-cảnh-báo-sai-theo-đối-chiếu)) |
| Chọn công cụ mã nguồn mở để gạn, thử trên dữ liệu phát triển, ghi tên/phiên bản/bằng chứng/điều kiện/chi phí | Đạt (phát triển). Trên mã chưa từng xem, quy tắc dùng Semgrep (G3) chưa gạn ứng viên nào; quy tắc dùng Bandit (G2) gạn 19 | Semgrep CE 1.178.0 (LGPL-2.1), luật nhánh chết, quy tắc G3: gạn 1/7 cảnh báo sai, 0/13 lỗi thật; 13/13 ca kiểm tra với Semgrep thật. Bảng so các phương án: [chuong-3 §3.3.2(b)](chuong-3-thuc-nghiem.md#332-mức-giảm-cảnh-báo-sai-theo-đối-chiếu). Bằng chứng CodeQL (bộ máy không mã nguồn mở) là lớp thứ hai, báo cáo tách riêng |
| Chỉ gạn khi có căn cứ cụ thể; thiếu bằng chứng, mâu thuẫn, chạy dở thì giữ | Đạt | 10 mã lý do giữ, kiểm thử trong [test_adjudicate.py](../../backend/tests/triage/test_adjudicate.py), [test_api.py](../../backend/tests/workflows/scans/test_api.py). Độc lập: 4 lỗi thật Python được truy vấn bằng chứng xét và giữ lại |
| Lưu bản gốc và lý do gạn; đếm riêng cảnh báo chỉ hạ ưu tiên | Đạt | `disposition`, bản ghi `adjudication`, cột "demoted" của báo cáo |
| So sánh Semgrep riêng, CodeQL riêng, tập hợp đã khử trùng, tập sau gạn trên cùng phiên bản mã và đơn vị đếm | Đạt: đủ nhãn trên dữ liệu phát triển (CWE-78 Python) và trên 210 vị trí độc lập có hai loại nhãn (lượt quét lại sau khi sửa lỗi); chỉ nhãn dương tính trên 43 vị trí JS và 7 vị trí Python độc lập còn lại | [owasp-benchmarkpython-v0.2.json](../../experiments/evaluation/results/owasp-benchmarkpython-v0.2.json); [independent-secbench/results](../../experiments/evaluation/independent-secbench/results/configurations.json); [independent-python/results](../../experiments/evaluation/independent-python/results/configurations.json) |
| Đo lỗi đúng, bỏ sót, sai gạn đúng, đúng gạn nhầm, chưa xác định bị gạn, thời gian | Đạt | [chuong-3 §3.3](chuong-3-thuc-nghiem.md#33-các-chỉ-số-đánh-giá). Lỗi đúng bị gạn nhầm: 0/13 (phát triển), 0/7 Python và 0/37 JS (độc lập) |
| Precision, recall, F1 khi đủ nhãn | Đạt trên dữ liệu phát triển (bảng a). Trên dữ liệu độc lập: **đạt ngoài kết quả đã đăng ký** — lượt quét đã đăng ký của đợt 4 thất bại vì lỗi của nguyên mẫu; số liệu lấy từ lượt quét lại sau khi sửa (hợp mọi nguồn: P 0,66, R 0,71, F1 0,69; Semgrep riêng 0,88/0,36/0,51; CodeQL riêng 1,00/0,15/0,26). Chưa có trên mã ứng dụng thật | Bảng (a) và (f) của [chuong-3 §3.3.2](chuong-3-thuc-nghiem.md#332-mức-giảm-cảnh-báo-sai-theo-đối-chiếu); [DEVIATIONS.md](../../experiments/evaluation/independent-labeled/DEVIATIONS.md) |
| Chốt tiêu chí lọc trước khi chấm; ghi tập phát triển, nguồn nhãn, giới hạn | Đạt, kèm giới hạn: tiêu chí được thiết kế khi đã biết benchmark; năm đợt độc lập được đăng ký bằng mã băm cục bộ và chỉ commit sau khi quét; riêng tập giữ lại `pairs-v1` có cấu hình được commit trước khi quét | [experiments/evaluation/README.md](../../experiments/evaluation/README.md); năm tệp `PREREGISTRATION.json`; sai lệch được ghi ở hai tệp `DEVIATIONS.md` ([đợt 2–3](../../experiments/evaluation/independent-secbench/DEVIATIONS.md), [đợt 4](../../experiments/evaluation/independent-labeled/DEVIATIONS.md)) |
| Kiểm tra trên mã chưa từng xem | Đạt, phạm vi: 79 nguồn (52 package npm có CVE thật, 6 ứng dụng luyện tập, 1 kho mã minh họa có hai loại nhãn, 20 công cụ dòng lệnh Python không có nhãn) | JS: 32/43 vị trí ở lượt quét hoàn tất được báo (CodeQL riêng 27, Semgrep riêng 12). Python: 7/7. Mã minh họa: 96/135 vị trí có lỗi. Không vị trí nào bị gạn. [independent-labeled/](../../experiments/evaluation/independent-labeled/PROTOCOL.md), [independent/](../../experiments/evaluation/independent/PROTOCOL.md), [independent-secbench/](../../experiments/evaluation/independent-secbench/PROTOCOL.md), [independent-python/](../../experiments/evaluation/independent-python/PROTOCOL.md) |
| Đánh giá trên tập giữ lại `pairs-v1` | **Đạt**, phạm vi: 16 cặp, 9 vị trí lỗi đã biết, chỉ nhãn dương tính; phiên bản 0.3 đóng băng trước khi quét | Hợp mọi nguồn báo 7/7 vị trí ở lượt quét hoàn tất (CodeQL riêng 6, Semgrep riêng 3), 9/9 tính cả lượt chạy dở; 0 bị gạn; 6/7 ở P1+P2. Cả 16 nguồn đúng byte đã khóa. [result.json](../../experiments/evaluation/pairs-v1/held_out/result.json), [Amendment 08](../../experiments/amendments/AMENDMENT_08_HELD_OUT_WITH_V0_3.md), [HELD_OUT_GATE.json](../../experiments/evaluation/pairs-v1/HELD_OUT_GATE.json). Tập phát triển (v0.2): 21/22, [result.json](../../experiments/evaluation/pairs-v1/development/result.json) |
| Báo cáo cả kết quả ngang hoặc kém đối chứng | Đạt | F1 sau gạn 0,84 so với CodeQL riêng 0,85; G2 gạn 0 ca; trên dữ liệu độc lập bước gạn không gạn gì (ở đợt 4 vì lượt quét chạy dở); 11/43 lỗ hổng thật không được báo; độ chính xác của hợp các nguồn (0,66) thấp hơn Semgrep và CodeQL chạy riêng; nhóm rà trước chỉ chứa 37/135 vị trí có lỗi của đợt 4; 3 lượt quét hỏng vì hai lỗi của nguyên mẫu |
| CWE-22 báo riêng làm minh họa | Đạt | [chuong-3 §3.3.2(h)](chuong-3-thuc-nghiem.md#332-mức-giảm-cảnh-báo-sai-theo-đối-chiếu) |
| Trình diễn trên ứng dụng chạy thật: ca một công cụ báo được giữ, ca trùng được gộp, ca sai được gạn có lý do, mở lại bản gốc, xuất báo cáo | Đạt | [adjudication-demo.mjs](../demo/adjudication-demo.mjs) chạy qua trên stack thật; ảnh trong [../demo/](../demo/README.md) |
| Bảng đối chứng tái lập được | Đạt | [test_evaluation.py](../../experiments/tests/test_evaluation.py) dựng lại mọi tệp kết quả từ báo cáo đã lưu và kiểm mã băm của 97 thư mục báo cáo |
| Tự kiểm thử, sửa lỗi và chạy lại | Đạt | Hai lỗi làm hỏng lượt quét, đều do dữ liệu độc lập làm lộ: tệp có `\r\n` (JavaScript) và tệp Python sai cú pháp. Cả hai đã sửa, có kiểm thử hồi quy, và nguồn bị lỗi được quét lại ([đợt 2](../../experiments/evaluation/independent-secbench/posthoc-after-fix/result.json), [đợt 4](../../experiments/evaluation/independent-labeled/results/posthoc-after-fix.json)) |
| Bước gạn hành động trên mã chưa từng xem, ở lượt quét hoàn tất | Đạt cho quy tắc G2; chưa đạt cho G1 và G3 | Đợt 5: 18/20 lượt hoàn tất, 19/145 ứng viên bị gạn. Phép kiểm độc lập đã đăng ký: 17 lệnh hằng, 2 bị đánh "không hằng"; đọc lại sau đó cho thấy cả hai là lệnh hằng bọc trong `int()`/`bool()`. [READING.md](../../experiments/evaluation/independent-filter/READING.md) |
| Hướng dẫn chạy; ghi chú Chương 2–3 | Đạt | Tài liệu trong thư mục này |

## Giai đoạn JavaScript/TypeScript (phiên bản 0.3, ngày 2026-11-15)

Toàn bộ là dữ liệu phát triển; chi tiết ở [READING.md](../../experiments/evaluation/js-matching-v0.3/READING.md).

| Tiêu chí | Trạng thái | Minh chứng |
|---|---|---|
| Tìm nguyên nhân bốn ca ghép hụt từ đầu ra đã lưu | Đạt | Hai ca do Semgrep bỏ qua `build/`, hai ca do luật định vị thiếu bí danh hai bước; không ca nào do bước chuẩn hóa hay đối sánh. [READING.md §1](../../experiments/evaluation/js-matching-v0.3/READING.md) |
| Sửa nguyên nhân khái quát được | Đạt | Phạm vi tệp do worker quyết định; bộ định vị v1 là tập cha của v0. [PRIORITY_V0_3.md](../../profiles/command-injection-v0.3/PRIORITY_V0_3.md) |
| Kiểm thử ca phải ghép và ca hai lời gọi gần nhau phải giữ riêng | Đạt | Semgrep thật: 19/19 ca định vị; [test_javascript_matching.py](../../backend/tests/triage/test_javascript_matching.py); backend 483 test đạt |
| Giữ riêng và ghi lý do khi thiếu căn cứ | Đạt | 14 cảnh báo vẫn ở hàng U, bốn nhóm lý do. [READING.md §4](../../experiments/evaluation/js-matching-v0.3/READING.md) |
| Đo riêng số ca ghép đúng được cải thiện và số ca ghép nhầm | Đạt (dữ liệu phát triển) | 84 nguồn: hàng U 37 → 14 ứng viên; 23 cảnh báo gộp thêm; 0 ghép nhầm; 0 mất ghép. [compare.json](../../experiments/evaluation/js-matching-v0.3/results/compare.json) |
| Chọn một nhóm cảnh báo sai hẹp cho JS/TS và xác định công cụ có đủ bằng chứng không | Đạt | Nhóm lệnh hằng; Semgrep CE đủ bằng chứng: 20/20 ca tổng hợp (6 hằng, 14 không hằng) |
| Tích hợp điều kiện gạn vào cấu hình mới, giữ đường dẫn về cảnh báo gốc và lý do | Đạt | Quy tắc G4 trong profile `command-injection-v0.3`; bản ghi thẩm định có luật bằng chứng, vùng mã lời gọi, mã băm tệp luật |
| Im lặng của công cụ hoặc việc ghép được không đủ để gạn | Đạt | G4 đòi bằng chứng đúng vùng mã lời gọi và không có công cụ nào khẳng định luồng; 7 ca phải giữ trong kiểm thử |
| Báo riêng số cảnh báo sai gạn đúng, cảnh báo đúng gạn nhầm, ca chưa đủ căn cứ | Đạt, với nhãn đối chứng độc lập cho nhóm lệnh hằng | 120 ứng viên gọi `exec`/`execSync`: cảnh báo sai nhóm lệnh hằng gạn đúng 1/1; ứng viên lệnh không hằng gạn nhầm 0/116; 0/62 vị trí lỗi đã biết bị gạn; 3 không đọc được. [constant-reference.json](../../experiments/evaluation/js-matching-v0.3/results/constant-reference.json) |
| Độ chính xác, độ bao phủ, F1 trên JavaScript có nhãn | Đạt trên 25 vị trí của bộ I4 (dữ liệu phát triển): v0.2 → v0.3 là 1,00/0,40/0,57 → 0,86/0,80/0,83 | [DEVIATIONS.md §4](../../experiments/evaluation/independent-labeled/DEVIATIONS.md) |
| Kết luận về điều kiện gạn đã thử | Đạt: G4 đúng (1/1, 0/116) nhưng tác động không đáng kể (1/146 ứng viên JavaScript) | [READING.md §5](../../experiments/evaluation/js-matching-v0.3/READING.md) |
| Cảnh báo sai trên JavaScript ngoài nhóm lệnh hằng | **Đạt trên nhãn đã có người kiểm** (chủ đề án rà từng ca cả 84 nhãn do trợ lý AI đề xuất, sửa 12, tách một ca thành bảy): 11/133 ứng viên đã quyết định là cảnh báo sai; bước gạn chuyển đi 1, gạn nhầm 0/122; 10 ca còn lại chưa có bằng chứng gạn. Dữ liệu phát triển, một người rà | [js-labels-v0.3/](../../experiments/evaluation/js-labels-v0.3/README.md), [labels.json](../../experiments/evaluation/js-labels-v0.3/labels.json), [score.json](../../experiments/evaluation/js-labels-v0.3/results/score.json) |
| Độ chính xác, độ bao phủ, F1 trên ứng viên JavaScript của mã thật | **Đạt trên nhãn đã có người kiểm**: hợp mọi nguồn 0,92 / 0,95 / 0,93 (TP 122, FP 11); CodeQL riêng 0,98 / 0,76 / 0,86; Semgrep ∪ CodeQL 0,96 / 0,85 / 0,90. Độ bao phủ và F1 là cận trên | [score.json](../../experiments/evaluation/js-labels-v0.3/results/score.json) |
| Ghi rõ dữ liệu dùng để sửa và dữ liệu dùng để đánh giá | Đạt | 10 nguồn đã đọc mã, 74 nguồn chưa đọc mã, báo tách riêng. [README.md](../../experiments/evaluation/js-matching-v0.3/README.md) |
| Kiểm thử luồng bị ảnh hưởng trên ứng dụng; trình diễn một ca JS/TS | Đạt | [js-matching-demo.mjs](../demo/js-matching-demo.mjs) chạy qua trên stack thật; ảnh trong [../demo/](../demo/README.md) |
| Đoạn bổ sung cho Chương 2–3 | Đạt | [chuong-2 §2.3.3, §2.4.2, §2.4.3](chuong-2-thiet-ke.md), [chuong-3 §3.3.2 (i), (j)](chuong-3-thuc-nghiem.md) |
| Giữ kết quả nghiên cứu đã khóa | Đạt | Profile v0.2 không đổi một byte; tệp đã đăng ký của các đợt độc lập không đổi, hai tệp mã quy trình thay đổi được ghi ở [PIPELINE_CHANGES.json](../../experiments/evaluation/PIPELINE_CHANGES.json) |

## Còn thiếu, và thao tác cần có

| Việc | Vì sao chưa có | Thao tác còn thiếu |
|---|---|---|
| Đánh giá độc lập cho phiên bản sau v0.3 | Tập giữ lại của `pairs-v1` đã được dùng | Một tập giữ lại mới |
| Độ chính xác trên mã ứng dụng thật cho CWE-78 | Dữ liệu độc lập có nhãn an toàn chỉ là mã minh họa của luật (đợt 4) | Một người gán nhãn mẫu ứng viên ngoài vị trí lỗi đã biết (47 ứng viên của đợt 2 là điểm bắt đầu) |
| Quy tắc gạn dựa trên luồng dữ liệu (G1, G3) hành động trên dữ liệu độc lập | Ở đợt 5 bước gạn đã hành động ở lượt quét hoàn tất (19/145 ứng viên, đều là lệnh hằng, quy tắc G2). G1 và G3 chưa gạn ứng viên nào ngoài dữ liệu phát triển | Dữ liệu độc lập có cảnh báo sai thuộc loại nhánh chết hoặc rào chắn mà gói bằng chứng mô tả; hoặc mở rộng gói bằng chứng theo mã thật |
| Bước gạn bị tắt khi lượt quét chạy dở | Thiết kế bảo thủ: một tệp không phân tích được là đủ | Quyết định có thu hẹp nguyên tắc "chạy dở thì giữ" xuống mức tệp (cần phiên bản bộ quy tắc mới và đánh giá lại) |
| Bằng chứng gạn cho các loại cảnh báo sai JavaScript còn lại | Đã đo trên nhãn có người kiểm: bước gạn chuyển đi 1/11, còn 10 ca (6 đã kiểm tra hoặc trích dẫn, 2 giá trị nội bộ, 1 không qua shell, 1 lệnh hằng không được định vị) | Quyết định viết bằng chứng gạn cho loại nào; người rà thứ hai độc lập với quy trình nếu cần. Chi tiết ở [js-labels-v0.3/](../../experiments/evaluation/js-labels-v0.3/README.md) |
| 14 cảnh báo JavaScript vẫn ở hàng U sau phiên bản 0.3 | Thiếu căn cứ ghép: một cảnh báo nêu nhiều lời gọi (8), cảnh báo ở dòng nhập module (4), tệp đã đóng gói (1), thư viện bọc `mz/child_process` (1) | Cách biểu diễn một cảnh báo liên quan tới nhiều lời gọi; mở rộng danh sách module của bộ định vị |
| Dùng danh mục tài liệu tham khảo đã sửa | Danh mục của đề cương ghi sai tác giả ở [1], [6], [8] và có mục [9] không tìm thấy; bản đã sửa nằm ở [tai-lieu-tham-khao.md](tai-lieu-tham-khao.md) | Chủ đề án duyệt bản đã sửa, kiểm số trang và DOI của [1], đọc lại [5] |
| Phiếu rà soát của người rà, tích hợp CI/CD | Ngoài phạm vi đợt này | Xem [commitments.md](commitments.md) |
