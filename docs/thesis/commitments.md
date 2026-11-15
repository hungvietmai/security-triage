# Đối chiếu cam kết của đề cương với hiện trạng

Đề cương: "Xây dựng quy trình sàng lọc và thẩm định cảnh báo lỗ hổng kết hợp Semgrep và CodeQL"
(đề án thạc sĩ định hướng ứng dụng, PTIT). Đối chiếu ngày 2026-11-14, cập nhật các dòng 6 và
11–13 ngày 2026-11-15, trên nhánh
`feat/cwe22-triage`. Số liệu chi tiết: [chapter-3-results.md](chapter-3-results.md).

**Cách đọc cột "Hiện trạng":** *Đạt* nghĩa là có mã chạy được và có đầu ra đã kiểm chứng;
*Đạt một phần* nghĩa là có nhưng phạm vi hẹp hơn cam kết; *Còn thiếu* nghĩa là chưa có.

| # | Cam kết trong đề cương | Hiện trạng | Phần còn thiếu | Minh chứng |
|---:|---|---|---|---|
| 1 | Hệ thống hóa lý thuyết SAST và cảnh báo sai (Chương 1) | Đạt: văn bản đủ đề mục, trích dẫn đã đối chiếu với nguồn | Sửa danh mục tài liệu tham khảo của đề cương: [1], [6], [8] ghi sai tác giả, không tìm thấy bài [9] | [chuong-1-tong-quan.md](chuong-1-tong-quan.md) |
| 2 | Quy trình nhiều bước: quét nhanh rồi thẩm định sâu | Đạt, có điều chỉnh: tập ứng viên là hợp các nguồn, CodeQL vừa phát hiện vừa thẩm định | Giải trình điều chỉnh trong Chương 2 (đã có ghi chú) | [chapter-2-notes.md §2.3](chapter-2-notes.md#23-điều-chỉnh-so-với-đề-cương-từ-nối-tiếp-sang-hợp-các-nguồn) |
| 3 | Semgrep quét nhanh | Đạt | — | Profile `command-injection-v0.2`; lượt quét thật trong [validation.md](../validation.md) |
| 4 | Công cụ bổ trợ theo ngôn ngữ: Bandit (Python) | Đạt | — | [bandit.py](../../backend/app/scanners/bandit.py); Bandit báo riêng 2/13 lỗi thật trên OWASP |
| 5 | Công cụ bổ trợ theo ngôn ngữ: eslint-plugin-security (JS/TS) | Đạt một phần | Rule duy nhất liên quan CWE-78 chỉ bắt `exec()` có đối số không phải hằng | [eslint.py](../../backend/app/scanners/eslint.py); bảng JS trong chapter-3 |
| 6 | CodeQL thẩm định sâu để giảm cảnh báo sai | Đạt một phần | Gói bằng chứng CodeQL chỉ cho Python (CWE-78, CWE-22). Với JS/TS, bước gạn dùng bằng chứng của Semgrep CE cho một loại (lệnh hằng, G4) | Quy tắc G1; OWASP: gạn 2/7 cảnh báo sai, 0/13 cảnh báo đúng. Thêm lớp gạn bằng công cụ mã nguồn mở (Semgrep CE, G3): 1/7, 0/13. JavaScript (84 package, dữ liệu phát triển): G4 gạn 1/11 cảnh báo sai, 0/122 cảnh báo đúng |
| 7 | Tiêu chí quyết định sau thẩm định | Đạt | — | [adjudicate.py](../../backend/app/triage/adjudicate.py), [PRIORITY_V0_2.md](../../profiles/command-injection-v0.2/PRIORITY_V0_2.md) |
| 8 | Chuẩn hóa và tổng hợp kết quả theo SARIF | Đạt | — | Đọc SARIF của 4 công cụ; xuất SARIF 2.1.0 hợp nhất (`/report.sarif`) |
| 9 | Báo cáo thống nhất thể hiện danh sách trước và sau thẩm định | Đạt | — | `GET /scans/{id}/report`; khối "Báo cáo trước–sau" trên giao diện |
| 10 | Nguyên mẫu tự động chạy công cụ, thu thập, chuẩn hóa | Đạt | — | Ứng dụng web + worker; [README](../../README.md) |
| 11 | Phạm vi JavaScript/TypeScript và Python | Đạt một phần | Độ chính xác đều đo trên dữ liệu phát triển: Python trên benchmark tổng hợp; JS/TS 0,92 trên 146 ứng viên của 84 package, nhãn do trợ lý AI đề xuất và chủ đề án rà (một người, không mù). JS/TS có độ bao phủ trên lỗ hổng thật chưa từng xem (32/43, và 8/8 ở tập giữ lại). Bước gạn JS/TS chỉ có một quy tắc hẹp | [chuong-3 §3.3.2](chuong-3-thuc-nghiem.md#332-mức-giảm-cảnh-báo-sai-theo-đối-chiếu) |
| 12 | Dữ liệu: dự án mã nguồn mở từ GitHub | Đạt một phần | Phần có nhãn đầy đủ là benchmark tổng hợp (OWASP) và các kho CWE-22 đã gán nhãn. Dữ liệu chưa từng xem gồm 52 package npm có CVE thật và 6 ứng dụng luyện tập trên GitHub, chỉ có nhãn dương tính. Tập CVE lỗi/vá `pairs-v1` đã quét cả hai phần (phát triển bằng v0.2; giữ lại một lần bằng v0.3 đã đóng băng), cũng chỉ có nhãn dương tính | [experiments/evaluation/README.md](../../experiments/evaluation/README.md) |
| 13 | Chỉ số: precision, recall, F1, tỷ lệ cảnh báo sai | Đạt cho CWE-78 Python trên dữ liệu phát triển | Trên dữ liệu độc lập: precision, recall, F1 có trên 210 dòng mã minh họa (lượt quét lại sau khi sửa lỗi, ngoài kết quả đã đăng ký); trên mã thật: độ bao phủ trên CVE (tập giữ lại 9/9 vị trí đã biết) và số lỗi thật bị gạn nhầm (0); độ chính xác JavaScript chỉ có trên dữ liệu phát triển với một người rà. Chưa có độ chính xác trên dữ liệu chưa từng xem với người rà độc lập | [results/owasp-benchmarkpython-v0.2.json](../../experiments/evaluation/results/owasp-benchmarkpython-v0.2.json), [independent-secbench/results](../../experiments/evaluation/independent-secbench/results/configurations.json) |
| 14 | Chi phí thời gian trước và sau thẩm định | Đạt một phần | Một lần đo mỗi nguồn, có tranh chấp CPU; chưa đo lặp | Cột thời gian trong báo cáo; bảng thời gian chapter-3 |
| 15 | So sánh trước và sau thẩm định | Đạt | — | Bảng trước–sau CWE-78 |
| 16 | Cố định bộ dữ liệu và phiên bản công cụ để tái lập | Đạt | — | [tools/pins.env](../../tools/pins.env), profile ghim hash, [test_evaluation.py](../../experiments/tests/test_evaluation.py) |
| 17 | Dễ tích hợp CI/CD (kết quả kỳ vọng) | Còn thiếu | Chưa có lệnh dòng lệnh hoặc ví dụ CI cho profile v0.2 | — |
| 18 | LLM hỗ trợ giải thích (tùy chọn, hướng phát triển) | Không làm | Giữ ở mục hướng phát triển | — |

## Điều chỉnh cần được người hướng dẫn chấp thuận

1. Tập ứng viên là hợp kết quả các công cụ, không phải chỉ kết quả quét nhanh (mục 2).
2. Bước gạn có hai lớp: luật bằng chứng của Semgrep CE (mã nguồn mở) và truy vấn bằng chứng của
   CodeQL (bộ máy CodeQL CLI không phải mã nguồn mở).
3. Phạm vi nhóm lỗi: CWE-78 là kịch bản chính, CWE-22 (Python) là minh họa bổ sung.
