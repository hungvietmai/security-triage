# Tiến độ thực hiện kế hoạch sau Wave C

Ngày: 2026-10-21. Người dùng đã yêu cầu thực hiện kế hoạch. Các phần dưới đây
không thay thế human review hoặc phê duyệt một giao thức thí nghiệm mới.

| Đầu việc | Trạng thái | Kết quả |
|---|---|---|
| Chuẩn bị lượt rà đầu | Hoàn tất chuẩn bị | [START_HERE.md](owner-review/START_HERE.md), tám nhãn trống, hàng đợi, notes và session trống |
| Thực hiện human review | Hoàn tất dạng xác minh (28–29/10) | Chủ đề án kiểm từng dữ kiện trong đề xuất của assistant, không mù: [gói xác minh](../../reviews/owner-verification/README.md). Template owner-review trống được giữ nguyên |
| Lập bảng kết quả / metadata | Hoàn tất tổng hợp | [12 repository](evidence/repositories.csv), [sổ quan hệ](evidence/relationships.json); near-duplicate ngữ nghĩa vẫn chưa xác nhận |
| Viết báo cáo | Đã có bản thảo đầy đủ cho số liệu hiện có | [REPORT.md](REPORT.md); kết luận nhãn/acceptance còn provisional |
| Khảo sát hợp đồng | Đã chốt kết luận khảo sát | [CONTRACT_FEASIBILITY.md](CONTRACT_FEASIBILITY.md): chưa qua cổng mở thí nghiệm chỉ bổ sung policy |
| Kiểm tra đầu ra | Đã chạy | [85 test và các khóa](evidence/checks.json); [evaluator với nhãn trống](evidence/seed-evaluation-check.json) khớp báo cáo gốc, không thêm xác nhận human |
| Tự rà kỹ thuật theo yêu cầu người dùng | Hoàn tất lượt rà exploratory | [Kết quả](self-review/REVIEW.md): 18 đường đi, 39 nút, 3 summary; sửa hai nhãn normalization thành unknown, đính chính JSON thiếu ID |
| Acceptance sau tự rà | Dừng xác nhận | [Evaluator](self-review/evaluation-command.json) exit 2: v0.2 đã loại một ca nay đề xuất unknown; không phải TP bị loại đã được xác nhận |
| Bản thử baseline sau tự rà | Hoàn tất vòng phát triển riêng | [v0.2.1](../../v021-normalization/results/round-001/RESULTS.md) khôi phục một sink normalization, giữ 6 thay vì 5 trên bảy repo; không đổi acceptance lịch sử |
| Rà lượt hai / hòa giải | Chưa làm | Tùy chọn; nếu bỏ, ghi là độ lệch giao thức (một người, một lượt, không mù) |
| Chấm nhãn | Đã chấm (29/10) | Evaluator đã khóa exit 0, `no_observed_safety_failure` ở cả hai repo; v0.3 loại thêm 0/5 FP. Nhãn chưa được khóa |
| Assistant rà kỹ thuật C và B ngày 27/10 | Đã rà 8 sink C và 17 cảnh báo B | [Gói rà riêng](../../reviews/2026-10-27-assistant-pass1/README.md): C 2 FP có điều kiện / 6 unknown; B 4 TP / 9 FP có điều kiện / 4 unknown, tất cả proposed; không thay owner review |

Khảo sát chỉ đọc source/tài liệu đã có và QL hiện tại; không thêm source/sink,
model pack hoặc quét mẫu mới. Các tệp trong closeout là bản thảo/tệp làm việc,
không thuộc các gói kết quả lịch sử đã khóa. Không sửa các gói đó để cập nhật
trạng thái mới.

Việc tiếp theo là mở hồ sơ lượt rà đầu. Agent có thể chấm ngay khi có nhãn thực
tế được cung cấp; không tự xác nhận thay người rà.

Cập nhật 2026-10-27: hồ sơ closeout đã được commit và push trong `8e99ecc`
(nhánh `feat/research-safety-evidence`). Ngày 28–29/10, chủ đề án đã xác minh nhãn (xem bảng trên).
Trạng thái tổng hợp của toàn bộ nghiên cứu: [docs/research.md](../../../docs/research.md).

Lượt assistant 27/10 đã đối chiếu lại source và đồ thị C; evaluator đã khóa tiếp tục
exit 2 (`failed_acceptance`). Hồ sơ owner, danh tính và thời gian human vẫn trống.
Lượt này không được tính thành lượt human thứ nhất/thứ hai hoặc bắt đầu khoảng
chờ bảy ngày. Đợt B thiếu path gốc nên không xác nhận đã rà mọi luồng báo; RC-M5
và RC-M7 được đề xuất đổi thành unknown trong gói mới, giữ nguyên nhãn khóa cũ.
