# Rà nhãn Wave C

Gói này chứa đầu ra scanner và hàng đợi rà nhãn. Chưa có nhãn do chủ đề án xác nhận.
Các ghi chú trong `proposals/` là đề xuất từ đọc mã, đã thấy số lượng của bộ lọc;
không phải một reviewer độc lập và không phải lần rà mù của chủ đề án.

## Các tệp cần dùng

- `evaluation/review_queue.csv`: thứ tự rà đã định bởi evaluator; các sink bị bất kỳ
  cấu hình nào loại đứng trước. Có liên kết mã nguồn tại đúng commit.
- `evaluation/review_packet.json`: vị trí nguồn/sink được báo và codeFlows nếu có.
- `evaluation/labels.template.json`: nhãn, reviewer, ngày rà, scope và root cause để trống.
- `inputs/<rank>/none.sarif`: đầu ra baseline nguyên bản; các cấu hình khác được lưu cạnh đó.
- `proposals/`: đọc riêng sau lượt rà đầu nếu muốn tránh nhìn nhãn đề xuất trước.
- `original_run.json`, `runtime.json`, `logs/`: nguồn gốc, thời gian, lệnh, stdout/stderr.
- `RESULTS_LOCK.sha256`: hash kết quả; không chỉnh trực tiếp các tệp đã khóa.

Hàng đợi ẩn tên rule, quyết định lọc và nhãn đề xuất. Thứ tự ưu tiên và ngữ cảnh source
vẫn có thể làm lộ công cụ; không gọi đây là review hoàn toàn mù.

## Rà lần đầu

1. Sao chép template ra một tệp mới như `labels.owner-pass1.json`; giữ nguyên template.
2. Đọc mã tại đúng commit, các caller và mọi luồng có thể tác động đến sink. Ghi rõ
   giới hạn của SARIF: không có codeFlows thì không được nhận là đã xem đầy đủ đường
   CodeQL chỉ nhờ các vị trí nguồn/sink.
3. Điền `technical_label`: `true_positive`, `true_positive_conditional`,
   `false_positive` hoặc `unknown`. Ghi `scope` là production/test/example và một
   `root_cause_id` dùng chung cho các sink có cùng cơ chế, kèm bằng chứng mã nguồn.
4. Chỉ chủ đề án tự điền reviewer và ngày rà thực tế. `owner_reviewed` chỉ dùng sau
   khi thật sự duyệt; không sao chép trạng thái này từ ghi chú đề xuất. Đo thời gian
   rà thực tế riêng; thời gian scanner không phải reviewer-hours.
5. Chỉ đặt `all_reported_flows_reviewed=true` khi đã có căn cứ. Rà S-TEST, S-TMP,
   S-PURPOSE, S-ENV, A-SYM khi áp dụng. Mỗi giả định cần trạng thái và bằng chứng;
   tên thư mục test hoặc tên helper không phải bằng chứng triển khai/phân quyền.

Các sink v0.2 đã loại cũng phải được rà. Không bỏ chúng chỉ vì strict/scoped không
loại thêm. TP/TP có điều kiện/unknown bị loại hoặc giả định bị bác bỏ phải được ghi
đúng theo giao thức và dừng xác nhận, không sửa nhãn để làm bộ lọc đạt.

## Chấm lại nhãn đã được cung cấp

Từ gốc repository, dùng thư mục output mới:

```powershell
python experiments/wave-c/evaluate.py --run experiments/wave-c/results/study-001/evaluation_run.json --labels experiments/wave-c/results/study-001/labels.owner-pass1.json --output artifacts/wave-c/owner-review-pass1
```

Lệnh chỉ đọc các kết quả đã lưu; không quét lại source. Không sửa evaluator hoặc các
manifest đã khóa sau khi thấy nhãn. Nhãn chưa rà vẫn là unreviewed; N/A không thành 0%.

Khi chỉ có một người rà, lần hai diễn ra sau ít nhất 7 ngày kể từ lần một thực tế,
đổi thứ tự và ẩn nhãn lần đầu. Giữ hai bản, ngày rà và hòa giải riêng. Không tính
ghi chú đề xuất là người rà thứ hai hoặc tự tạo ngày rà khi chưa có hoạt động đó.

## Tái lập báo cáo không cần CodeQL

```powershell
python experiments/v03-interprocedural-guard/scripts/verify_freeze.py --manifest experiments/wave-c/results/study-001/RESULTS_LOCK.sha256
python experiments/wave-c/evaluate.py --run experiments/wave-c/results/study-001/evaluation_run.json --output artifacts/wave-c/reproduce-study-001
```

`evaluation_run.json` chỉ đổi đường dẫn sang bản sao đầu ra đã xuất bản, giữ nguyên
byte từng SARIF/CSV và các hash scanner. `packaging.json` ghi ánh xạ với lượt gốc.
Database, archive source và cache toolchain vẫn ở `artifacts/`, ngoài gói Git.
