# Bắt đầu lượt rà đầu

Trạng thái: **chưa bắt đầu human review**. Tám nhãn, danh tính, thời điểm và thời
gian hoạt động đang để trống. Ngày tạo các tệp không phải ngày bạn bắt đầu rà.

1. Mở [hàng đợi](review_queue.csv), [ghi chú](notes.md) và
   [tệp nhãn làm việc](labels.owner-pass1.json). Tệp nhãn là bản sao nguyên byte
   của template đã khóa, chưa chép bất kỳ nhãn đề xuất nào.
2. Khi thực sự bắt đầu, tự ghi danh tính, thời điểm và thời gian hoạt động trong
   [session.json](session.json). Tạm nghỉ không tính vào thời gian hoạt động.
   Các trường session là sổ thời gian, không được evaluator tự xác thực.
3. Theo thứ tự hàng đợi, mở từng thẻ đường đi trong notes và đọc source tại đúng
   SHA. Đọc cả caller, guard, giá trị tới sink và các bước gọi hàm được tóm tắt.
   Thẻ/đường đi không thay bằng chứng triển khai hoặc quyền truy cập.
4. Điền nhãn `true_positive`, `true_positive_conditional`, `false_positive` hoặc
   `unknown`; scope `production`/`test`/`example`, root cause và căn cứ. Bổ sung
   `label_evidence` vào từng phần tử nhãn hoặc ghi chi tiết trong notes kèm unit ID.
   Với giả định áp dụng, ghi supported/contradicted/unknown và nguồn bằng chứng.
   Chỉ dùng `owner_reviewed` sau khi bạn thực sự duyệt ca đó và điền reviewer,
   reviewed_at. Chỉ đặt `all_reported_flows_reviewed=true` khi đã có căn cứ về
   các luồng CodeQL báo và các summary liên quan; không hiểu nó là mọi thực thi.
5. Giữ ca chưa rà ở trạng thái ban đầu. Hoàn thành lượt đầu thì lưu bản đó riêng,
   giữ session/notes và tạo bản lượt hai sau ít nhất bảy ngày từ lượt đầu thực tế.
   Lượt hai phải đảo thứ tự, ẩn nhãn lượt đầu và giữ hồ sơ hòa giải riêng.

Không cần xem báo cáo tổng hợp, khảo sát hợp đồng hoặc nhãn đề xuất trước lượt
đầu. Bạn có thể đã biết kết quả chung; hồ sơ này không tuyên bố review hoàn toàn
mù hay có hai reviewer độc lập.

Sau khi có nhãn thực tế, chạy từ repository root với thư mục output mới:

```powershell
python experiments/wave-c/evaluate.py --run experiments/wave-c/results/study-001/evaluation_run.json --labels experiments/wave-c/closeout/owner-review/labels.owner-pass1.json --output artifacts/wave-c/owner-review-pass1-001
```

Đây là evaluator đã khóa, chỉ đọc kết quả lưu. Output exit 2 có thể là kết quả
`failed_acceptance`; phải giữ báo cáo và xử lý đúng giao thức, không sửa nhãn để
cho lệnh thành công. Nhãn chưa rà không được tự coi là FP hoặc kết luận an toàn.

Hướng dẫn gốc: [REVIEW_GUIDE.md](../../results/study-001/REVIEW_GUIDE.md).

Đính chính artifact: JSON graph trong gói paths-001 cũ chỉ có label dù tài liệu
cũ nói có ID. Khi cần phân biệt các nút trùng label, dùng
[bản decode có ID/URL](../self-review/decoded), giữ namespace của từng BQRS riêng.
Đây là sửa biểu diễn từ BQRS lưu sẵn, không phải output của lần quét mới.
