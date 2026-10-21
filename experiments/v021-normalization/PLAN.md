# Bản thử v0.2.1 — normalization trước guard

Đây là phát triển sau khi đã xem Wave C và lượt tự rà. Không phải đánh giá độc
lập mới, không thay thế hoặc sửa gói Wave C `failed_acceptance` đã lưu.

Thay đúng một predicate: trong bản sao `SafetyEvidence.qll`, `excludedSink` không
còn loại receiver của `Path.resolve()` hoặc đối số của `os.path.realpath()` chỉ
vì kết quả được một guard sau đó kiểm tra. Giữ trường hợp `abspath` và toàn bộ
barrier khác. Không thêm source/sink, không nới validator hoặc hợp đồng.

Pack thử có tên riêng, giữ python-all 7.2.6/CodeQL 2.27.1. `IpgGuard.qll` được
copy nguyên byte để đo hai cấu hình dẫn xuất strict/scoped trên baseline sửa;
chúng mang ID `v031`/`v031s`, không nhận là kết quả v0.3 lịch sử. Extension rỗng
chỉ đổi tên pack đích, không thêm hàng hợp đồng.

## Khóa trước chạy và kiểm tra

Khóa fixture mới, kỳ vọng, pack và runner trước query đầu. Đây là khóa tại máy
cho phát triển, không nhận là công bố trước một phép kiểm chứng độc lập.

1. Tạo database chỉ từ fixture mới và bản sao hai tệp phản ví dụ tổng hợp
   `paths.py`/`values.py` cũ. Chỉ extract/scan, không import/chạy ứng dụng Flask.
2. Chạy baseline none/v0.2 đã đóng băng và ba cấu hình thử trên cùng database.
   Chấm riêng từng thao tác có marker; không cho một cảnh báo metadata che việc
   mất cảnh báo đọc nội dung trong cùng hàm.
3. Mọi marker `none=must` phải có baseline thực sự. Kiểm tra keep/drop theo bảng
   đã khóa. `realpath` không được tự thêm model: nếu baseline không báo metadata,
   ghi thiếu độ phủ, không nhận đã kiểm chứng retention cho thao tác đó.
4. Phản ví dụ cũ chỉ là hồi quy. Không mất sink nào của v0.2; các hàm `_bad`
   được baseline phát hiện phải tiếp tục có cảnh báo. Ca baseline không phát hiện
   phải được ghi riêng, không nhận là an toàn được chứng minh.
5. Nếu đạt fixture, đối chiếu v0.2.1 trên bản sao database của cả bảy repository
   Wave C đã quét. Đo thêm strict/scoped dẫn xuất trên hai repository có cảnh báo.
   Không tạo lại database hoặc chạy source. Giữ hash các database gốc trước/sau.

Quan hệ cần đạt theo sink `(file,line,column)`:
`R_old_all ⊆ R_v021 ⊆ R_none`,
`R_old_v03 ⊆ R_v031 ⊆ R_v021`,
`R_old_v03s ⊆ R_v031s ⊆ R_v031` khi có các cấu hình tương ứng.
Không mất cảnh báo đã giữ, không tự đổi nhãn để làm điều kiện đạt.

Mỗi tạo DB tối đa 30 phút; mỗi analyze tối đa 20 phút, `--rerun`, 2 thread,
`--ram=5000`. Các cờ không phải chứng minh trần CPU/RAM toàn cây tiến trình.
Lệnh lỗi hoặc kỳ vọng không đạt phải lưu output và dừng vòng này; không âm thầm
sửa kỳ vọng/fixture rồi gọi cùng lượt là đạt. Không quét các cặp held-out lịch sử.

## Diễn giải dự kiến

Mục tiêu là khôi phục cảnh báo normalization chưa đủ căn cứ loại, đồng thời giữ
barrier cho thao tác sau guard khi dùng đúng giá trị. Số cảnh báo có thể tăng.
Không hứa trước số cảnh báo khôi phục hoặc tỷ lệ FP. Nhãn tự rà vẫn exploratory,
giả định triển khai chưa được xác nhận; một vòng regression đạt không biến các
cấu hình thử thành phương pháp đã kiểm chứng độc lập hay bảo đảm an toàn chung.
