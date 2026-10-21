# Bản nháp diễn giải kết quả CWE-22

Đây là bản nháp từ số liệu scanner đã có, chưa phải nội dung được chủ đề án hoặc
giảng viên duyệt. Nhãn human, near-duplicate ngữ nghĩa và các giả định triển khai
chưa được xác nhận; các hạn chế này phải giữ trong mọi bản trích số liệu.

## Kết quả định lượng

Wave C chọn trước 12 repository từ quần thể advisory PyPI CWE-22 có tham chiếu SHA
vá đầy đủ. Bảy repository hoàn tất quét; ba vượt giới hạn archive và hai bị từ chối
vì symlink. Không thay mẫu hoặc tăng giới hạn sau khi biết kết quả. Trong bảy lượt
hoàn tất, truy vấn baseline sinh tám sink trên hai repository; năm repository còn
lại không có cảnh báo baseline. Các lượt không tải được không được tính là zero-alert.

v0.2 giữ năm sink và loại ba sink của pipecat. Cả v0.3 strict và scoped giữ nguyên
năm sink v0.2; mức loại thêm bằng không và độ phủ AllowedRoot là 0/5. Mẫu số năm
sink chỉ thuộc một repository, atomic-agents-stack. Vì vậy, bảy lượt quét không
tương đương bảy nhóm có cảnh báo để đo tác dụng của phép lọc mới. Không có sink bị
v0.3 loại trên mẫu này để kiểm tra an toàn của phép loại một cách không vacuous.

Chuỗi tập con đạt trên bảy repository. 105 lệnh scanner/diagnostic/decode thành công;
không thấy thiếu đường dẫn `.py` trong phép đối chiếu 2.783 tệp dự kiến với module
extractor. Các số này mô tả thực thi và phép đối chiếu, không đo recall hoặc chứng
minh mô hình nguồn/luồng đầy đủ. Runtime từng lệnh cộng lại là 3.358,2 giây; không
dùng nó làm kết luận tốc độ giữa các cấu hình. Các cờ tài nguyên được giữ nhưng
không xác minh trần CPU/RAM cứng cho toàn cây tiến trình.

## Diễn giải

Trên phần dữ liệu đã quét, chưa có bằng chứng về hiệu quả giảm FP tăng thêm của
v0.3 so với v0.2. Mười ứng viên resource trong diagnostics không tạo hợp đồng cho
các sink; việc nhận diện một số validator/summary không đủ khi thiếu hợp đồng về
gốc sink được phép truy cập. Kết quả phát triển mlflow — tám cảnh báo thuộc một gốc
nguyên nhân và phụ thuộc scoped assumptions — không được dùng thay kết quả này.

Nhãn của tám sink hiện vẫn là đề xuất/chưa được chủ đề án xác nhận. Ba cảnh báo bị
v0.2 loại cần được rà, thay vì mặc định thành FP. Tỷ lệ loại FP đã xác nhận là N/A,
không phải 0% hay 100%. Việc v0.3 không loại thêm cảnh báo không chứng minh v0.3 an
toàn tổng quát hoặc bảo toàn các TP mà truy vấn baseline chưa phát hiện.

## Hậu kiểm và giới hạn

Hậu kiểm source giữ riêng với scanner experiment. Nhánh kiểm tra toàn bộ đích
canonical được phân biệt với nhánh chỉ kiểm tra cha rồi nối tên con. Quan sát tổng
hợp trên marker tự tạo cho thấy symlink con có sẵn có thể phá containment của dạng
thứ hai mà không cần race; đây là lý do cần giữ điều kiện A-SYM gồm cả symlink có
sẵn. Không chạy ứng dụng để kiểm chứng khai thác, không sửa QL và không coi quan
sát hậu kiểm là một lần kiểm chứng độc lập của quy tắc.

Cả tám cảnh báo thiếu codeFlows trong SARIF, nên source/sink locations không tự
chứng minh mọi luồng đã được rà. Metadata/fingerprint không thấy cờ quan hệ giữa
các snapshot, nhưng không thay cho near-duplicate review ngữ nghĩa. Mẫu cũng bị
giới hạn vào repository có advisory và archive đáp ứng giới hạn đã đặt trước;
không suy rộng thành toàn bộ dự án Python.

Theo điều kiện dừng, nghiên cứu ghi nhận mức tăng thêm bằng không và không mở rộng
quy tắc trong đợt này. Công việc còn lại là rà nhãn đúng phạm vi, kiểm tra quan hệ/
contamination và hoàn thiện phần kết luận với kết quả âm tính được giữ nguyên.
Nguồn: `study-001/RESULTS.md`, `study-001/evaluation/report.json`, hồ sơ hậu kiểm
`review-001/REVIEW.md`; mọi nhãn/thời điểm rà thực tế phải được bổ sung riêng.
