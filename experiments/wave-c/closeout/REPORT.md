# Kết quả Wave C và giới hạn giảm cảnh báo sai

Trạng thái: **bản thảo báo cáo từ kết quả scanner đã lưu; nhãn chủ đề án và
kiểm tra độc lập về họ mã nguồn chưa hoàn tất**. Kết luận về mức loại tăng thêm
bằng không đã xác định được từ tập cảnh báo; kết luận về FP/TP cần nhãn thực tế.

**Cập nhật tự rà kỹ thuật:** [lượt rà mới](self-review/REVIEW.md) sửa hai đề xuất
normalization từ FP thành unknown. Evaluator trên nhãn exploratory trả
`failed_acceptance` vì v0.2 loại một ca unknown; strict/scoped kế thừa kết quả
đó. Giữ tín hiệu lỗi và dừng xác nhận acceptance. Chưa có TP bị loại được xác
nhận độc lập; các số lượng raw bên dưới không đổi.

## Câu hỏi và thiết kế

Wave C đánh giá liệu v0.3 strict/scoped có loại thêm FP so với v0.2 trên repository
Python mới hay không. Đơn vị cảnh báo là sink theo tệp/dòng/cột và CWE; đơn vị
gán nhãn gồm mọi luồng được CodeQL báo đến sink. Nhiều sink có cùng nguyên nhân
không được coi là nhiều quan sát độc lập. Mẫu không đo recall tổng thể.

Mười hai repository được chọn theo quy tắc hash cố định từ metadata advisory
PyPI CWE-22 có commit vá tham chiếu. Snapshot tại commit vá không mặc nhiên an
toàn và không biến mọi cảnh báo thành FP. Các repository đã dùng trước được
loại theo danh sách đã khóa. Không thay mẫu sau khi xem output.

Phương pháp, mẫu, source/toolchain lock và runner/evaluator được công bố trước
quét. [publication.json](../publication.json) ghi nhận commit và dịch vụ công bố;
[giao thức](../PROTOCOL.md) và [execution lock](../EXECUTION_LOCK.sha256) giữ đầu
vào phương pháp. Dùng CodeQL 2.27.1, python-all 7.2.6, python-queries 1.8.11;
bốn cấu hình chạy cùng database, có `--rerun`. Không thực thi source ứng dụng.

## Quần thể và kết quả từng repository

| Thứ tự | Repository | Acquisition / scan | none | v0.2 | strict | scoped |
|---:|---|---|---:|---:|---:|---:|
| 1 | jelmer/dulwich | hoàn tất | 0 | 0 | 0 | 0 |
| 2 | wkentaro/gdown | hoàn tất | 0 | 0 | 0 | 0 |
| 3 | dep0we/atomic-agents-stack | hoàn tất | 5 | 5 | 5 | 5 |
| 4 | zopefoundation/zope | hoàn tất | 0 | 0 | 0 | 0 |
| 5 | pytorch/serve | quá giới hạn tải archive | — | — | — | — |
| 6 | linuxfabrik/lib | archive có symlink bị từ chối | — | — | — | — |
| 7 | clinical-genomics/scout | archive có symlink bị từ chối | — | — | — | — |
| 8 | pipecat-ai/pipecat | hoàn tất | 3 | 0 | 0 | 0 |
| 9 | khoj-ai/khoj | quá giới hạn tải archive | — | — | — | — |
| 10 | open-webui/open-webui | quá giới hạn tải archive | — | — | — | — |
| 11 | blacklanternsecurity/bbot | hoàn tất | 0 | 0 | 0 | 0 |
| 12 | openstack/ironic | hoàn tất | 0 | 0 | 0 | 0 |
| | Tổng trên 7 lượt hoàn tất | | **8** | **5** | **5** | **5** |

Năm acquisition không thành công là dữ liệu thiếu, không phải repository không
cảnh báo. Giới hạn archive 50 MiB và yêu cầu không có symlink được giữ nguyên.
Bảng với full SHA, trạng thái evaluator và lý do acquisition ở
[repositories.csv](evidence/repositories.csv).

## Kết quả định lượng có thể kết luận hiện nay

| Chỉ số | Kết quả | Cách diễn giải |
|---|---:|---|
| Strict loại thêm so với v0.2 | 0/5 sink | Không có tác động tăng thêm quan sát được |
| Scoped loại thêm so với strict | 0/5 sink | Không có tác động tăng thêm quan sát được |
| AllowedRoot strict / scoped | 0/5 ở mỗi chế độ | Không có hợp đồng cho các sink v0.2 còn lại |
| Chuỗi tập con | đạt 7/7 lượt quét | Kiểm tra nhất quán tập cảnh báo, không phải chứng minh an toàn |
| Sink baseline cần rà | 8 | Chưa có nhãn chủ đề án duyệt |
| Tỷ lệ loại FP đã xác nhận | N/A | Chưa có mẫu số FP được xác nhận |

V0.2 loại ba sink pipecat; đó không phải đóng góp mới của v0.3 và các ca này vẫn
cần rà. Năm sink v0.2 còn lại đều thuộc atomic-agents-stack. Vì vậy, bảy repository
quét xong chỉ cung cấp một repository có ứng viên để đo phần tăng thêm v0.3.

Do không có phép loại tăng thêm, Wave C chưa tạo kiểm tra an toàn không vacuous
cho phép loại mới. `no_observed_safety_failure` trong một hàng evaluator không
có nghĩa nhãn đã hoàn tất hoặc toàn bộ cổng acceptance/independence đã đạt.
Các cờ `labels_complete_for_complete_repositories=false` và human review pending
phải được giữ khi trích báo cáo.

## Bằng chứng kỹ thuật và chi phí đã đo

105 lệnh scanner/diagnostic/decode kết thúc exit 0; tổng wall time từng lệnh là
3.358,2 giây. Đối chiếu module với archive không thấy thiếu trong 2.783 đường
dẫn `.py` dự kiến. Điều này kiểm tra thực thi/đường dẫn, không chứng minh mô hình
taint đầy đủ hoặc mọi lỗ hổng đều được phát hiện. Runtime gồm nhiều loại lệnh;
không suy ra tốc độ giữa các cấu hình từ tổng này. Giới hạn cứng CPU/RAM toàn cây
tiến trình chưa được xác minh, dù giữ các cờ `--threads=2 --ram=5000`.

Diagnostics nhận diện summary nhưng không có hàng hợp đồng/containment/suppression
cho các sink. Mười ứng viên resource ở pipecat/bbot/ironic không tạo hợp đồng
được chấp nhận. Đây hỗ trợ nhận xét về giới hạn độ phủ của cấu hình hiện tại;
không chứng minh tự động suy chính sách là bất khả thi trong mọi phương pháp.

SARIF chính dùng `@kind problem`, không có codeFlows. Chẩn đoán hậu kiểm dùng
bản sao hai database, giữ nguyên cấu hình taint/source/sink, sinh 18 đường đi mẫu
cho tám sink và 114 dòng cạnh có vị trí. Cặp nguồn–sink khớp cả tọa độ kết thúc;
database gốc và kết quả trước đó không đổi. Chín lệnh hậu kiểm tốn 245,282 giây,
ghi riêng với runtime chính. [Gói đường đi](../results/paths-001/PATHS.md) không
liệt kê mọi thực thi; CSV có thể tóm tắt bước gọi hàm được SARIF khai triển.

Hậu kiểm source và quan sát tổng hợp phân biệt canonical containment của toàn
đích với resolve thư mục cha rồi nối tên con. Dạng sau vẫn cần A-SYM cho symlink
có sẵn, không chỉ điều kiện không có race. Đây không phải kiểm chứng khai thác
ứng dụng hoặc một bộ thử độc lập mới. Không dùng hậu kiểm để sửa QL Wave C.

## Giá trị và giới hạn của kết quả

Kết quả mới chưa hỗ trợ khẳng định v0.3 giảm thêm FP so với v0.2 trên mã thật.
Kết quả scoped trên mlflow thuộc dữ liệu phát triển và một nguyên nhân gốc;
không được gộp làm quan sát độc lập của Wave C. Các bộ phản ví dụ/benchmark đã
dùng nhiều vòng là hồi quy, không thay cho đánh giá mới.

Mẫu giới hạn vào repository có advisory và archive đáp ứng ràng buộc. Acquisition
thiếu có thể làm thay đổi đặc điểm phần quan sát được. Không tính khoảng tin cậy
theo tám sink như thể độc lập, hoặc coi năm repo zero-alert là năm lần kiểm tra
tác dụng lọc v0.3. Không có cảnh báo baseline không tương đương không có lỗ hổng.

[Sổ quan hệ](evidence/relationships.json) ghi đủ 12 repository và metadata đã
kiểm hash. Metadata không gắn cờ fork/parent/source hoặc trùng định danh loại trừ;
màn exact-byte đã lưu giữa các snapshot mới không phát hiện trùng tệp theo tiêu
chí của nó. Near-duplicate ngữ nghĩa vẫn pending trên các snapshot khả dụng;
không có xác nhận độc lập tổng quát. Không đọc source held-out lịch sử để lập sổ này.

Nhãn và điều kiện triển khai là phần chưa hoàn tất. Đề xuất ban đầu bốn FP /
bốn unknown đã được thay bằng hai FP có điều kiện / sáu unknown trong phiên bản
tự rà riêng; giữ nguyên tệp đề xuất lịch sử. Không dùng các đề xuất này thành
nhãn xác nhận, và không tự tạo thời gian human review. Chỉ sau
khi có nhãn thực tế mới chấm lại tỷ lệ FP và quyết định acceptance theo giao thức.

## Quyết định và phần đang chờ

Giữ mức loại tăng thêm bằng không và dừng mở rộng quy tắc trong Wave C. Đã thực
hiện [khảo sát hợp đồng khai báo](CONTRACT_FEASIBILITY.md): tài liệu có ích về
mục đích tài nguyên, nhưng policy đơn thuần chưa giải quyết binding root động,
containment theo ngữ cảnh và căn cứ triển khai. Chưa qua cổng mở thí nghiệm mới.

[Hồ sơ làm việc lượt rà đầu](owner-review/START_HERE.md) đã chuẩn bị, còn trống.
Sau lượt rà thực tế, evaluator đã khóa sẽ tạo báo cáo riêng. Giữ hai lượt rà cách
ít nhất bảy ngày theo giao thức và hồ sơ hòa giải. Nếu còn cổng chưa hoàn tất,
báo cáo này tiếp tục mang trạng thái provisional; không tự đóng acceptance.

Nguồn số liệu định lượng tái lập: [metrics.json](evidence/metrics.json),
[provenance.json](evidence/provenance.json),
[báo cáo scanner gốc](../results/study-001/RESULTS.md).
