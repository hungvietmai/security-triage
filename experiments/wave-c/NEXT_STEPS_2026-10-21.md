# Kế hoạch sau Wave C — đề xuất ngày 2026-10-21

Trạng thái: người dùng đã yêu cầu thực hiện kế hoạch; phần chuẩn bị, báo cáo và
khảo sát đã có [kết quả triển khai](closeout/STATUS.md). Human review chưa bắt đầu.
Đây chưa phải giao thức thí nghiệm mới đã phê duyệt.
Không cho phép thay phương pháp Wave C, tự xác nhận nhãn hoặc bắt đầu quét mẫu mới.

## Quyết định đề xuất

**Đóng Wave C với kết quả tăng thêm bằng không; dừng phát triển quy tắc v0.3
trong đợt này. Ưu tiên hoàn tất nhãn và báo cáo trước một vòng phát triển khác.**

Nếu cần nghiên cứu tiếp, thử có giới hạn hướng **hợp đồng gốc được khai báo từ
bằng chứng độc lập, kết hợp chứng cứ an toàn để hỗ trợ người rà**. Đây là câu hỏi
mới về độ phủ hợp đồng và chi phí sử dụng, chưa phải một phương pháp đã có hiệu quả.
Không gọi nó là kết quả của Wave C hoặc suy ra hiệu quả từ các nhãn đã biết.

## Căn cứ và giới hạn

| Quan sát đã lưu | Ý nghĩa đối với quyết định |
|---|---|
| 12 repository được chọn; 7 quét xong, 5 acquisition thất bại/bị từ chối | Giữ cả 12 trong báo cáo; không thay mẫu để kiếm cảnh báo |
| `none=8`, `v0.2=5`, `strict=5`, `scoped=5` | V0.3 không loại thêm cảnh báo trong phần đã quét |
| AllowedRoot `0/5`; năm sink v0.2 đều thuộc atomic-agents-stack | Nút thắt quan sát được là hợp đồng; mẫu có khả năng đo phần tăng thêm rất hẹp |
| Không có phép loại tăng thêm nào của v0.3 | Chưa có kiểm tra an toàn không vacuous cho phép loại mới trên mẫu này |
| Tám nhãn chưa được chủ đề án duyệt | Chưa tính được tỷ lệ loại FP đã xác nhận; N/A không phải 0% |
| 18 đường đi mẫu cho tám sink, endpoint khớp baseline | Đủ hồ sơ hỗ trợ lượt rà; không cần thêm scanner chỉ để có thêm log |

Kết quả này **chưa chứng minh tác dụng tăng thêm trên dữ liệu mới**, nhưng cũng
không đủ để kết luận v0.3 vô ích trên mọi chương trình. Tám cảnh báo mlflow từng
được scoped loại là một nguyên nhân gốc trong dữ liệu phát triển, không thay thế
cho kết quả mới. Không dùng benchmark hồi quy để tuyên bố hiệu quả trên mã thật.

## Chặng 1 — hoàn tất Wave C

Thời lượng dưới đây là ước lượng lập kế hoạch, không phải thời gian đã đo.
Khoảng chờ bảy ngày phải tính từ lượt human review đầu thực tế.

| Việc | Người thực hiện | Thời lượng dự kiến | Đầu ra / điều kiện xong |
|---|---|---|---|
| Rà lần đầu tám sink từ thẻ đường đi và source đúng SHA | Chủ đề án | Một buổi; dự kiến 2–4 giờ, tối đa theo ngân sách giao thức | Tệp nhãn mới, bằng chứng, phạm vi, root cause, giả định, ngày và thời gian thực tế |
| Chạy evaluator đã khóa với nhãn được cung cấp | Agent | Sau lượt rà | Báo cáo mới, giữ nguyên kết quả scanner; phân biệt v0.2 với phần tăng thêm v0.3 |
| Tổng hợp giới hạn mẫu và quan hệ repository | Agent; chủ đề án xác nhận điểm chưa rõ | Trong 1 ngày làm việc | Sổ bằng chứng quan hệ/contamination; mục chưa giải quyết vẫn pending, không nhận độc lập đã xác nhận |
| Soạn báo cáo và đối chiếu số liệu | Agent | 1–2 ngày làm việc, có thể làm trong khoảng chờ | Bản thảo kết quả và giới hạn, dẫn tới đúng gói dữ liệu; nhãn chưa xong được ghi rõ |
| Rà lần hai, đảo thứ tự và ẩn nhãn lượt đầu; hòa giải | Chủ đề án | Sớm nhất 7 ngày sau lượt đầu | Hai lượt giữ riêng, bất đồng và quyết định cuối; không nhận là hai reviewer độc lập |
| Chấm lại, khóa gói nhãn/báo cáo cuối | Agent | Sau hòa giải | Kết luận với trạng thái acceptance thực tế; chưa đủ cổng thì giữ provisional |

Ưu tiên rà ba sink pipecat đã bị v0.2 loại, rồi năm sink atomic. Xem kỹ sự khác
nhau giữa kiểm tra toàn đích canonical và kiểm tra thư mục cha rồi nối tên con;
A-SYM gồm cả symlink có sẵn. Giá trị từ CLI không tự chứng minh bất biến hoặc
phân quyền. Không tự điền reviewer, ngày rà hay `all_reported_flows_reviewed`.

Nếu sink bị loại được rà thành TP, TP có điều kiện hoặc unknown, hoặc giả định
áp dụng bị bác bỏ, giữ số liệu nguyên bản và xử lý `failed_acceptance` theo
giao thức/evaluator. Không chữa nhãn hay QL để cùng lượt đánh giá trở thành đạt.
Nếu có nhu cầu sửa sau đó, đó là phiên bản và đợt nghiên cứu mới.

Nguồn để làm ngay:

- [Hướng dẫn rà và lệnh chấm](results/study-001/REVIEW_GUIDE.md).
- [Tám thẻ đường đi](results/paths-001/PATHS.md), ưu tiên đọc thẻ trước ghi chú nhãn đề xuất.
- [Nháp kết quả hiện có](results/review-001/THESIS_RESULTS_DRAFT.md), khi viết bản mới
  cần bổ sung dẫn chiếu gói đường đi hậu kiểm; không sửa bản nháp đã khóa.
- [Quyết định sau Wave C](DECISION_2026-10-21.md) và [giao thức gốc](PROTOCOL.md).

## Chặng 2 — chốt nội dung đóng góp từ bằng chứng hiện có

Đề xuất trọng tâm báo cáo: **khả năng và giới hạn giảm cảnh báo sai bằng chứng
cứ an toàn trong phân tích tĩnh Python**, với ba phần có thể kiểm tra:

1. Cơ chế chứng cứ, phản ví dụ và cách giữ cảnh báo khi không chứng minh đủ.
   Mô tả các lần v0.1 loại nhầm để giải thích vì sao điều kiện chặt là cần thiết.
2. Phân biệt kết quả benchmark, dữ liệu phát triển và mẫu repository mới;
   trình bày phần tăng thêm bằng không và độ phủ hợp đồng thấp của Wave C.
3. Hồ sơ tái lập, các ca có giả định và chi phí rà được đo thật. Nhãn chưa xác
   nhận, cảnh báo chưa phát hiện và dữ liệu acquisition thiếu phải tách rõ.

Đây là đề xuất cách trình bày đóng góp, không bảo đảm đáp ứng yêu cầu học thuật
của đề tài. Trước khi đầu tư thí nghiệm mới, dùng bản thảo ngắn này để thống nhất
với người hướng dẫn về mức đóng góp còn cần. Hướng 2 trong bàn giao cũ là thiết
kế đánh giá độc lập; Wave C đã thực hiện bước đó, nên không quay lại mô tả nó
như một hướng hoàn toàn chưa thử.

## Chặng 3 — chỉ mở thử nghiệm mới khi cần và có căn cứ

### Giả thuyết mới được đề xuất

Khi chính sách gốc truy cập không suy ra được tự động, liệu hợp đồng được khai
báo từ tài liệu/API/cấu hình triển khai có căn cứ có giúp cơ chế hiện tại xác
nhận thêm cảnh báo an toàn, với chi phí khai báo và rà chấp nhận được?

Hợp đồng là đầu vào có điều kiện và có thể sai. Phương pháp chỉ kiểm tra an toàn
theo hợp đồng; không tuyên bố đã tự chứng minh chính sách phân quyền đúng.

### Khảo sát khả thi, giới hạn hai ngày làm việc

Chỉ dùng dữ liệu đã xem và ghi rõ là phát triển. Không quét repository mới ở bước
này. Hai ngày là ngân sách đề xuất cho khảo sát, không gia hạn ngầm nếu chưa đạt.

- Lập một bảng nhỏ gồm sink, chứng cứ containment, hợp đồng còn thiếu, nguồn có
  thể xác thực hợp đồng và công việc người dùng phải làm. Dùng hồ sơ đã có;
  không lặp lại toàn bộ source audit hoặc tạo thêm gói log nếu không có câu hỏi mới.
- Tìm bằng chứng chính sách ngoài phép `join`, tên biến và nhãn FP: ngữ nghĩa API,
  tài liệu hoặc cấu hình triển khai cụ thể. Ghi nguồn, phạm vi và các điểm chưa rõ.
- Chốt trước một mẫu hợp đồng và hồ sơ bằng chứng tối thiểu. Không mở rộng đồng
  thời validator, source/sink, thuộc tính, tham số hoặc thêm một công cụ phát hiện.
- Kiểm tra nguy cơ oracle vòng tròn: không lấy cùng model pack làm nguồn duy nhất
  cho cả hợp đồng lẫn nhãn đúng/sai; không viết hợp đồng chỉ để loại FP đã biết.

**Cổng quyết định:** chỉ thiết kế thí nghiệm tiếp nếu có hợp đồng được biện minh
độc lập với nhãn và có triển vọng tái dùng ngoài một trường hợp đã biết, đồng
thời mô tả được chi phí sử dụng. Nếu chỉ có thể đoán chính sách hoặc hardcode
theo nhãn, dừng hướng này và hoàn thiện báo cáo hiện có. Không thêm một vòng nới
quy tắc tự động chỉ vì kết quả Wave C bằng không.

### Nếu qua cổng, viết và công bố giao thức mới trước khi chạy

So sánh trên cùng tập ứng viên và snapshot:

| Cấu hình | Câu hỏi |
|---|---|
| v0.2 | Đường cơ sở còn lại những cảnh báo nào? |
| v0.3 tự suy luận đã đóng băng | Suy luận tự động có đóng góp tăng thêm không? |
| Biến thể dùng hợp đồng có căn cứ | Độ phủ/quyết định thay đổi bao nhiêu và cần bao nhiêu công khai báo? |

Không mặc định hậu kiểm tốt hơn cùng logic nhúng trong truy vấn. Nếu so hai cách
thực thi, phải đo chúng trên cùng ứng viên; không nhận tiết kiệm chi phí phát hiện
chỉ vì lọc đầu ra sau khi truy vấn đã chạy xong.

Giao thức mới cần chốt quần thể, kích thước mẫu, ngân sách, cách chia theo
repository/root cause, tiêu chí đạt/dừng và thứ tự khai báo hợp đồng/gán nhãn
trước khi xem output tương ứng. Có thể chọn quần thể repository có cảnh báo
baseline để đo triage, nhưng phải công bố phép sàng lọc trước, giữ số repository
zero-alert/thất bại và không suy rộng thành mọi repository Python. Không lọc mẫu
theo việc v0.3 có loại được FP hay không. Dữ liệu Wave C đã dùng để sửa phương
pháp không còn là kiểm tra độc lập cho phương pháp sửa đó.

Các số cần đo: FP đã xác nhận bị loại; TP/TP có điều kiện/unknown bị loại; độ phủ
hợp đồng; tỷ lệ hợp đồng bị bác bỏ/chưa xác định; số root cause và repository;
thời gian khai báo, rà và chạy thực tế. Chỉ nhận lợi ích thời gian so với rà thủ
công khi có đối chứng và thiết kế xử lý hiệu ứng đã nhớ mã; nếu không, chỉ báo
chi phí mô tả. Mẫu số không đủ thì N/A. Lỗi hợp đồng hoặc một luồng chưa chứng
minh được phải giữ cảnh báo trong quyết định vận hành.

Chỉ tiếp tục vòng sau nếu đạt điều kiện đặt trước, có ích ngoài một trường hợp
phát triển và không loại nhầm ca nguy hiểm/unknown. Nếu có hiệu quả trên một
nhóm duy nhất thì báo tính khả thi; nếu không có hiệu quả, ghi nhận kết quả đó
và dừng, không bổ sung mẫu sau khi thấy output.

## Tình trạng triển khai

Đã chuẩn bị hồ sơ lượt rà đầu, tổng hợp bảng kết quả/sổ metadata, viết bản thảo
báo cáo và kết thúc khảo sát hợp đồng với quyết định chưa mở thí nghiệm chỉ thêm
policy. Xem [STATUS.md](closeout/STATUS.md) và các đầu ra được liên kết.

Theo yêu cầu tự kiểm tra, đã [tự rà kỹ thuật tám sink](closeout/self-review/REVIEW.md).
Đề xuất mới có hai FP có điều kiện / sáu unknown. Evaluator trả `failed_acceptance`
vì v0.2 loại một ca normalization nay đề xuất unknown. Dừng xác nhận acceptance;
không vá QL hoặc đổi nhãn để làm cùng lượt đánh giá đạt. Mức loại thêm v0.3 vẫn 0.

Chưa có human review, giao thức mới, model pack mới, quét mới, commit hoặc push
cho phần closeout. Không sửa bất kỳ gói đã khóa nào. Việc kế tiếp trực tiếp là
lượt rà tám sink của chủ đề án; đánh giá cuối vẫn chờ nhãn và các cổng còn thiếu.
