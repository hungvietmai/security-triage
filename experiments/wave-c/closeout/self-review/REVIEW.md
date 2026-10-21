# Tự rà kỹ thuật tám sink — 2026-10-21

**Kết quả: 2 FP đề xuất có điều kiện, 6 unknown.** Hai đề xuất normalization
trước đây được hạ từ FP thành unknown. Evaluator đã khóa trả exit 2,
`failed_acceptance`, do v0.2 đã loại một sink normalization nay mang nhãn đề xuất
unknown. Strict/scoped kế thừa tập kết quả đó; mức loại tăng thêm v0.3 vẫn bằng 0.

Đây là lượt tự rà của cùng assistant đã thấy dữ liệu, không phải owner review,
reviewer độc lập hoặc lượt human thứ hai. Kết luận kỹ thuật được ghi ngay ở đây;
không nhận danh tính/thời gian rà của người dùng. Giữ kết quả đánh giá lỗi và dừng
xác nhận acceptance; không sửa QL hay nhãn để lệnh trở thành thành công.

## Đã kiểm tra

- Toàn bộ tám alert và 18 đường đi mẫu, đối chiếu source đúng SHA và hash từ
  source audit đã khóa. Đọc guard, giá trị trả về, caller và các nhánh tới sink.
- Hai đồ thị đã lưu: 29 + 10 nút, 31 + 9 hàng cạnh, 2 + 1 summary gọi hàm.
  Bản decode mới có ID và URL. Các route hữu hạn trong đồ thị trừu tượng đều
  khớp một đường đi mẫu tương ứng; không nhận đây là mọi thực thi Python.
- Ba summary: hai nơi gọi `safe_resolve_under`, một nơi gọi
  `_resolve_download_path`. Kiểm tra thân helper ngoài các bước taint, vì guard
  không nhất thiết xuất hiện trên đường dữ liệu.
- Mô hình `FileSystemAccess` của python-all 7.2.6, quy tắc `excludedSink` của
  v0.2 và hành vi metadata của pathlib trong fixture độc lập tự tạo.

[audit.json](audit.json) giữ đối chiếu graph/path, [nodes.csv](nodes.csv) giữ
39 nút và dòng source; [labels.proposed.json](labels.proposed.json) là phiên bản
đề xuất mới. `all_reported_flows_reviewed=true` ở tệp đề xuất này chỉ ghi nhận
việc rà các artifact CodeQL vừa nêu. Nó không phải chứng minh toàn chương trình,
không xác nhận giả định triển khai và không đổi `review_status=proposed`.
Các ghi chú supplemental kế thừa trong tệp nhãn là lịch sử của đề xuất trước;
`label_evidence` và `label_changes.json` ghi quyết định mới.

## Quyết định từng sink

| Unit | Sink | Kết luận đề xuất mới | Lý do |
|---|---|---|---|
| 8dcaf01d | pipecat `run.py:215:18` | unknown, trước là FP | `resolve()` tra filesystem trước guard; thiếu chính sách về metadata |
| 5859e664 | pipecat `run.py:268:16` | FP có điều kiện | Dùng đúng giá trị canonical helper đã kiểm tra; hợp đồng folder/TOCTOU vẫn có điều kiện |
| c295eacf | pipecat `run.py:273:34` | FP có điều kiện | FileResponse dùng cùng giá trị trả về; không có phép đổi đường dẫn sau guard trong route đã rà |
| b99a22cc | atomic `_io.py:110:17` | unknown, trước là FP | Normalization xảy ra trước `relative_to`; không có căn cứ bỏ qua metadata |
| 29973e5c | atomic `serve.py:113:16` | unknown | Cùng sink nhận cả đích canonical và cha đã kiểm tra rồi nối con |
| 1d3c60e0 | atomic `serve.py:113:37` | unknown | `is_file` không kiểm tra lại containment; cùng điều kiện gốc/symlink chưa xác nhận |
| 788be445 | atomic `serve.py:141:16` | unknown | Kiểm tra tồn tại lặp lại không giải quyết chính sách gốc hoặc symlink con |
| 0f3b3e4c | atomic `serve.py:145:23` | unknown | `read_bytes` dùng đường nhận từ hai dạng caller; thiếu căn cứ chấp nhận mọi giả định |

Không có TP hoặc exploit ứng dụng mới nào được xác nhận. Unknown là kết luận
thiếu bằng chứng, không phải tự coi việc đọc metadata là một lỗ hổng khai thác được.

## Sửa lập luận normalization

Đề xuất trước thu hẹp hậu quả sang đọc/ghi nội dung tệp để gọi normalization là
FP. Lập luận đó chưa đủ: mô hình CodeQL đang coi cả `resolve`, `exists`, `stat`
và `read_bytes` là `FileSystemAccess`. Wave C không có căn cứ rõ ràng cho việc
bỏ metadata khỏi phạm vi. Không thay mô hình đe dọa; sửa độ chắc chắn của nhãn
thay vì tiếp tục dùng giả định hẹp chưa được xác nhận.

[Fixture metadata](metadata-observation.json) trên Python 3.12.3 xác nhận ở cả
hai dạng helper: `Path.resolve()` gọi `lstat` tới marker ngoài thư mục allowed
của fixture, rồi containment guard mới từ chối. Marker vẫn trong workspace;
không đọc nội dung, không có symlink hoặc race, không import/chạy ứng dụng.
Vì vậy, loại trừ TOCTOU hoặc chấp nhận A-SYM không tự giải quyết câu hỏi metadata
đã xảy ra trước guard. Quan sát này chưa chứng minh rò rỉ có thể quan sát từ xa.

Nguồn cục bộ đã kiểm tra:

- `Stdlib.qll`, class `PathlibFileAccess`, danh sách method gồm `resolve`, `stat`,
  `exists`, `is_file`, `read_bytes` (python-all 7.2.6).
- `PathInjectionCustomizations.qll`, `FileSystemAccessAsSink`.
- `SafetyEvidence.qll:480–493`: `excludedSink` loại receiver normalization khi
  kết quả được containment-check. Cần rà giả định của phép loại này; một guard
  sau normalization không chứng minh metadata trước guard là vô hại.

## Kết quả evaluator và quyết định vận hành

[Lệnh thực tế](evaluation-command.json) dùng nhãn đề xuất mới và evaluator đã
khóa, chỉ đọc các SARIF/CSV gốc. [Báo cáo](evaluation/report.json) giữ counts
`none=8`, `v0.2=5`, `strict=5`, `scoped=5`, nhưng đặt `safety_failure=true` theo
chính sách chặn ca unknown bị loại. Pipecat là repository `failed_acceptance`.

Ba sink pipecat bị v0.2 loại hiện gồm **hai FP đề xuất có điều kiện và một unknown**.
Không diễn giải cả ba thành FP được loại đúng. Đây là tín hiệu acceptance từ
lượt rà exploratory, không phải bằng chứng độc lập rằng đã mất TP. Số nhãn human
xác nhận vẫn bằng 0; tỷ lệ FP đã xác nhận vẫn N/A.

Quyết định vận hành thận trọng là giữ cảnh báo normalization chưa xác định đó;
không dùng danh sách đã lọc để che ca này. Danh sách raw vẫn được giữ nguyên để
tái lập. Dừng xác nhận an toàn/hiệu quả cho cấu hình hiện tại, ghi hạn chế trong
báo cáo và không vá rồi tiếp tục gọi cùng dữ liệu là kiểm tra độc lập.

## Đính chính hồ sơ ID và hai log đang mở

`paths-001/PATHS.md`, tám thẻ, khóa `graph_json_with_entity_ids` trong summary
và mô tả script đóng gói đã nói JSON có ID. **Thực tế decode mặc định chỉ có
label**, với nhiều nút trùng label; không thể tái dựng chính xác đồ thị bằng
label đó. Đây là lỗi mô tả artifact của lượt trước.

Giữ byte/khóa cũ để không viết lại lịch sử. Đã decode bốn BQRS lưu sẵn bằng
`--entities=all`: [bản mới](decoded), [lệnh và hash](decoded/commands.json),
[script](decode_saved.py). Bản mới có ID và URL, khi bỏ chúng đi thì khớp dữ
liệu label-only cũ; số alert, cạnh và summary không đổi. ID chỉ có ý nghĩa trong
phạm vi BQRS/type tương ứng, không phải ID source ổn định giữa mọi lần chạy.
Không chạy lại query, tạo database hoặc thực thi source.

`03-paths.stderr.log` và `03-edges.stderr.log` đều có warning import local
library `SafetyEvidence`; cả hai đã compile/evaluate xong và lệnh có exit 0
trong run manifest. Không gọi warning này là lỗi scanner, cũng không nhận log
stderr rỗng. Bản QLL được import khớp byte với baseline, và query `none` giữ
ExtraSanitizer rỗng. Không sửa import trong pack đã khóa để xóa warning.

## Tái lập phần tự kiểm

Các script từ repository root, với đầu ra mới, được lưu để đối chiếu. Các thư
mục hiện có không được ghi đè. Bốn lệnh decode đều exit 0; audit đọc output,
còn evaluator **exit 2 là kết quả thực tế phải giữ**, không phải lỗi cần né.
Không dùng lượt tự rà này làm lần human thứ hai hay giả nhận đã chờ bảy ngày.

[Kiểm tra](checks.json): 85 regression test bằng fixture tổng hợp đều qua;
execution lock và các khóa kết quả lịch sử vẫn khớp. Suite này không thay cho
kết quả evaluator failed_acceptance hoặc chứng minh nhãn mới. [Khóa tự rà](SELF_REVIEW_LOCK.sha256)
giữ dữ liệu decode, audit, quan sát metadata, nhãn đề xuất mới, báo cáo lỗi và log;
không thay các khóa cũ.
