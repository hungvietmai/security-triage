# Khảo sát hợp đồng khai báo — kết luận hiện tại

**Chưa qua cổng để mở thí nghiệm chỉ bổ sung policy.** Đã tìm thấy tài liệu về
mục đích tài nguyên, nhưng chưa có hợp đồng triển khai được xác nhận và chưa có
cách gắn các gốc động này với chứng cứ containment bằng QL đã khóa. Việc thêm
chuỗi gốc vào `sinkAllowedRoot` đơn thuần không giải quyết cả hai việc đó.

Đây là khảo sát phát triển hậu kiểm trên hai snapshot đã xem. Không phải nhãn
độc lập, bằng chứng hiệu quả hay một vòng quét mới. Không có model pack mới,
thay đổi QL, source/sink hoặc kết quả lọc. Ngân sách đề xuất tối đa hai ngày;
khảo sát này dừng khi đã xác định được trở ngại cần thay phương pháp, không dùng
hết ngân sách để nới quy tắc.

## Phạm vi đã thực hiện

Đọc có mục tiêu tài liệu/cấu hình/source của hai repository có cảnh báo, đối chiếu
10 tệp được trích với hai archive đã khóa. Đọc thêm SPEC và QL hiện tại; không
import/chạy source, ứng dụng hoặc scanner. [source_evidence.json](evidence/source_evidence.json)
giữ hash, SHA, trích đoạn và liên kết tại commit, không lặp lại audit toàn bộ source.
Các tìm kiếm tài liệu không cho phép kết luận đã xem mọi tài liệu hoặc chứng minh
một chính sách không tồn tại ở nơi khác.

## Chính sách dự kiến và phần còn thiếu

| Nhóm sink | Chứng cứ mục đích ngoài phép nối | Hợp đồng có thể mô tả | Phần chưa được chứng minh |
|---|---|---|---|
| Pipecat `run.py:215:18` | CLI help `--folder` và docstring helper | Chuẩn hóa đường tải xuống dưới folder được cấu hình | Scope hậu quả của metadata I/O; folder động; chưa xác nhận hợp đồng triển khai |
| Pipecat `run.py:268:16`, `:273:34` | Cùng CLI/help, route tải tệp và docstring | Truy cập tệp đã kiểm tra dưới downloads folder | Binding `args.folder`, bot callback chia sẻ Namespace, quyền truy cập và TOCTOU |
| Atomic `_io.py:110:17` | Đặc tả dashboard nêu vị trí output; helper được dùng chung | Chuẩn hóa đường tương đối theo root của caller | Helper không có một root/policy duy nhất cho mọi caller; dynamic binding và scope metadata |
| Atomic `serve.py:113:16`, `:113:37`, `:141:16`, `:145:23` | Đặc tả riêng cho dashboard toàn cục/per-agent; README cấu hình vault | Chính sách khác nhau cho static-dashboard và trang từng agent | Hai dạng containment tới cùng sink; symlink con có sẵn; root động; quyền và triển khai chưa xác nhận |

Không gán các hàng này thành hợp đồng được chấp nhận. Tám sink vẫn giữ nguyên
nhãn đề xuất/chưa duyệt và kết quả chính.

## Những nguồn chính sách có ích nhưng chưa đủ

Atomic [đặc tả dashboard:54](https://github.com/dep0we/atomic-agents-stack/blob/ec474f458122c5c0ca718d0df3078c8080338b2c/docs/spec/09-cost-observability.md#L54)
và [dòng 87](https://github.com/dep0we/atomic-agents-stack/blob/ec474f458122c5c0ca718d0df3078c8080338b2c/docs/spec/09-cost-observability.md#L87)
nêu output toàn cục `<agents_root>/_dashboard/index.html` và trang từng agent
`<agents_root>/{agent_name}/dashboard.html`. Đây là bằng chứng mục đích từ tài liệu,
tách khỏi nhãn FP và phép `join`; chưa phải danh sách đầy đủ mọi tài nguyên HTTP
được phép phục vụ. Đặc tả ở dòng 191 nói Flask/FastAPI trong khi source thực tế
dùng `http.server`, cho thấy cần đối chiếu tài liệu thay vì coi nó tuyệt đối đúng.

[README:278](https://github.com/dep0we/atomic-agents-stack/blob/ec474f458122c5c0ca718d0df3078c8080338b2c/README.md#L278)
nêu biến cấu hình vault. [SECURITY.md:29](https://github.com/dep0we/atomic-agents-stack/blob/ec474f458122c5c0ca718d0df3078c8080338b2c/SECURITY.md#L29)
nêu quyền dựa trên filesystem của người vận hành. Cả hai không xác nhận rằng mọi
tệp nằm dưới root đều được một HTTP caller bất kỳ phép đọc. Cũng không dùng
docstring loopback-only thay bằng chứng host không thể đổi: API/CLI cho phép đổi host.

Pipecat [run.py:972](https://github.com/pipecat-ai/pipecat/blob/7519c26ac5508573c35fa3a9c4717b013993d129/src/pipecat/runner/run.py#L972)
đặt tên mục đích folder qua CLI; [helper:212](https://github.com/pipecat-ai/pipecat/blob/7519c26ac5508573c35fa3a9c4717b013993d129/src/pipecat/runner/run.py#L212)
nêu containment. Đây là mô tả API/source tại snapshot; người rà đã thấy output
trước khi khảo sát nên không gọi việc khai báo hậu kiểm này là annotation mù.
Không có chứng cứ về triển khai thật hay phân quyền được cung cấp trong lượt này.

## Trở ngại kỹ thuật với phiên bản đang đóng băng

1. `rootValue`/`trustedRoot` trong [IpgGuard.qll](../../v03-interprocedural-guard/ql/IpgGuard.qll)
   chỉ nhận các dạng giá trị tĩnh được liệt kê. Nó không gắn một chuỗi do model
   pack khai báo với `args.folder`, `self.agents_root` hay giá trị tham số root.
   Khai báo thêm AllowedRoot không tự sinh ProvenContained cho giá trị động.
2. `sinkAllowedRoot(file, function, root)` không có ngữ cảnh route/caller. Cùng
   helper đọc tệp của atomic nhận cả nhánh static-dashboard lẫn agent. Dùng gốc
   vault rộng cho tất cả để né khác biệt chính sách sẽ làm yếu hợp đồng dự kiến.
3. Hợp đồng đúng không sửa được containment thiếu: resolve cha rồi nối
   `dashboard.html` vẫn cần A-SYM cho symlink con có sẵn. Không thể coi một policy
   khai báo là bằng chứng filesystem hoặc tự chuyển unknown thành FP.
4. Tài liệu nêu đường output không đủ để xác nhận chính sách quyền. Oracle nhãn
   không được chỉ đọc cùng policy model rồi nhận các sink bị loại đều là FP.

Đây là giới hạn nhận diện qua đọc QL/source và diagnostics đã lưu, không phải một
lượt đo tác động của model mới. Không có số dự đoán "sẽ loại thêm" nào được tính.

## Mẫu hợp đồng và điều kiện dùng lại

[contract.template.json](contract.template.json) là biểu mẫu tài liệu trống,
**không phải model pack CodeQL**, không được nạp vào scanner. Mẫu yêu cầu:

- Snapshot và thao tác/sink cụ thể; context route/caller khi chính sách khác nhau.
- Nguồn chính sách, tài nguyên được phép, giới hạn quyền và chính sách xung đột.
- Binding root và vòng đời/ghi lại; chứng cứ containment của đúng giá trị tại sink.
- Giả định được rà riêng, evidence label độc lập với policy, thời gian khai báo thật.

Các trường còn trống có nghĩa chưa biết. Không điền đường tuyệt đối giả định để
cho đủ tuple, không chọn quyền truy cập bằng cách xem sink nào đã được gán FP.
Trong thí nghiệm tương lai, hợp đồng phải được lập trước khi xem output liên quan,
và nhãn đánh giá cần căn cứ riêng; dữ liệu đã dùng sửa phương pháp là phát triển.

**Quyết định thực hiện:** dừng trước bước mở thí nghiệm mới. Hoàn thiện báo cáo và
human review hiện tại. Chỉ cân nhắc phương pháp binding root theo ngữ cảnh trong
một đề xuất nghiên cứu riêng nếu có nhu cầu tiếp theo và chứng cứ chính sách phù
hợp; đó sẽ là mở rộng phương pháp, không còn là thử nghiệm chỉ bổ sung policy.
