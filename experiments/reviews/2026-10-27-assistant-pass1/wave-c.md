# Đợt C: tám sink

Tất cả quyết định là `proposed`; không có nhãn owner được thêm. Đọc source đúng
SHA, đường đi mẫu và finite graph đã lưu; không chạy scanner. Thứ tự theo hàng
đợi START_HERE, không sắp lại để ưu tiên ca có kết quả đẹp.

Source pipecat: `pipecat-ai/pipecat@7519c26ac5508573c35fa3a9c4717b013993d129`.
Source atomic: `dep0we/atomic-agents-stack@ec474f458122c5c0ca718d0df3078c8080338b2c`.
Hash và URL đầy đủ ở [sources.json](sources.json). Audit source/graph ở [audit.json](audit.json).

## 8dcaf01d7907a8adda39bd13 — unknown

Sink pipecat `src/pipecat/runner/run.py:215:18`, root cause
`C-PC-NORMALIZATION`, production. Đường đi `filename` của route :261 → call
:267 → helper :212 → `(allowed_base / filename).resolve()` :215.

`allowed_base` được resolve ở :214; kết quả đích chỉ được kiểm tra bằng
`is_relative_to` ở :217–218. Nhánh lỗi không trả file, nhưng không đảo được
metadata I/O xảy ra trong resolve trước guard. Source không cung cấp căn cứ
loại metadata khỏi hậu quả đang xét. Không coi đây là exploit hoặc TP đã xác
nhận; tiếp tục unknown và giữ cảnh báo.

## 5859e664e867d805eef70b8c — FP đề xuất có điều kiện

Sink pipecat `run.py:268:16`, root cause `C-PC-DOWNLOAD-CONTAINMENT`, production.
Helper :212–220 trả **đúng Path đã resolve** sau khi kiểm tra containment; route
:267 gán giá trị này cho `file_path`, rồi :268 gọi `exists()`. Guard ném
HTTPException trước khi trả về nếu không chứa trong base. Route không bắt lỗi
để tiếp tục dùng giá trị cũ. Đường đi lưu có summary helper đã được đọc thân.

Kết luận FP chỉ theo mô hình attacker điều khiển filename, root download được
cấu hình hợp lệ, ổn định qua request và filesystem không bị đổi giữa guard và
sink. `--folder` :972 và docstring :213 hỗ trợ mục đích, không tự xác nhận mọi
quyền truy cập hoặc tính bất biến của Namespace dùng chung. S-ENV, S-PURPOSE
và A-SYM vẫn unknown ở mức triển khai. Chưa chấp nhận suppression vận hành.

## c295eacf017f952ad64f5391 — FP đề xuất có điều kiện

Sink pipecat `run.py:273:34`, cùng root cause và scope với ca :268. `FileResponse`
dùng Path trả về từ helper, không nối thêm thành phần không tin cậy sau guard.
`guess_type` :271 chỉ tính MIME, không thay đổi Path. Điều kiện root/policy như
ca :268; thêm việc filesystem vẫn ổn định tới lúc FileResponse thực sự mở
file. Chưa có phiên bản Starlette/deployment được xác nhận trong lượt này.
Không coi việc tồn tại :268 là cơ chế loại race; giữ suppression chưa chấp nhận.

## b99a22ccccd631527dd62004 — unknown

Sink atomic `atomic_agents/_io.py:110:17`, root cause `C-AA-NORMALIZATION`, production.
Ba nhánh đã lưu bắt nguồn từ `do_GET`: tên agent :71 → :80; rel :89 → :90;
bare :94 → :95. Hai nhánh sau qua `_serve_under_dashboard` :97/:105.
`safe_resolve_under` resolve `(root / child)` :110 **trước** `relative_to`
:113 và PathTraversalError :115. Root chỉ được resolve ở :111.

Guard chứng minh điều kiện trên giá trị trả về, không chứng minh I/O metadata
tại :110 an toàn. Với nhánh agent còn có kiểm tra ký tự :76, nhưng cùng sink
cũng nhận hai nhánh static không có kiểm tra đó. Không gán toàn sink FP dựa
trên một nhánh hoặc dựa vào tên helper. Scope metadata vẫn chưa xác lập.

## 29973e5cc3b0b49c809a4873 — unknown

Sink atomic `atomic_agents/dashboard/serve.py:113:16` (`exists`), root cause
`C-AA-CALLER-CONTAINMENT`, production. Ba path exemplar nhận hai dạng giá trị:
nhánh static dùng chính đích canonical :105 → :109; nhánh agent dùng thư mục
canonical :80 rồi nối `dashboard.html` :84. Phép nối con sau guard không tự
chứng minh canonical containment của file con. Symlink con có sẵn có thể
khác với race; loại trừ race đơn thuần không đủ.

Mục đích trong docstring :34–41 và đặc tả dashboard không tự xác nhận policy
cho mọi caller. Root động `self.agents_root`; `serve(..., host=...)` :173/:189
cũng không bảo đảm lời chú thích loopback-only luôn đúng. Giữ unknown.

## 1d3c60e0364a3a006fa676d3 — unknown

Sink atomic `serve.py:113:37` (`is_file`), cùng root cause và ba nhánh với :113:16.
Short circuit của `or` chỉ làm is_file chạy khi exists là true. Nó không kiểm
tra containment, policy hoặc symlink của đích. Các giả định triển khai và
root động vẫn chưa xác nhận. Không suy FP từ việc file là regular file.

## 788be445943d8a953ce5a232 — unknown

Sink atomic `serve.py:141:16` (`exists`), cùng root cause. Nhận Path từ
`_serve_file_contained` :116; ba nhánh đã lưu không có bước resolve/containment
bổ sung. Kiểm tra tồn tại lần nữa không sửa khoảng trống nhánh nối con :84
hoặc bất biến filesystem. Giữ unknown.

## 0f3b3e4c8adbc208a0ca43bd — unknown

Sink atomic `serve.py:145:23` (`read_bytes`), cùng root cause. Kiểm tra :141
không ràng buộc canonical target hoặc file descriptor được mở ở :145.
`except OSError` chỉ xử lý lỗi sau truy cập, không phải guard ngăn vượt thư
mục. Phải xét cả nhánh canonical static lẫn nhánh thư mục canonical + con.
Chưa có bằng chứng triển khai đủ để nhận toàn bộ các đường này là an toàn.

## Giả định và kết quả

Tám sink đều thuộc mã production; S-TEST được hỗ trợ theo file/route đã đọc,
không dùng quy tắc tên test để loại. S-TMP không phải căn cứ của các quyết
định này. Các trường A-SYM/S-ENV/S-PURPOSE chưa xác nhận được giữ unknown,
có ghi nguồn và điều kiện trong nhãn JSON. Không biến unknown thành một giả
định được chấp nhận để tăng số FP.

Nhãn đề xuất vẫn là 2 FP có điều kiện / 6 unknown như lượt tự rà 21/10.
Evaluator chỉ đọc output cũ; giữ lỗi acceptance vì baseline v0.2 đã loại ca
normalization :215. Mức loại tăng thêm v0.3 vẫn bằng 0. Đọc đủ finite graph
không thay xác nhận human, kiểm tra mọi thực thi hoặc kiểm tra triển khai.
