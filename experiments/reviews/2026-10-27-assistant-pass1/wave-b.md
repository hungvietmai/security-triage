# Đợt B: 17 cảnh báo còn chờ

Rà source/caller theo SHA lỗi và vá trong inventory; các file chứa sink giống
nhau từng byte. Không có artifact đường đi CodeQL gốc B trên máy này. Mọi nhãn
dưới đây là đề xuất; `all_reported_flows_reviewed=false`, owner review vẫn chờ.
Tên FP trong bảng là FP theo các điều kiện đã nêu, không phải nhãn xác nhận.

| Root cause | Số ca | Đề xuất cũ | Đề xuất lượt này |
|---|---:|---|---|
| RC-M4 | 2 | unknown | unknown |
| RC-M5 | 1 | FP | unknown |
| RC-M7 | 1 | FP | unknown |
| RC-C1 | 5 | FP | FP có điều kiện |
| RC-C2 | 1 | TP | TP |
| RC-D1 | 3 | TP | TP |
| RC-D2 | 4 | FP | FP có điều kiện |

## mlflow — RC-M4 (2 unknown)

Commit vá `6e801f4259d96804c73107315b24cef0f6aa115a`, commit lỗi
`145703f1074e1bcc14ec2a2a38361762b190c433`.

- `mlflow/server/assistant/api.py:311:32`, `update_config`: dữ liệu projects từ
  request :304–310 đi vào `Path(location).expanduser()`, kiểm tra tồn tại :312,
  rồi lưu project location. Kiểm tra tồn tại không áp đặt allowed root.
- `mlflow/server/assistant/api.py:371:27`, `install_skills_endpoint`: nhánh custom
  :370 dùng `request.custom_path`; kiểm tra destination tồn tại :374 không
  chứng minh quyền ghi vào root, sau đó chuyển cho `install_skills` :380.

Router :62–66 áp dụng `_require_localhost`; :48–59 kiểm tra IP peer loopback.
Đây là ranh giới client, không phải guard containment. Chức năng cho phép
người vận hành chọn đường tùy ý có thể là chủ đích. Chưa có căn cứ về proxy,
browser origin hoặc quyền của client được tin cậy, nên không gán TP hoặc FP.
Không khẳng định DNS rebinding khai thác được. Chưa đọc thân skill installer
và chưa có các path gốc; không nhận đã duyệt mọi bước gọi hàm.

## mlflow — RC-M5 (1 unknown, trước là FP)

`mlflow/utils/uri.py:534:29`, `validate_path_within_directory`. Thân :521–542
resolve base :533, resolve constructed_path :534, sau đó mới kiểm tra
`is_relative_to` :536 và ném lỗi. Hàm **trả constructed_path gốc** ở :542,
không trả canonical Path; do đó không suy rằng caller dùng giá trị canonical.

Phạm vi nhãn ở đây là sink normalization :534, không tự suy một lỗ hổng ở
caller. Lập luận cũ "không đọc nội dung nên FP" không giải quyết metadata I/O
trước guard. Để nhất quán với đợt C, đề xuất unknown cho đến khi scope hậu quả
metadata được xác lập. Không tạo exploit, không khẳng định TP. V0.2 đã loại
ca này; không dùng nó làm FP được loại đúng đã xác nhận trong kết quả mới.

## mlflow — RC-M7 (1 unknown, trước là FP)

`mlflow/server/__init__.py:145:12`, `serve_gateway_proxy`, chuyển tới
`gateway_proxy_handler` trong `handlers.py:2029–2048`. `_validate_gateway_path`
:2008–2026 hạn chế endpoint request; `target_uri` do cấu hình. Điều này không
chứng minh kiểu JSON trả về của upstream. Nhánh HTTP 200 trả trực tiếp
`response.json()` :2042 mà không kiểm tra `dict`/`list` hoặc chủ động jsonify.

Source Flask tham chiếu phân biệt dict/list (JSON response) với str (response
body trực tiếp). JSON cấp cao có thể là chuỗi. Chưa xác nhận schema upstream,
khả năng attacker làm nó phản chiếu markup và phiên bản Flask thực chạy.
Vì vậy chưa đủ bằng chứng cho FP, cũng chưa đủ bằng chứng cho TP/khai thác.
Nhánh lỗi MlflowException được decorator :977–994 chuyển JSON không chứng minh
nhánh thành công an toàn. Hai bản `handlers.py` chỉ khác vùng xử lý model
version; các hàm/decorator liên quan nhãn này giữ nguyên.

## changedetection.io — RC-C1 (5 FP đề xuất có điều kiện)

Commit vá `49bc982c697169c98b79698889fb9d26f6b3317f`, commit lỗi
`e0abf0b50507a8a3d0c1d8522ab23519b3e4cdf4`.

- `changedetectionio/flask_app.py:1079:76`: `diff_history_page` lookup watch
  :1063; KeyError redirect :1064–1066 trước tạo `watch_dir` :1078. UUID special
  `first` lấy từ key có sẵn :1058–1059. Phải phân biệt directory với output
  filename do `send_from_directory` kiểm tra; không coi API này kiểm tra UUID.
- `changedetectionio/store.py:245:35`: `exists` trong nhánh delete một watch.
  Caller `/api/delete` chặn UUID không có trong datastore :1360–1362;
  checkbox operation :1439–1440 kiểm tra key rồi gọi delete với cùng strip.
- `changedetectionio/store.py:246:35`: `shutil.rmtree` dùng cùng Path :244.
  Check exists không phải guard bảo mật; căn cứ là membership tại caller.
- `changedetectionio/store.py:378:24`: kiểm tra screenshot path, caller edit
  page kiểm tra membership :671–673 trước call :820.
- `changedetectionio/store.py:378:62`: kiểm tra elements path; cùng UUID,
  caller guard và điều kiện với vế screenshot của short circuit.

`model/__init__.py:68` tạo UUID4. `store.py:355–357` bỏ uuid khỏi extras;
:364 thêm watch bằng key được tạo. Tuy nhiên `store.py:64–87` cũng nạp key từ
JSON cục bộ. Không nói mọi key trong mọi môi trường đều do server vừa sinh.
FP được đề xuất cho attacker HTTP không sửa được persisted datastore, plugin
hoặc filesystem/symlink; không đổi các điều kiện đó thành sự thật đã đo.
Chưa có full path B và chưa audit mọi writer/plugin. Nếu cho phép attacker
kiểm soát các tài nguyên này, nhãn phải được rà lại; vận hành vẫn giữ cảnh báo.

## changedetection.io — RC-C2 (1 TP đề xuất)

`changedetectionio/flask_app.py:1284:40`, `static_content`. Route :1239 nhận
group/filename là hai thành phần string. Nhánh mặc định :1284 tạo directory
`static/{group}` từ input, không kiểm tra group. `send_from_directory` kiểm
tra filename **bên dưới directory được truyền vào**; không biến directory do
client điều khiển thành root đáng tin. `group='..'` vượt khỏi static root.

Werkzeug 3.0.6 đúng pin trong requirements xác nhận ranh giới directory/path
này. Nhãn dựa trên cấu trúc source và hậu quả đọc file ngoài static root;
không thực thi request/exploit. Nhánh mặc định không có decorator login như
hai nhánh screenshot/visual-selector. Chưa nhận là đã tái xác minh đầy đủ
advisory hoặc triển khai thực tế.

## Django — RC-D1 (3 TP đề xuất)

Commit vá `05413afa8c18cdb978fcdf470e09f7a12b234a23`, commit lỗi
`6822aa5c6c3fbec7c5393a05e990865ba59fe167`.

- `django/contrib/admindocs/views.py:333:20`: `exists` trên
  `Path(directory) / self.kwargs['template']` :322/:332, không containment.
- `django/contrib/admindocs/views.py:334:41`: `read_text` trên cùng Path khi
  tồn tại; existence không giới hạn root.
- `django/contrib/admindocs/views.py:339:31`: gọi exists lần hai, đưa vào context
  templates; cùng đường thiếu containment.

`admindocs/urls.py:45–48` dùng converter path, cho phép thành phần slash.
`BaseAdminDocsView.dispatch` :37–43 yêu cầu staff và có docutils; đây là tiền
điều kiện cấu hình/quyền đã nhận diện, không phải kiểm tra đường dẫn. Nội dung
được đưa vào context; mức lộ nội dung cho người dùng phụ thuộc template thực
chạy. Không nhận lỗ hổng unauthenticated hoặc đã chạy exploit. Nhãn TP ở
phạm vi source đã phân tích, không dựa duy nhất vào tên CVE trong nhãn cũ.

## Django — RC-D2 (4 FP đề xuất có điều kiện)

- `django/views/static.py:37:8`: `is_dir`.
- `django/views/static.py:41:12`: `exists`.
- `django/views/static.py:44:15`: `stat`.
- `django/views/static.py:50:29`: mở file để tạo FileResponse.

Cả bốn dùng `fullpath = Path(safe_join(document_root, path))` :35–36.
`django/utils/_os.py:17–32` áp dụng abspath và ranh giới prefix có separator,
equality hoặc filesystem root; ném SuspiciousFileOperation trước trả giá trị
không đạt. Sink dùng giá trị trả về, không dùng raw path bỏ qua validator.
Caller staticfiles/views :30–39 còn có finders và DEBUG/insecure gate.

FP chỉ trong mô hình root hợp lệ do server cấu hình và không có symlink do
attacker kiểm soát dưới root. Đây là containment từ vựng, **không** canonical:
abspath không resolve symlink. Không dùng nhãn FP này để tuyên bố chặn symlink
hoặc an toàn triển khai tổng quát. Mô tả code chỉ dùng trong development không
đổi scope thành test: vẫn là production-library code được ứng dụng gọi.

## Hệ quả đối với số liệu

17 cảnh báo được rà thành 4 TP / 9 FP có điều kiện / 4 unknown đề xuất; không
có owner approval mới. RC-M5 và RC-M7 là hai thay đổi kỹ thuật; chín FP còn lại
có điều kiện được làm rõ hơn. Không tính lại tỷ lệ FP toàn B bằng cách trộn
nhãn đề xuất này với phần owner đã duyệt trước, không ghi đè LABELS_LOCK và
không xem việc đọc source thay cho đầy đủ path gốc.
