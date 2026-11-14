# CHƯƠNG 1: TỔNG QUAN VỀ PHÂN TÍCH MÃ NGUỒN VÀ CÁC CÔNG CỤ LIÊN QUAN

> **Ghi chú cho người viết (không thuộc nội dung đề án).** Văn bản ngày 2026-11-14, theo đúng
> đề mục của đề cương. Số trong ngoặc vuông là số thứ tự tài liệu tham khảo của đề cương;
> [15]–[19] là tài liệu đề nghị bổ sung. Mọi câu có trích dẫn đã được đối chiếu với nguồn ngày
> 2026-11-14; kết quả đối chiếu và **bốn chỗ danh mục của đề cương ghi sai** nằm ở cuối tệp.

Chương này trình bày cơ sở của phân tích mã nguồn tĩnh, bản chất của cảnh báo và vấn đề cảnh báo
sai, lý do và nguyên tắc phối hợp nhiều công cụ, sau đó khảo sát bốn công cụ được dùng trong đề
án: Semgrep, Bandit, ESLint với eslint-plugin-security, và CodeQL.

## 1.1. Tổng quan về phân tích mã nguồn tự động trong kiểm tra an toàn phần mềm

### 1.1.1. Khái quát về phân tích mã nguồn tĩnh

**Khái niệm và mục tiêu.** Kiểm thử an toàn ứng dụng tĩnh (Static Application Security Testing,
SAST) là việc dùng công cụ để tìm dấu hiệu lỗ hổng bảo mật trong mã nguồn mà không chạy chương
trình. Công cụ đọc mã, dựng một mô hình của chương trình và đối chiếu mô hình đó với mô tả của
từng loại lỗi. Vì không cần môi trường chạy, SAST áp dụng được ngay từ lúc viết mã và trong mỗi
lần tích hợp, sớm hơn kiểm thử động và kiểm thử xâm nhập.

Mục tiêu của SAST trong quy trình phát triển gồm ba điểm:

- phát hiện sớm lỗi thuộc các nhóm đã biết, ví dụ chèn lệnh hệ điều hành (CWE-78) hay duyệt
  đường dẫn (CWE-22);
- chỉ ra vị trí cụ thể trong mã để lập trình viên sửa;
- tạo kết quả lặp lại được trên cùng một phiên bản mã, làm căn cứ theo dõi theo thời gian.

**Các hướng tiếp cận phổ biến.** Công cụ SAST khác nhau chủ yếu ở mô hình chương trình mà chúng
dựng và ở độ sâu của phép suy luận trên mô hình đó.

1. *Khớp mẫu cú pháp.* Công cụ phân tích mã thành cây cú pháp trừu tượng (AST) và tìm các nút
   khớp một mẫu, ví dụ "mọi lời gọi `subprocess.run` có tham số `shell=True`". Cách này nhanh,
   dễ viết luật và dễ giải thích. Nó không biết dữ liệu trong lời gọi đến từ đâu, nên báo cả
   những lời gọi có đối số là hằng.
2. *Phân tích luồng dữ liệu và phân tích vết bẩn (taint analysis).* Công cụ mô hình hóa ba loại
   điểm: **nguồn** (source) là nơi dữ liệu không tin cậy đi vào, **đích** (sink) là thao tác
   nguy hiểm, và **bộ làm sạch** (sanitizer) là thao tác khiến dữ liệu an toàn. Một cảnh báo
   được sinh ra khi có đường đi từ nguồn tới đích không qua bộ làm sạch. Phân tích *trong một
   hàm* (intraprocedural) rẻ nhưng mất dấu khi dữ liệu đi qua lời gọi hàm; phân tích *liên hàm*
   (interprocedural) theo được dữ liệu qua nhiều hàm và nhiều tệp với chi phí cao hơn.
3. *Truy vấn trên cơ sở dữ liệu mã.* Mã nguồn được trích xuất thành một cơ sở dữ liệu quan hệ
   chứa AST, đồ thị luồng điều khiển và luồng dữ liệu. Mỗi loại lỗi là một truy vấn trên cơ sở
   dữ liệu đó. CodeQL thuộc nhóm này.

Lấy ví dụ đoạn mã Python sau:

```python
def ping(request):
    host = request.args["host"]           # nguồn: dữ liệu từ người dùng
    subprocess.run("ping -c 1 " + host,   # đích: lệnh shell
                   shell=True)
```

Công cụ khớp mẫu báo dòng `subprocess.run` vì có `shell=True`. Công cụ phân tích vết bẩn báo vì
`host` đi từ `request.args` tới đối số lệnh. Nếu thay `host` bằng một chuỗi hằng, công cụ thứ
nhất vẫn báo còn công cụ thứ hai thì không. Nếu `host` được lấy qua một hàm bọc mà công cụ thứ
hai không mô hình hóa, công cụ thứ hai im lặng trong khi lỗi vẫn còn. Hai tình huống này chính là
hai loại sai số mà mọi công cụ SAST phải đánh đổi.

**Giới hạn về nguyên lý.** Mọi tính chất không tầm thường về hành vi của chương trình đều không
quyết định được bằng thuật toán trong trường hợp tổng quát (định lý Rice [15]). Công
cụ vì thế phải xấp xỉ: xấp xỉ rộng thì báo thừa (cảnh báo sai), xấp xỉ hẹp thì bỏ sót. Không có
cấu hình nào loại được cả hai; câu hỏi thực tế là chọn điểm cân bằng nào và xử lý phần sai số
còn lại ra sao.

### 1.1.2. Cảnh báo trong phân tích mã nguồn

**Thông tin cơ bản của cảnh báo và yêu cầu truy vết.** Một cảnh báo hữu ích phải trả lời được bốn
câu hỏi: lỗi gì, ở đâu, vì sao công cụ cho là lỗi, và kết quả này sinh ra từ đâu. Tương ứng, một
cảnh báo cần có:

| Thành phần | Nội dung |
|---|---|
| Luật | Mã định danh của luật hoặc truy vấn, nhóm lỗi (CWE), mức độ |
| Vị trí | Tệp, dòng và cột bắt đầu, kết thúc của vùng mã |
| Giải thích | Thông điệp; với phân tích luồng dữ liệu là dãy các bước từ nguồn tới đích |
| Nguồn gốc | Tên và phiên bản công cụ, bộ luật, phiên bản mã nguồn được quét |

Thành phần cuối thường bị xem nhẹ nhưng quyết định khả năng tái lập: cùng một kho mã, khác phiên
bản công cụ hoặc khác bộ luật sẽ cho tập cảnh báo khác. Định dạng SARIF 2.1.0 của OASIS [10] quy
định cách biểu diễn cả bốn thành phần trong một tài liệu JSON: `tool.driver` mô tả công cụ và
luật, `results[].locations` mô tả vị trí, `results[].codeFlows` mô tả đường đi của dữ liệu,
`results[].suppressions` ghi nhận cảnh báo đã bị gạn cùng lý do. Semgrep [12], Bandit [11] và
CodeQL [14] đều xuất được SARIF, và nền tảng quét mã của GitHub nhận định dạng này [13]. Đề án
dùng SARIF làm định dạng trao đổi duy nhất giữa công cụ và hệ thống.

**Tiêu chí đánh giá chất lượng cảnh báo.** Khi có nhãn đúng/sai cho từng vị trí, kết quả của
công cụ được chia thành:

- *đúng dương tính* (true positive, TP): công cụ báo và vị trí thật sự có lỗi;
- *dương tính giả* (false positive, FP), hay cảnh báo sai: công cụ báo nhưng vị trí an toàn;
- *âm tính giả* (false negative, FN), hay bỏ sót: vị trí có lỗi mà công cụ không báo.

Từ đó tính ba chỉ số dùng trong đề án:

- độ chính xác (precision) = TP / (TP + FP): trong các cảnh báo, bao nhiêu phần là lỗi thật;
- độ bao phủ (recall) = TP / (TP + FN): trong các lỗi thật, bao nhiêu phần được báo;
- F1 = 2 × precision × recall / (precision + recall).

Ba chỉ số này chỉ có nghĩa trên một tập vị trí đã gán nhãn. Trên mã thực tế, số lỗi thật chưa
biết nên độ bao phủ thường chỉ tính được trên các lỗ hổng đã công bố. Ngoài đúng và sai, các
nghiên cứu về hành vi của lập trình viên còn dùng khái niệm cảnh báo *đáng hành động*
(actionable): cảnh báo mà người nhận thực sự sửa. Yedida và cộng sự [8] xuất phát từ nhận xét
rằng lập trình viên chỉ xử lý một phần nhỏ cảnh báo của công cụ phân tích tĩnh, và huấn luyện
mô hình dự đoán cảnh báo đáng hành động trên tám dự án Java. Một cảnh báo đúng về kỹ thuật
nhưng không ai xử lý cũng không mang lại giá trị.

**Vấn đề cảnh báo sai và tác động trong dự án thực tế.** Cảnh báo sai gây ba loại chi phí. Thứ
nhất là thời gian: mỗi cảnh báo cần một người đọc mã để phân loại. Thứ hai là niềm tin. Nhóm
xây dựng nền tảng phân tích Tricorder tại Google [7] định nghĩa *cảnh báo sai hiệu dụng*
(effective false positive) là mọi báo cáo mà người nhận chọn không xử lý, tức là nhìn từ phía
lập trình viên chứ không từ phía người viết bộ phân tích. Họ yêu cầu tỷ lệ này dưới 10% đối
với kết quả hiển thị lúc rà soát mã; bộ phân tích có tỷ lệ bị đánh dấu "không hữu ích" từ 10%
bị đưa vào diện theo dõi và trên 25% có thể bị tắt. Thứ ba là rủi ro bị che khuất: khi danh
sách quá dài, lỗi thật nằm lẫn giữa cảnh báo sai và dễ bị bỏ qua. Hu và cộng sự [3] khảo sát
việc tắt cảnh báo trong mã Python, Java và JavaScript với bốn công cụ (Pylint, Checkstyle,
PMD, ESLint): cảnh báo sai là một trong các lý do phổ biến để tắt, một phần chỉ thị tắt không
còn tác dụng với cảnh báo nào, và một phần có thể vô tình che cảnh báo phát sinh về sau. Cơ
chế tắt cảnh báo trong mã vì vậy vừa là công cụ quản lý, vừa là nơi lỗi thật có thể bị giấu đi.

Các nghiên cứu so sánh công cụ SAST, về khả năng phát hiện, cách báo cáo và tính dễ dùng [1]
hay trên lỗ hổng thực tế của mã Java [2], là cơ sở để đề án không giả định trước rằng một công
cụ đơn lẻ đủ tốt, mà đo từng công cụ trên cùng dữ liệu trước khi kết hợp.

## 1.2. Tổng quan về cách tiếp cận kết hợp nhiều công cụ để giảm cảnh báo sai

### 1.2.1. Lý do cần kết hợp nhiều công cụ

Các công cụ dùng kỹ thuật khác nhau nên sai theo cách khác nhau:

| Kỹ thuật | Thường báo thừa khi | Thường bỏ sót khi |
|---|---|---|
| Khớp mẫu cú pháp | Lời gọi nguy hiểm về hình thức nhưng đối số an toàn | Lời gọi không khớp mẫu đã viết |
| Vết bẩn trong một hàm | Dữ liệu được làm sạch ở hàm khác | Nguồn và đích nằm ở hai hàm |
| Vết bẩn liên hàm | Đường đi tồn tại trên đồ thị nhưng không xảy ra khi chạy | Nguồn, đích hoặc hàm trung gian chưa được mô hình hóa |

Từ bảng này có hai hệ quả. Một là tập lỗi thật mà mỗi công cụ báo không trùng nhau, nên lấy
**hợp** kết quả của nhiều công cụ có thể tăng độ bao phủ. Hai là một công cụ có thể cung cấp
thông tin mà công cụ kia thiếu về cùng một vị trí, nên kết quả của công cụ này có thể dùng để
**thẩm định** cảnh báo của công cụ kia.

Thí điểm của chính đề án trên 20 vị trí chèn lệnh của bộ OWASP BenchmarkPython minh họa cả hai hệ
quả (số liệu chi tiết ở Chương 3): CodeQL báo 11 trên 13 lỗi thật, Semgrep báo 7, và hai lỗi còn
lại chỉ được Bandit báo; ngược lại, cả bảy vị trí an toàn đều bị ít nhất một công cụ khớp mẫu
báo.

Cái giá của việc lấy hợp là số cảnh báo tăng và cùng một lỗi bị báo nhiều lần ở những vị trí hơi
khác nhau. Kết hợp nhiều công cụ vì thế luôn kéo theo hai bài toán: **gộp** các cảnh báo cùng một
vấn đề và **gạn** bớt cảnh báo sai.

### 1.2.2. Nguyên tắc sàng lọc và thẩm định theo nhiều bước

Tài liệu về giảm cảnh báo sai đi theo hai hướng chính. Hướng thứ nhất dùng học máy để phân loại
cảnh báo sau khi công cụ đã sinh ra chúng: mạng nơ-ron tích chập phân loại cảnh báo sai của bộ
kiểm tra tĩnh trong tích hợp liên tục [5]; mô hình Transformer lọc cảnh báo sai của bộ phát
hiện lỗi cho hai loại lỗi (tham chiếu rỗng và rò rỉ tài nguyên), với mức tăng độ chính xác
được báo cáo là 17,5% [4]; hay bộ phân loại cắt tỉa cạnh sai trong đồ thị lời gọi tĩnh [6].
Hướng này cần
dữ liệu huấn luyện có nhãn và cho quyết định khó giải thích với người rà soát. Hướng thứ hai tổ
chức phân tích thành nhiều bước: bước đầu rẻ và rộng để tạo tập nghi vấn, bước sau đắt và sâu để
xem xét lại tập đó. Đề án đi theo hướng thứ hai, vì kết quả của nó giải thích được bằng chính
bằng chứng mà công cụ đưa ra và không cần dữ liệu huấn luyện.

Đề án đặt năm nguyên tắc cho một quy trình nhiều bước. Chúng được dùng làm ràng buộc thiết kế ở
Chương 2.

1. **Không xóa cảnh báo.** Bước thẩm định chỉ thay đổi nơi hiển thị và thứ tự rà soát. Cảnh báo
   bị gạn vẫn xem lại được cùng nguyên bản và lý do.
2. **Chỉ gạn khi có bằng chứng cụ thể.** Bằng chứng là một phát biểu kiểm tra lại được về chính
   vị trí đó, ví dụ "dữ liệu chỉ tới lệnh qua một nhánh không bao giờ chạy".
3. **Im lặng không phải bằng chứng.** Việc một công cụ không báo một vị trí không chứng minh vị
   trí đó an toàn; có thể công cụ chưa mô hình hóa nguồn dữ liệu.
4. **Thiếu thì giữ.** Khi công cụ chạy dở, bằng chứng mâu thuẫn hoặc không đối chiếu được vị
   trí, cảnh báo ở lại danh sách rà chính.
5. **Đo cả phần mất.** Mọi phép gạn phải đi kèm số lỗi thật bị gạn nhầm trên dữ liệu có nhãn,
   bên cạnh số cảnh báo sai được loại.

Nguyên tắc 3 có hệ quả trực tiếp tới thiết kế: nếu công cụ phân tích sâu chỉ xem lại những vị trí
mà công cụ quét nhanh đã báo, thì mọi lỗi công cụ quét nhanh bỏ sót sẽ mất hẳn. Chương 2 trình
bày điều chỉnh mà đề án thực hiện vì lý do này.

## 1.3. Khảo sát công cụ sàng lọc nhanh

### 1.3.1. Semgrep

Semgrep là công cụ phân tích tĩnh mã nguồn mở (bản Community Edition, giấy phép LGPL-2.1) hỗ trợ
nhiều ngôn ngữ, trong đó có Python, JavaScript và TypeScript. Đặc điểm chính:

- **Luật viết bằng YAML, mẫu viết bằng chính cú pháp của ngôn ngữ đích.** Mẫu
  `subprocess.run($CMD, shell=True, ...)` khớp mọi lời gọi có dạng đó; `$CMD` là biến mẫu
  (metavariable), `...` khớp phần còn lại. Luật kết hợp nhiều mẫu bằng các toán tử như
  `pattern-either`, `pattern-not`, `pattern-inside`.
- **Chế độ vết bẩn** (`mode: taint`) cho phép khai báo nguồn, đích và bộ làm sạch bằng mẫu. Ở
  bản Community Edition, phép phân tích này giới hạn trong một hàm.
- **Lan truyền hằng.** Semgrep suy ra giá trị của biến được gán hằng và cho phép so sánh giá trị
  đó trong luật (`metavariable-comparison`). Đề án dùng khả năng này ở bước thẩm định để chứng
  minh một nhánh điều kiện không bao giờ chạy (Chương 2).
- **Không cần biên dịch hay cài phụ thuộc** của dự án được quét; thời gian chạy tính bằng giây
  trên các dự án đã đo ở Chương 3.
- **Xuất SARIF** bằng tham số dòng lệnh [12].

Hạn chế đối với bài toán của đề án: luật khớp mẫu báo theo hình thức của lời gọi nên sinh nhiều
cảnh báo sai; luật vết bẩn của bản Community Edition không theo được dữ liệu qua lời gọi hàm nên
bỏ sót các lỗi có nguồn và đích ở hai hàm khác nhau.

Đề án dùng Semgrep 1.178.0 với bốn luật cộng đồng cho mỗi ngôn ngữ ở bước phát hiện, và một gói
ba luật tự viết ở bước thẩm định.

### 1.3.2. Công cụ bổ trợ theo ngôn ngữ

Công cụ bổ trợ được chọn theo sáu tiêu chí chung, xuất phát từ yêu cầu của quy trình:

| Tiêu chí | Lý do |
|---|---|
| Mã nguồn mở, giấy phép cho phép dùng trong nghiên cứu | Tái lập và kiểm tra được |
| Có luật cho nhóm lỗi mục tiêu tại vị trí lời gọi | Gộp được với cảnh báo của công cụ khác |
| Xuất được SARIF | Dùng chung bộ chuẩn hóa |
| Không cần chạy hay cài đặt mã được quét | An toàn khi quét mã không tin cậy |
| Cấu hình cố định được từ bên ngoài kho mã | Mã bị quét không tự tắt được luật |
| Thời gian chạy ngắn | Đúng vai trò quét nhanh |

**Tiêu chí lựa chọn công cụ cho JavaScript/TypeScript.** ESLint là bộ kiểm tra mã phổ biến nhất
của hệ sinh thái JavaScript (giấy phép MIT); eslint-plugin-security (Apache-2.0) bổ sung các luật
bảo mật. Với nhóm lỗi chèn lệnh, plugin có luật `detect-child-process`, báo lời gọi
`child_process.exec()` có đối số đầu không phải chuỗi hằng. Kết quả được xuất SARIF qua bộ định
dạng `@microsoft/eslint-formatter-sarif`; TypeScript được đọc bằng `@typescript-eslint/parser`.
Hai điểm cần lưu ý khi dùng ESLint làm công cụ bảo mật:

- mặc định ESLint tôn trọng chú thích `eslint-disable` và tệp cấu hình nằm trong kho mã, nên
  phải chạy với cấu hình tuyệt đối từ bên ngoài và tắt chú thích nội tuyến;
- luật chỉ bao phủ `exec()`; các hàm `spawn`, `execFile`, `execSync` nằm ngoài phạm vi.

Đề án dùng ESLint 10.15.0 và eslint-plugin-security 4.2.1.

**Tiêu chí lựa chọn công cụ cho Python.** Bandit là công cụ của nhóm PyCQA (Apache-2.0) chuyên
tìm lỗi bảo mật phổ biến trong mã Python bằng cách duyệt AST và chạy các bộ kiểm tra theo từng
loại nút [11]. Với nhóm lỗi chèn lệnh, Bandit có các kiểm tra tại vị trí lời gọi: `B602` và `B604`
(lời gọi có `shell=True`), `B603` và `B606` (khởi chạy tiến trình không qua shell), `B605` (khởi
chạy tiến trình qua shell), `B607` (đường dẫn chương trình không đầy đủ), `B609` (ký tự đại diện
trong lệnh). Mỗi kết quả có mức nghiêm trọng và độ tin cậy; riêng `B602` và `B605` hạ mức nghiêm
trọng xuống LOW khi đối số lệnh là chuỗi hằng. Chi tiết này được đề án dùng làm một nguồn bằng
chứng ở bước thẩm định. Tương tự ESLint, Bandit đọc tệp cấu hình `.bandit` và chú thích `# nosec`
trong mã được quét, nên phải chạy với cấu hình đã cố định và bỏ qua `# nosec`.

Đề án dùng Bandit 1.9.4.

Cả hai công cụ bổ trợ đều chỉ khớp mẫu cú pháp. Chúng báo rộng, nhanh, không phân biệt đối số
an toàn hay không, và vì thế phù hợp với vai trò tạo tập nghi vấn hơn là vai trò thẩm định.

## 1.4. Khảo sát công cụ thẩm định sâu CodeQL

CodeQL là bộ máy phân tích ngữ nghĩa mã nguồn do GitHub phát triển. Nó hoạt động theo hai giai
đoạn:

1. **Trích xuất.** Mã nguồn được chuyển thành một cơ sở dữ liệu chứa cây cú pháp, đồ thị luồng
   điều khiển, đồ thị luồng dữ liệu và thông tin kiểu. Với Python và JavaScript/TypeScript,
   bước này không cần biên dịch dự án.
2. **Truy vấn.** Mỗi loại lỗi được viết thành một truy vấn bằng ngôn ngữ QL, một ngôn ngữ logic
   hướng đối tượng. Thư viện chuẩn cung cấp sẵn mô hình nguồn, đích và các bước lan truyền cho
   nhiều khung phát triển (Flask, Django, Express...).

Các đặc điểm quan trọng đối với đề án:

- **Phân tích vết bẩn liên hàm.** CodeQL theo dữ liệu qua lời gọi hàm, thuộc tính đối tượng và
  nhiều tệp. Truy vấn dạng đường đi (path query) trả về không chỉ vị trí đích mà cả dãy bước từ
  nguồn tới đích, được ghi trong `codeFlows` của SARIF [14].
- **Mở rộng được bằng rào chắn (barrier).** Người viết truy vấn có thể khai báo thêm điều kiện
  chặn luồng, ví dụ "giá trị đã được so sánh với một hằng". Đề án dùng cơ chế này để viết các
  *truy vấn bằng chứng an toàn*: cùng một truy vấn gốc nhưng thêm rào chắn; cảnh báo biến mất
  sau khi thêm rào chắn là cảnh báo có bằng chứng bác bỏ.
- **Một cơ sở dữ liệu, nhiều truy vấn.** Trích xuất là phần tốn thời gian nhất; sau đó có thể
  chạy thêm truy vấn mà không trích xuất lại. Nhờ vậy bước thẩm định chỉ tốn thêm thời gian
  chạy truy vấn.
- **Chi phí.** Thời gian và bộ nhớ lớn hơn các công cụ khớp mẫu một bậc; trong các lần đo ở
  Chương 3, CodeQL chiếm phần lớn thời gian của mỗi lượt quét.
- **Giấy phép.** Thư viện và truy vấn chuẩn là mã nguồn mở (giấy phép MIT). Bản thân CodeQL
  CLI **không phải** mã nguồn mở: điều khoản sử dụng cho phép dùng miễn phí cho nghiên cứu học
  thuật và cho mã nguồn mở. Đề án ghi rõ điểm này và tách riêng phần kết quả chỉ dựa trên công
  cụ mã nguồn mở.

Hạn chế đối với bài toán của đề án: CodeQL chỉ báo khi cả nguồn, đích và mọi bước trung gian đều
đã được mô hình hóa. Dữ liệu đi vào qua một lớp bọc tự viết hoặc một thư viện chưa có mô hình sẽ
không tạo cảnh báo. Trong thí điểm, đây là nguyên nhân của hai lỗi thật mà CodeQL bỏ sót.

Đề án dùng CodeQL 2.27.1 với hai truy vấn chèn lệnh mặc định cho mỗi ngôn ngữ, và các gói truy
vấn bằng chứng tự viết cho Python.

**So sánh bốn công cụ theo vai trò trong quy trình.**

| | Semgrep CE | Bandit | ESLint + plugin-security | CodeQL |
|---|---|---|---|---|
| Ngôn ngữ trong đề án | Python, JS/TS | Python | JS/TS | Python, JS/TS |
| Kỹ thuật | Khớp mẫu; vết bẩn trong một hàm | Khớp mẫu trên AST | Khớp mẫu trên AST | Vết bẩn liên hàm trên cơ sở dữ liệu mã |
| Có đường đi của dữ liệu | Có, với luật vết bẩn | Không | Không | Có |
| Chi phí chạy | Thấp | Thấp | Thấp | Cao |
| Giấy phép | LGPL-2.1 | Apache-2.0 | MIT / Apache-2.0 | Truy vấn: MIT; CLI: không mã nguồn mở |
| Vai trò trong đề án | Nguồn phát hiện; bằng chứng thẩm định | Nguồn phát hiện; tín hiệu lệnh hằng | Nguồn phát hiện | Nguồn phát hiện; bằng chứng thẩm định |

## 1.5. Kết chương

Chương này đã trình bày ba nội dung. Thứ nhất, cảnh báo sai là hệ quả tất yếu của việc xấp xỉ
trong phân tích tĩnh, và tác động của nó tới người dùng đủ lớn để quyết định một công cụ có được
dùng hay không. Thứ hai, các công cụ sai theo cách khác nhau, nên kết hợp chúng vừa tăng được độ
bao phủ vừa tạo ra thông tin để thẩm định, với điều kiện giải quyết được việc gộp cảnh báo trùng
và tuân theo các nguyên tắc: không xóa, chỉ gạn khi có bằng chứng, im lặng không phải bằng chứng,
thiếu thì giữ, và đo cả phần mất. Thứ ba, bốn công cụ được khảo sát có vai trò bổ sung cho nhau:
Semgrep, Bandit và ESLint quét nhanh và rộng; CodeQL phân tích sâu, có đường đi của dữ liệu và
mở rộng được để tạo bằng chứng. Chương 2 dùng các kết luận này để thiết kế quy trình.

---

## Kết quả đối chiếu tài liệu tham khảo (2026-11-14)

Phần này không thuộc nội dung đề án. Mọi câu có trích dẫn trong chương đã được đối chiếu với
nguồn; số liệu chỉ được dùng khi đọc được trong nguồn.

| Số | Kết quả đối chiếu | Việc cần làm với danh mục |
|---|---|---|
| [1] | Bài báo tồn tại (EASE Companion 2025). **Đề cương ghi sai tác giả**: tác giả là Haifa Al-Shammare, Rawan Alraddadi, Faten Al-Abdulwahhab, Mahmood Niazi, Mamoona Humayun | Sửa tên tác giả; kiểm lại DOI trên trang ACM |
| [2] | Luận văn thạc sĩ tồn tại trong kho của Đại học Lund | Không |
| [3] | Đúng: Hu, Wang, Rubin, Pradel, FSE 2025 | Không |
| [4] | Đúng: Kharkar và cộng sự, ICSE 2022; con số 17,5% lấy từ tóm tắt | Không |
| [5] | Chưa mở được toàn văn; chỉ dẫn ở mức nhan đề | Nên đọc lại trước khi nộp |
| [6] | Bài báo tồn tại (ICSE 2022). **Đề cương ghi sai tác giả**: tác giả là Akshay Utture, Shuyang Liu, Christian Gram Kalhauge, Jens Palsberg | Sửa tên tác giả |
| [7] | Đúng; ngưỡng 10% và 25% đọc trực tiếp trong bài | Không |
| [8] | Bài báo tồn tại (arXiv:2205.10504). **Đề cương ghi sai tác giả**: tác giả là Rahul Yedida, Hong Jin Kang, Huy Tu, Xueqi Yang, David Lo, Tim Menzies | Sửa tên tác giả |
| [9] | **Không tìm thấy bài báo có nhan đề này.** Mã arXiv:2407.16235 trong đề cương là một bài khác: Zhou và cộng sự, "Comparison of Static Application Security Testing Tools and Large Language Models for Repo-level Vulnerability Detection". Chương này không dẫn [9] | Bỏ [9], hoặc thay bằng bài của Zhou và cộng sự (liên quan trực tiếp tới so sánh công cụ SAST) |
| [10]–[14] | Tài liệu kỹ thuật; dùng cho các phát biểu về SARIF và khả năng xuất SARIF | Không |

Tài liệu đề nghị bổ sung, đã được chương này dẫn hoặc cần cho mục 1.3 và 1.4:

- [15] H. G. Rice (1953), "Classes of Recursively Enumerable Sets and Their Decision Problems",
  *Transactions of the American Mathematical Society* 74(2), 358–366.
- [16] Tài liệu chính thức của Semgrep về chế độ vết bẩn và viết luật.
- [17] Tài liệu chính thức của ESLint và kho mã của eslint-plugin-security (luật
  `detect-child-process`).
- [18] Tài liệu chính thức của CodeQL về cơ sở dữ liệu, truy vấn đường đi và phân tích luồng dữ
  liệu.
- [19] Điều khoản sử dụng của CodeQL CLI (GitHub CodeQL Terms and Conditions), cho phát biểu về
  giấy phép ở mục 1.4.

Các phát biểu về Semgrep, Bandit, ESLint và CodeQL ở mục 1.3 và 1.4 mô tả đúng hành vi của các
phiên bản đã ghim mà nguyên mẫu đang chạy; chúng được kiểm bằng lượt quét thật, chưa được đối
chiếu từng câu với tài liệu [16]–[19].
