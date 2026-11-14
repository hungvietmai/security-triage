# CHƯƠNG 2: THIẾT KẾ VÀ XÂY DỰNG QUY TRÌNH PHÂN TÍCH NHIỀU BƯỚC VÀ CHUẨN HÓA KẾT QUẢ

> **Ghi chú cho người viết (không thuộc nội dung đề án).** Văn bản ngày 2026-11-14, theo đúng
> đề mục của đề cương. Căn cứ mã nguồn và số liệu của từng mục nằm ở
> [chapter-2-notes.md](chapter-2-notes.md); số liệu đánh giá nằm ở Chương 3. Mục 2.2 và 2.4.1
> giải trình điểm điều chỉnh so với đề cương; điểm này cần người hướng dẫn chấp thuận.

Chương này mô tả bài toán, các mục tiêu thiết kế, quy trình bốn bước mà đề án xây dựng và nguyên
mẫu cài đặt quy trình đó. Quy trình gồm: phát hiện rộng, chuẩn hóa và gộp cảnh báo trùng, thẩm
định và gạn cảnh báo sai, báo cáo trước–sau.

## 2.1. Mô tả bài toán và mục tiêu thiết kế

### 2.1.1. Bài toán giảm cảnh báo sai trong phân tích mã nguồn

**Đầu vào** là một phiên bản cố định của mã nguồn (một package npm theo đúng phiên bản, hoặc một
commit của kho GitHub) viết bằng Python hoặc JavaScript/TypeScript.

**Đầu ra** là danh sách các vị trí nghi có lỗ hổng thuộc nhóm lỗi mục tiêu, được sắp theo thứ tự
rà soát, kèm bằng chứng cho từng vị trí.

**Khó khăn** nằm ở ba điểm đã phân tích trong Chương 1:

1. Mỗi công cụ bỏ sót một phần lỗi thật, nên chỉ dùng một công cụ là chấp nhận trước phần bỏ sót
   của công cụ đó.
2. Dùng nhiều công cụ thì số cảnh báo tăng, cùng một lời gọi bị báo nhiều lần ở các vị trí hơi
   khác nhau, và phần lớn cảnh báo thêm vào đến từ luật khớp mẫu có tỷ lệ sai cao.
3. Loại bớt cảnh báo luôn có nguy cơ loại nhầm lỗi thật; nguy cơ này phải được kiểm soát bằng
   thiết kế và đo được bằng số liệu.

**Nhóm lỗi.** Kịch bản chính là chèn lệnh hệ điều hành (CWE-78) trên cả hai ngôn ngữ. Duyệt
đường dẫn (CWE-22) trên Python là minh họa bổ sung cho bước thẩm định.

### 2.1.2. Mục tiêu của quy trình đề xuất

Quy trình có hai mục tiêu, xếp theo thứ tự ưu tiên:

1. **Phát hiện được nhiều lỗi thật nhất** trong phạm vi đánh giá.
2. **Giảm số cảnh báo sai người rà phải đọc, đồng thời đo được số cảnh báo đúng bị mất** do bước
   gạn.

Thứ tự này có chủ ý: một lỗi thật bị loại khỏi danh sách gây hại nhiều hơn một cảnh báo sai còn
sót lại. Từ hai mục tiêu và năm nguyên tắc ở mục 1.2.2, đề án đặt ba ràng buộc thiết kế:

- **R1 — Không xóa.** Không bước nào xóa cảnh báo. Cảnh báo bị gạn chuyển sang một danh sách
  riêng, xem lại được cùng cảnh báo gốc, quy tắc đã áp dụng và bằng chứng.
- **R2 — Bảo thủ.** Chỉ gạn khi có bằng chứng cụ thể về chính vị trí đó. Thiếu bằng chứng, bằng
  chứng mâu thuẫn hoặc công cụ chạy dở thì giữ lại.
- **R3 — Tái lập.** Mọi công cụ, luật, truy vấn và cấu hình được cố định phiên bản và mã băm;
  mỗi lượt quét lưu lại đầu ra thô của công cụ.

## 2.2. Thiết kế tổng thể quy trình phân tích nhiều bước

**Quy trình.**

```
Mã nguồn (một phiên bản cố định, có SHA-256)
   │
   ▼
[1] Phát hiện rộng       Semgrep, Bandit (Python), ESLint + eslint-plugin-security (JS/TS), CodeQL
   │                     → cảnh báo thô, mỗi công cụ một tệp SARIF
   ▼
[2] Chuẩn hóa và gộp     SARIF → cảnh báo chuẩn hóa → đơn vị (lời gọi + vai trò đối số)
   │                     → ứng viên rà soát (mỗi lời gọi một mục)
   ▼
[3] Thẩm định và gạn     xếp ưu tiên P1–P4/U; bằng chứng của Semgrep, CodeQL và Bandit
   │                     → danh sách rà chính / danh sách đã gạn
   ▼
[4] Báo cáo trước–sau    số liệu từng bước, đóng góp từng công cụ, thời gian, SARIF hợp nhất
```

**Điều chỉnh so với đề cương.** Đề cương mô tả luồng nối tiếp: Semgrep và công cụ bổ trợ quét
nhanh để tạo danh sách cảnh báo ban đầu, sau đó CodeQL thẩm định "tại các vị trí đã được cảnh
báo". Thí điểm trên 20 vị trí chèn lệnh của OWASP BenchmarkPython (13 lỗi thật, 7 an toàn) cho
thấy luồng này có một giới hạn không khắc phục được ở bước sau:

| Nhóm vị trí | Lỗi thật | An toàn |
|---|---:|---:|
| Chỉ Semgrep báo | 0 | 5 |
| Chỉ CodeQL báo | 4 | 0 |
| Cả hai báo | 7 | 2 |
| Không công cụ nào trong hai công cụ báo | 2 | — |

Bốn lỗi thật chỉ CodeQL báo sẽ không bao giờ tới bước thẩm định nếu CodeQL chỉ xem những vị trí
Semgrep đã báo. Luồng nối tiếp vì thế chỉ đạt tối đa 7 trên 13 lỗi thật, kể cả khi bước thẩm
định hoàn hảo, thấp hơn CodeQL chạy riêng (11 trên 13). Điều này trái với mục tiêu thứ nhất.

Đề án vì vậy điều chỉnh một điểm: **tập ứng viên là hợp kết quả của mọi công cụ trên cùng phiên
bản mã**, thay vì chỉ là kết quả quét nhanh. Các thành phần khác của đề cương được giữ nguyên:

| Thành phần của đề cương | Trong quy trình đã xây dựng |
|---|---|
| Semgrep quét nhanh | Giữ nguyên; là một nguồn ứng viên |
| Công cụ bổ trợ theo ngôn ngữ (Bandit, eslint-plugin-security) | Giữ nguyên; là nguồn ứng viên |
| CodeQL thẩm định sâu có trọng tâm | Giữ: truy vấn bằng chứng chỉ xét các cảnh báo đã có. Thêm: kết quả truy vấn mặc định của CodeQL cũng là nguồn ứng viên |
| Chuẩn hóa theo SARIF, báo cáo trước và sau thẩm định | Giữ nguyên |

Tên đề tài vẫn mô tả đúng quy trình: kết hợp Semgrep và CodeQL để sàng lọc và thẩm định cảnh báo.
Phần thay đổi là thứ tự phối hợp. Việc bổ sung nguồn ứng viên được quyết định bằng số đo: đóng
góp riêng của từng công cụ được báo cáo ở mỗi lượt quét (mục 2.5) và ở Chương 3.

**Nguyên mẫu.** Quy trình được cài đặt thành một ứng dụng web chạy bằng Docker Compose:

| Thành phần | Vai trò |
|---|---|
| Giao diện (React, TypeScript) | Tạo dự án và lượt quét; danh sách rà chính, danh sách đã gạn; chi tiết bằng chứng; báo cáo trước–sau |
| API (FastAPI) | Nhận yêu cầu, ghi trạng thái, trả kết quả và báo cáo |
| Worker (Celery) | Tải mã nguồn, chạy bốn công cụ theo phiên bản đã ghim, gộp, thẩm định |
| PostgreSQL | Cảnh báo chuẩn hóa, đơn vị, ứng viên, kết quả thẩm định, nguồn gốc |
| Kho đối tượng (S3) | Tệp nén mã nguồn, SARIF thô, nhật ký |

Một lượt quét đi qua các bước: tải và kiểm tra mã băm của mã nguồn; kiểm tra phiên bản công cụ;
chạy các công cụ phát hiện; chuẩn hóa và gộp; chạy các bước bằng chứng; thẩm định; lưu kết quả.
Mã được quét **không bao giờ được thực thi** và phụ thuộc của nó không được cài đặt.

**Hồ sơ quét (scan profile).** Mỗi nhóm lỗi có một hồ sơ liệt kê công cụ, luật, truy vấn, tệp
cấu hình và mã băm SHA-256 của từng tệp. Worker từ chối chạy khi phiên bản công cụ hoặc mã băm
không khớp. Đề án dùng hai hồ sơ: `command-injection-v0.2` cho CWE-78 và `path-traversal-v0.2`
cho CWE-22.

## 2.3. Thiết kế bước sinh cảnh báo ban đầu

### 2.3.1. Sàng lọc nhanh bằng Semgrep

Semgrep 1.178.0 chạy bốn luật cộng đồng cho mỗi ngôn ngữ, gồm cả luật khớp mẫu (ví dụ lời gọi
`subprocess` có `shell=True`) lẫn luật vết bẩn trong một hàm. Luật được sao chép vào kho của đề
án và ghim mã băm, không tải từ mạng lúc quét. Đầu ra là một tệp SARIF.

Ngữ nghĩa của từng luật được khai báo riêng: luật thuộc loại khẳng định luồng dữ liệu hay loại rà
soát theo hình thức, loại nguồn dữ liệu mà luật mô hình hóa. Bước thẩm định dùng khai báo này để
phân biệt "công cụ khẳng định có luồng dữ liệu tới lệnh" với "công cụ chỉ thấy một lời gọi có
hình thức nguy hiểm".

### 2.3.2. Sinh thêm cảnh báo bằng công cụ bổ trợ theo ngôn ngữ

| Công cụ | Phiên bản | Ngôn ngữ | Luật được bật |
|---|---|---|---|
| Bandit | 1.9.4 | Python | `B602`–`B607`, `B609`: các kiểm tra chèn lệnh tại vị trí lời gọi |
| ESLint + eslint-plugin-security | 10.15.0 + 4.2.1 | JavaScript/TypeScript | `security/detect-child-process` |

Kiểm tra `B404` của Bandit (dòng `import subprocess`) bị loại vì nó không chỉ vào một lời gọi
thực thi lệnh nên không gộp được với cảnh báo của công cụ khác.

**An toàn khi quét mã không tin cậy.** Cả hai công cụ mặc định đọc cấu hình và chú thích nằm
trong chính mã được quét, tức là mã được quét có thể tự tắt luật. Đề án đã kiểm chứng điều này
với tệp `.bandit`. Cách xử lý:

- Bandit chạy với tệp cấu hình đã ghim (`--ini`) và bỏ qua chú thích `# nosec`
  (`--ignore-nosec`);
- ESLint chạy với tệp cấu hình và bộ định dạng theo đường dẫn tuyệt đối bên ngoài mã được quét,
  và tắt chú thích `eslint-disable`;
- tệp mà ESLint không phân tích cú pháp được khiến bước ESLint ở trạng thái "chạy dở", không
  phải "không có cảnh báo"; tương tự, tệp Python mà bộ định vị lời gọi không phân tích được
  khiến lượt quét của ngôn ngữ đó ở trạng thái "chạy dở".

### 2.3.3. Tổng hợp và sàng lọc tập nghi vấn ban đầu

Bước này biến các tệp SARIF rời rạc thành một danh sách mà người rà đọc được, qua bốn việc.

**(1) Chuẩn hóa.** Mỗi kết quả SARIF trở thành một cảnh báo chuẩn hóa gồm công cụ, luật, tệp,
vùng mã, thông điệp, đường đi của dữ liệu nếu có, và nguyên bản kết quả gốc. Tệp SARIF sai định
dạng làm lượt quét thất bại; nó không được hiểu là "không có cảnh báo".

**(2) Gộp thành đơn vị.** Các công cụ chỉ vào những vị trí khác nhau cho cùng một vấn đề: CodeQL
chỉ vào đối số lệnh, Bandit và ESLint chỉ vào cả lời gọi, luật vết bẩn của Semgrep chỉ vào biểu
thức đích. Để gộp, một bộ định vị dùng AST tìm mọi lời gọi thực thi lệnh trong mã (các hàm của
`subprocess`, `os.system`, `child_process`...). Mỗi cảnh báo được ghép vào một lời gọi theo một
trong ba căn cứ, và căn cứ được lưu lại:

| Căn cứ | Ý nghĩa |
|---|---|
| Liên kết tường minh | Công cụ chỉ thẳng tới vị trí lệnh của lời gọi |
| Chứa trong | Vùng mã của cảnh báo nằm trong vùng mã của lời gọi |
| Trùng vùng | Vùng mã của cảnh báo trùng đúng vùng mã của lời gọi |

Khóa của một **đơn vị** gồm phiên bản mã, tệp, vùng mã của lời gọi và vai trò của đối số (lệnh
shell, tên chương trình, danh sách tham số).

**(3) Gộp thành ứng viên rà soát.** Các đơn vị thuộc cùng một lời gọi tạo thành một **ứng viên**,
vì người rà xem một lời gọi một lần. Ứng viên là đơn vị đếm của mọi bảng số liệu trong đề án.

**(4) Giữ riêng ca chưa chắc chắn.** Cảnh báo không ghép được vào lời gọi nào, cảnh báo có vai
trò đối số chưa xác định, và cảnh báo trên dòng có ký tự ngoài ASCII (không so được cột một cách
tin cậy) không bị ép ghép. Chúng thành ứng viên riêng và được đánh dấu.

**Xếp ưu tiên.** Mỗi đơn vị được xếp vào một mức rà soát theo một danh sách quyết định có thứ tự;
quy tắc đầu tiên khớp sẽ quyết định:

| Mức | Tình huống điển hình |
|---|---|
| P1 | Có đường đi hợp lệ của dữ liệu tới đối số lệnh do CodeQL báo, thường cùng ít nhất một công cụ quét nhanh |
| P2 | CodeQL báo nhưng chưa có đường đi hợp lệ tới đối số lệnh, hoặc ngữ nghĩa shell của lời gọi chưa rõ |
| U | Cảnh báo không gộp được vào lời gọi nào: cần người xem |
| P3 | Chỉ công cụ khớp mẫu báo |
| P4 | Toàn bộ lệnh là chuỗi hằng |

Mức ưu tiên là **thứ tự rà soát**, không phải nhãn đúng/sai, và không mức nào ẩn cảnh báo. Trong
đề án, "hạ ưu tiên" nghĩa là xếp ở P3 hoặc P4 nhưng vẫn nằm trong danh sách rà chính; "gạn" nghĩa
là chuyển sang danh sách riêng (mục 2.4). Hai khái niệm được đếm tách biệt trong mọi báo cáo.

## 2.4. Thiết kế bước thẩm định sâu bằng CodeQL

### 2.4.1. Nguyên tắc thẩm định có trọng tâm

"Có trọng tâm" trong đề án có nghĩa: bước thẩm định chỉ xét các ứng viên đã có, và với mỗi ứng
viên chỉ tìm bằng chứng cho một câu hỏi: *luồng dữ liệu mà công cụ khẳng định có thật sự tới được
lệnh không*. Nó không tìm thêm lỗi mới.

**Cách tạo bằng chứng bằng CodeQL.** Với mỗi truy vấn mặc định, đề án viết một cặp truy vấn:

- *truy vấn đối chứng*: phát biểu lại truy vấn mặc định trong gói truy vấn của đề án;
- *truy vấn có bằng chứng*: truy vấn đối chứng cộng thêm các rào chắn mô tả tình huống an toàn.

Cả hai chạy trên chính cơ sở dữ liệu mà bước phát hiện đã tạo, nên không phải trích xuất lại. Một
cảnh báo mà truy vấn đối chứng báo đúng vị trí nhưng truy vấn có bằng chứng không còn báo là cảnh
báo **có bằng chứng bác bỏ**. Truy vấn đối chứng là điều kiện bắt buộc: nếu nó không báo đúng vị
trí của cảnh báo gốc thì không đối chiếu được, và cảnh báo được giữ.

**Lớp bằng chứng bằng công cụ mã nguồn mở.** Bộ máy CodeQL CLI không phải mã nguồn mở. Để bước
gạn không phụ thuộc hoàn toàn vào nó, đề án thêm một lớp bằng chứng độc lập dùng Semgrep CE. Bốn
phương án đã được thử trên dữ liệu phát triển trước khi chọn; kết quả thử nằm ở Chương 3. Gói
luật được chọn gồm ba luật:

| Luật | Báo gì |
|---|---|
| Đối chứng | Đối số lệnh nhận dữ liệu từ yêu cầu web, tham số hàm, tham số dòng lệnh, biến môi trường hoặc `input()` |
| Bằng chứng | Như trên, trừ các luồng đi qua một phép gán nằm trong nhánh không bao giờ chạy |
| Phép gán chết | Vế phải của từng phép gán như vậy |

Một nhánh "không bao giờ chạy" khi điều kiện của nó là một phép so sánh số nguyên mà Semgrep rút
gọn được thành hằng. Ví dụ:

```python
def handler(request):
    param = request.args["x"]
    if 7 * 42 - 86 > 200:      # luôn đúng
        cmd = "echo safe"
    else:
        cmd = param            # phép gán chết: không bao giờ chạy
    subprocess.run(cmd, shell=True)
```

Công cụ phân tích luồng dữ liệu không đánh giá điều kiện sẽ báo `param` chảy tới `cmd`. Luật
bằng chứng chỉ ra rằng luồng đó chỉ đi qua phép gán chết.

### 2.4.2. Tổ chức thẩm định theo nhóm lỗi ưu tiên

| Nhóm lỗi | Ngôn ngữ | Nguồn bằng chứng | Tình huống an toàn được mô tả |
|---|---|---|---|
| CWE-78 | Python | Semgrep CE (gói luật nhánh chết) | Nhánh có điều kiện số nguyên hằng không bao giờ chạy |
| CWE-78 | Python | CodeQL (gói bằng chứng v0.2) | Nhánh điều kiện hằng; đọc phần tử hằng của tập hợp; đoạn đường dẫn bị định tuyến cố định |
| CWE-78 | Python | Bandit cùng chứng minh của hệ thống | Toàn bộ lệnh là chuỗi hằng |
| CWE-22 | Python | CodeQL (gói bằng chứng v0.2) | Các kiểm tra đường dẫn làm luồng không còn khai thác được |
| CWE-78 | JavaScript/TypeScript | Chưa có | Bước thẩm định chỉ xếp ưu tiên, không gạn |

Mỗi gói bằng chứng là một phiên bản cố định, có mã băm trong hồ sơ quét. Thay đổi một rào chắn
đòi hỏi một phiên bản gói và một hồ sơ mới. Việc chưa có gói bằng chứng cho JavaScript/TypeScript
là giới hạn của đề án, được nêu lại ở mục 2.6 và Chương 3.

### 2.4.3. Tiêu chí quyết định sau thẩm định

Với mỗi ứng viên, bước thẩm định kiểm tra mọi quy tắc gạn. Ứng viên được chuyển sang danh sách
"Đã gạn" khi **ít nhất một** quy tắc thỏa đủ mọi điều kiện của nó; báo cáo ghi lại tất cả các quy
tắc đã thỏa.

| Quy tắc | Nguồn bằng chứng | Điều kiện (phải đủ tất cả) |
|---|---|---|
| G3 — nhánh không bao giờ chạy | Semgrep CE (mã nguồn mở) | (a) Luật đối chứng báo lệnh của ứng viên, luật bằng chứng không báo. (b) Mọi luồng do công cụ khác báo tại lời gọi đều kèm đường đi, và mỗi đường đi có một bước nằm trên dòng của một phép gán chết. (c) Truy vấn bằng chứng của CodeQL, nếu có, không còn báo luồng đó |
| G1 — bằng chứng an toàn của CodeQL | CodeQL | (a) Ứng viên có luồng do truy vấn mặc định báo. (b) Truy vấn đối chứng báo đúng vị trí đó. (c) Truy vấn có bằng chứng không còn báo. (d) Không công cụ nào khác khẳng định luồng dữ liệu tại lời gọi |
| G2 — lệnh là hằng | Bandit cùng chứng minh của hệ thống | (a) Hệ thống chứng minh toàn bộ lệnh là chuỗi hằng. (b) Bandit xếp lời gọi ở mức dành cho lệnh hằng. (c) Không công cụ nào khẳng định luồng dữ liệu |

Điều kiện (b) của G3 nối phép phân tích trong một hàm của Semgrep với khẳng định liên hàm của công
cụ khác: G3 chỉ gạn khi chính đường đi mà công cụ kia đưa ra cũng đi qua nhánh chết.

**Các trường hợp luôn giữ lại.** Mỗi ứng viên được giữ mang một mã lý do hiển thị cho người rà:

| Tình huống | Hệ quả |
|---|---|
| Một công cụ chạy dở hoặc thất bại | Không gạn ứng viên nào của lượt quét |
| Bước bằng chứng không hoàn tất | Giữ |
| Truy vấn có bằng chứng vẫn báo luồng | Giữ |
| Luồng do một truy vấn chưa có bản bằng chứng báo | Giữ |
| Truy vấn đối chứng không báo đúng vị trí | Giữ: không đối chiếu được |
| Công cụ khác vẫn khẳng định luồng (mâu thuẫn) | Giữ |
| Công cụ khác khẳng định luồng mà không kèm đường đi | Giữ: không kiểm tra được |
| Một đường đi được báo không qua nhánh chết | Giữ |
| Chỉ một nguồn nói lệnh là hằng | Giữ, chỉ hạ ưu tiên |
| Không có bằng chứng nào | Giữ |

Việc một công cụ **không báo** một vị trí không xuất hiện trong bảng điều kiện của quy tắc nào:
im lặng không được dùng làm bằng chứng. Hệ quả là các cảnh báo chỉ do luật khớp mẫu báo không bị
gạn dù nhiều khả năng là cảnh báo sai; chúng được xếp ở P3.

**Bản ghi thẩm định.** Mỗi ứng viên lưu: trạng thái (rà soát hay đã gạn), các quy tắc đã thỏa,
lý do giữ nếu được giữ, bằng chứng (vị trí lệnh, vị trí phép gán chết, mã truy vấn), phiên bản
bộ quy tắc, và một câu giải thích cho người rà. Cảnh báo gốc, đơn vị và mức ưu tiên của ứng viên
đã gạn không bị thay đổi.

**Giả định của các quy tắc**, cần được nêu khi dùng kết quả:

- Semgrep CE chỉ phân tích trong một hàm; biến cấp mô-đun được gán đúng một lần được coi là hằng;
  nguồn dữ liệu là một danh sách cố định.
- Đường đi do CodeQL xuất ra là một số đường đi mẫu, không phải mọi đường đi. Một đường đi không
  được xuất và không qua nhánh chết sẽ không được nhìn thấy.
- Các rào chắn của gói bằng chứng CWE-78 được phát triển trên bộ OWASP BenchmarkPython.

## 2.5. Chuẩn hóa kết quả và thiết kế báo cáo

**Đầu vào chuẩn hóa.** Mọi công cụ xuất SARIF 2.1.0; hệ thống chỉ đọc định dạng này. Thêm một
công cụ mới vào quy trình chỉ cần công cụ đó xuất được SARIF và có luật chỉ vào vị trí lời gọi.

**Báo cáo trước–sau** của một lượt quét gồm:

| Nhóm số liệu | Nội dung |
|---|---|
| Các bước của quy trình | Số cảnh báo thô, số đơn vị, số ứng viên, số ứng viên trong danh sách rà chính, số đã gạn, số chỉ hạ ưu tiên |
| Đóng góp của từng công cụ | Số ứng viên công cụ có báo; số ứng viên **chỉ** công cụ đó báo |
| Kết quả gạn | Số ứng viên theo từng quy tắc; danh sách ứng viên kèm quy tắc và lý do |
| Thời gian | Trạng thái và thời gian của từng bước, từng công cụ |
| Nguồn gốc | Mã băm của mã nguồn, hồ sơ quét, phiên bản công cụ, phiên bản bộ gộp và bộ quy tắc |

Cột "chỉ công cụ đó báo" là căn cứ để quyết định có giữ một nguồn phát hiện hay không.

**SARIF hợp nhất.** Hệ thống xuất một tệp SARIF 2.1.0 chứa mọi cảnh báo gốc của mọi công cụ. Mỗi
cảnh báo mang thêm khóa ứng viên, mức ưu tiên và kết quả thẩm định. Cảnh báo đã gạn mang trường
`suppressions` kèm lý do, đúng cách SARIF biểu diễn cảnh báo bị ẩn có chủ ý [10]. Một trình xem
SARIF bất kỳ vì thế hiển thị danh sách sau thẩm định, trong khi dữ liệu trước thẩm định vẫn nằm
đủ trong cùng tệp.

**Giao diện.** Trang lượt quét có hai danh sách: "Rà soát" (danh sách chính, sắp theo P1 → P4) và
"Đã gạn". Mở một ứng viên sẽ thấy cảnh báo gốc của từng công cụ, căn cứ gộp, đường đi của dữ
liệu, và khối "Thẩm định" nêu quy tắc và bằng chứng. Ứng viên đã gạn mở lại được với đầy đủ
thông tin như ứng viên trong danh sách chính.

**Lưu trữ để tái lập.** Mỗi lượt quét lưu tệp nén mã nguồn cùng SHA-256, SARIF thô của từng
công cụ, nhật ký, cấu hình và mã băm của hồ sơ quét. Mọi bảng ở Chương 3 được tính từ báo cáo và
tệp SARIF do ứng dụng xuất, bằng các script chạy được mà không cần công cụ quét.

## 2.6. Kết chương

Chương này đã trình bày quy trình bốn bước và nguyên mẫu cài đặt nó. Ba điểm chính:

1. **Tập ứng viên là hợp kết quả của mọi công cụ.** Đây là điều chỉnh so với luồng nối tiếp của
   đề cương, xuất phát từ số đo thí điểm: luồng nối tiếp làm mất các lỗi thật mà công cụ quét
   nhanh bỏ sót. CodeQL giữ vai trò thẩm định và có thêm vai trò nguồn phát hiện.
2. **Gộp theo lời gọi** biến cảnh báo của bốn công cụ thành một danh sách ứng viên, giữ nguyên
   nguồn gốc và giữ riêng các ca chưa chắc chắn.
3. **Gạn theo bằng chứng, có hai lớp**: luật của Semgrep CE (mã nguồn mở) và truy vấn bằng chứng
   của CodeQL, cùng tín hiệu lệnh hằng của Bandit. Mọi trường hợp thiếu bằng chứng, mâu thuẫn
   hoặc chạy dở đều giữ lại; không cảnh báo nào bị xóa.

Giới hạn của thiết kế:

- Bước gạn chỉ có gói bằng chứng cho Python. Với JavaScript/TypeScript, quy trình gộp và xếp ưu
  tiên nhưng không gạn.
- Cảnh báo chỉ do luật khớp mẫu báo không có bằng chứng bác bỏ nên không bị gạn; lượng cảnh báo
  này có thể lớn trên mã thực tế.
- Luật `detect-child-process` của eslint-plugin-security chỉ bao phủ `exec()`.
- Nguyên mẫu là ứng dụng một người dùng chạy cục bộ; chưa có lệnh dòng lệnh hay cấu hình mẫu để
  gắn vào hệ thống tích hợp liên tục.

Chương 3 đánh giá quy trình: từng công cụ riêng, tập hợp đã gộp, và danh sách sau khi gạn, trên
cùng phiên bản mã và cùng đơn vị đếm.
