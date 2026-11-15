# CHƯƠNG 3: THỬ NGHIỆM VÀ ĐÁNH GIÁ KẾT QUẢ

> **Ghi chú cho người viết (không thuộc nội dung đề án).** Văn bản ngày 2026-11-14, theo đúng
> đề mục của đề cương. Mọi con số tái lập được từ tệp đã lưu trong repo: dữ liệu phát triển ở
> [chapter-3-results.md](chapter-3-results.md) và `experiments/evaluation/results/`; năm đợt kiểm
> tra độc lập ở `experiments/evaluation/independent*/`. Lệnh dựng lại bảng:
> [experiments/evaluation/README.md](../../experiments/evaluation/README.md).

Chương này đánh giá quy trình đã thiết kế ở Chương 2 theo hai câu hỏi tương ứng với hai mục tiêu
của nó:

- **Q1 — Phát hiện.** Lấy hợp các nguồn có báo được nhiều lỗi thật hơn từng công cụ chạy riêng
  không?
- **Q2 — Thẩm định.** Bước gạn loại được bao nhiêu cảnh báo sai, và làm mất bao nhiêu lỗi thật?

## 3.1. Bộ dữ liệu và thiết lập thực nghiệm

### 3.1.1. Bộ dữ liệu đánh giá

Đề án phân biệt hai loại dữ liệu. **Dữ liệu phát triển** là dữ liệu đã được quét và xem trong
lúc xây dựng quy trình; kết quả trên đó cho biết quy trình làm được gì trên những ca nó đã thấy.
**Dữ liệu độc lập** là mã mà dự án chưa từng quét hay đọc; với loại này, câu hỏi, nhãn, cách
chấm và mã băm của cấu hình được ghi lại trước khi quét, và mỗi nguồn chỉ quét một lần.

| Bộ dữ liệu | Loại | Nội dung | Nhãn |
|---|---|---|---|
| D1. OWASP BenchmarkPython, nhóm chèn lệnh | Phát triển | 20 vị trí trong mã Python tổng hợp | 13 có lỗi, 7 an toàn; nhãn của tác giả bộ dữ liệu |
| D2. Mười hai package npm | Phát triển | Mã JavaScript/TypeScript thực tế | Không đủ nhãn; chỉ đếm |
| D3. Dữ liệu CWE-22 | Phát triển và kiểm tra của giai đoạn nghiên cứu | OWASP BenchmarkPython (4 nhóm lỗi) và các kho Python thực tế | Nhãn của bộ dữ liệu; nhãn mã thật do chủ đề án xác minh |
| I1. Ba ứng dụng luyện tập | Độc lập | 2 ứng dụng JavaScript, 1 ứng dụng Python | 3 vị trí lỗi do tác giả ứng dụng công bố |
| I2. Package npm có CVE chèn lệnh | Độc lập | 52 package của bộ SecBench.js | 52 vị trí lỗi do bộ dữ liệu công bố |
| I3. Ba ứng dụng luyện tập Python | Độc lập | 3 ứng dụng Flask | 6 vị trí lỗi đã công bố |
| I4. Bộ kiểm thử luật của kho semgrep-rules | Độc lập | 210 dòng mã minh họa (185 Python, 25 JavaScript/TypeScript) | 135 có lỗi, 75 an toàn; nhãn của tác giả luật |
| I5. Hai mươi công cụ dòng lệnh Python | Độc lập | Mã ứng dụng thật trên GitHub, chọn bằng một truy vấn tìm kiếm cố định | Không có nhãn; chỉ kiểm các ứng viên bị gạn |
| P1. Tập phát triển của `pairs-v1` | Phát triển (quét lần đầu) | 34 cặp phiên bản lỗi/vá của CVE thật; chỉ quét bản có lỗi | 26 vị trí lỗi đã biết, xác định trước khi quét |
| J1. 84 package npm đã quét ở các đợt trước | Phát triển | Quét lại bằng phiên bản 0.3 để so đối sánh | 69 vị trí lỗi đã biết; không có nhãn an toàn |

**Cách chọn I2.** SecBench.js là bộ dữ liệu lỗ hổng thật của package npm; mỗi mục có mã CVE hoặc
mã khuyến cáo và vị trí lời gọi nguy hiểm. Đợt I2 lấy **toàn bộ** các mục chèn lệnh mà dự án
chưa từng đưa vào danh mục dữ liệu của mình (53 mục), loại 1 mục có siêu dữ liệu mâu thuẫn bằng
một quy tắc cơ học, còn 52 nguồn. Không mục nào được chọn hay bỏ bằng tay, và mã nguồn của chúng
không được tải hay đọc trước khi quét.

**Cách chọn I4.** Kho luật cộng đồng của Semgrep giữ cạnh mỗi luật một tệp kiểm thử, trong đó
tác giả luật đánh dấu dòng nào phải bị báo và dòng nào không được báo. Đợt I4 lấy **toàn bộ**
các luật theo dõi dữ liệu không tin cậy tới lệnh hệ điều hành (chế độ vết bẩn, gắn CWE-78) của
Python và JavaScript/TypeScript, tổng cộng 25 luật, và dùng các đánh dấu đó làm nhãn "có lỗi"
và "an toàn". Nhãn được dựng bằng script; nội dung các tệp không được đọc trước khi quét. Dự
án từng chép tệp luật từ kho này nhưng chưa từng chép hay quét tệp kiểm thử.

**Giới hạn của dữ liệu.**

- D1 là mã tổng hợp sinh từ một bộ mẫu; 20 vị trí không phải 20 dự án độc lập. Các cơ chế bằng
  chứng của bước gạn được phát triển khi đã biết các ca an toàn của D1.
- I1, I2 và I3 **chỉ có nhãn dương tính**. Chúng cho biết độ bao phủ và số lỗi thật bị gạn nhầm,
  nhưng không cho biết độ chính xác.
- I4 có cả hai loại nhãn, nhưng là mã minh họa ngắn của luật Semgrep. Trên 64 vị trí thuộc
  kiểm thử của chính các luật mà quy trình đang chạy, Semgrep được chấm bằng kỳ vọng của chính
  nó; kết luận về Semgrep vì vậy chỉ dựa trên 146 vị trí còn lại.
- I1 và I3 là ứng dụng cố ý có lỗ hổng, lỗi được viết ở dạng dễ thấy. Package trong I2 phần lớn
  nhỏ.
- `pairs-v1` là tập 50 cặp phiên bản lỗi/vá của CVE thật đã khóa nguồn. **Tập phát triển** (34
  cặp) đã được quét một lần bằng phiên bản 0.2 sau khi chủ đề án thông qua một bản sửa đổi giao
  thức; mọi cặp được quét đúng các byte đã khóa. **Tập giữ lại** (16 cặp) **chưa được quét**:
  nó chỉ dùng được một lần và được để dành cho phiên bản cuối của quy trình.
- J1 gồm các nguồn đã quét trước đó, trong đó 10 nguồn đã được đọc mã để tìm lỗi cần sửa. Kết
  quả trên J1 là kết quả phát triển, không phải kiểm tra độc lập.

### 3.1.2. Môi trường và cấu hình chạy

| Mục | Giá trị |
|---|---|
| Hồ sơ quét | `command-injection-v0.2` (CWE-78), `path-traversal-v0.2` (CWE-22); cố định bằng SHA-256 |
| Công cụ phát hiện | Semgrep CE 1.178.0; CodeQL 2.27.1; Bandit 1.9.4; ESLint 10.15.0 với eslint-plugin-security 4.2.1 |
| Bước thẩm định | Bộ quy tắc `adjudicate-v0.2`: G3 (Semgrep CE), G1 (CodeQL), G2 (Bandit) |
| Môi trường | Docker Compose trên máy cá nhân (Windows, Docker Desktop); CodeQL giới hạn 2 GB bộ nhớ |
| Đơn vị đếm | Ứng viên rà soát: một lời gọi thực thi lệnh |
| Quy tắc khớp nhãn | Một vị trí có nhãn được tính là "được báo" khi có ứng viên cùng tệp và bắt đầu đúng dòng đó |

Mọi lượt quét chạy qua nguyên mẫu, đúng như một người dùng thao tác. Các bảng được tính từ báo
cáo và tệp SARIF hợp nhất do nguyên mẫu xuất ra; mỗi tệp đã lưu có mã băm đi kèm và một bộ kiểm
thử dựng lại toàn bộ bảng kết quả từ các tệp đó.

Với ba đợt độc lập, các tệp sau được băm trước lượt quét đầu tiên: giao thức, tệp nhãn, script
chấm, hồ sơ quét, bộ quy tắc gạn, các gói bằng chứng và tệp phiên bản công cụ. Bộ quy tắc gạn và
các gói bằng chứng **không thay đổi** giữa ba đợt.

## 3.2. Thiết kế kịch bản thử nghiệm

### 3.2.1. Kịch bản thử nghiệm cho JavaScript và TypeScript

| Kịch bản | Dữ liệu | Câu hỏi | Kết quả đo |
|---|---|---|---|
| JS-1 | D2 | Gộp cảnh báo của ba công cụ cho ra bao nhiêu ứng viên; từng công cụ đóng góp gì | Số lượng theo từng bước; chưa có nhãn |
| JS-2 | I1 (2 ứng dụng) | Lỗi đã công bố có được báo không | Độ bao phủ trên 2 vị trí |
| JS-3 | I2 (52 package) | Q1 trên lỗ hổng thật; bước gạn có gây hại không | Độ bao phủ theo từng cấu hình; số lỗi thật bị gạn; mức ưu tiên |
| JS-4 | I4 (25 vị trí) | Q1 khi có cả nhãn an toàn | TP, FP, FN, TN, độ chính xác, độ bao phủ, F1 |
| JS-5 | P1 (24 cặp JavaScript) | Q1 trên CVE thật của tập phát triển | Độ bao phủ theo từng cấu hình trên vị trí lỗi đã biết |
| JS-6 | J1 | Bản sửa đối sánh (phiên bản 0.3) gộp thêm được bao nhiêu cảnh báo, có ghép nhầm không; điều kiện gạn hẹp cho JavaScript có hoạt động đúng không | Số ứng viên ở hàng U trước và sau; cảnh báo mới gộp; ghép nhầm; ứng viên bị gạn |

Bước gạn chưa có gói bằng chứng cho JavaScript/TypeScript. Các kịch bản JS vì thế trả lời Q1 và
kiểm tra rằng bước thẩm định không làm mất lỗi thật; chúng không đo được lợi ích của bước gạn.

### 3.2.2. Kịch bản thử nghiệm cho Python

| Kịch bản | Dữ liệu | Câu hỏi | Kết quả đo |
|---|---|---|---|
| PY-1 | D1 | Q1 và Q2 trên dữ liệu có đủ nhãn | TP, FP, FN, độ chính xác, độ bao phủ, F1 của từng cấu hình; số cảnh báo sai và lỗi thật bị gạn theo từng quy tắc |
| PY-2 | D1 | Chọn công cụ mã nguồn mở cho bước gạn | Số cảnh báo sai có bằng chứng, số lỗi thật bị gạn nhầm, chi phí của từng phương án |
| PY-3 | I1 (1 ứng dụng), I3 | Q1 và phần "mất" của Q2 trên mã chưa từng xem | Độ bao phủ; số lỗi thật bị gạn |
| PY-4 | D3 | Bước thẩm định bằng CodeQL trên nhóm lỗi thứ hai (CWE-22) | Số cảnh báo sai được loại và lỗi thật bị loại nhầm |
| PY-5 | I4 (185 vị trí) | Q1 và Q2 trên mã chưa từng xem có cả nhãn an toàn | TP, FP, FN, TN, độ chính xác, độ bao phủ, F1; số vị trí an toàn và có lỗi bị gạn |
| PY-6 | I5 (20 kho) | Bước gạn có hành động ở lượt quét hoàn tất không, và có gạn đúng không | Số ứng viên bị gạn theo quy tắc; phán quyết của một phép kiểm độc lập với ứng dụng cho từng ứng viên bị gạn |
| PY-7 | P1 (10 cặp Python) | Q1 và phần "mất" của Q2 trên CVE thật của tập phát triển | Độ bao phủ; vị trí lỗi bị gạn; kiểm các ứng viên bị gạn |

### 3.2.3. Kịch bản so sánh trước và sau thẩm định

Mọi kịch bản so các cấu hình sau **trên cùng phiên bản mã và cùng đơn vị đếm**:

| Cấu hình | Người rà nhìn thấy |
|---|---|
| Semgrep riêng | Các ứng viên Semgrep có báo |
| CodeQL riêng | Các ứng viên CodeQL có báo |
| Công cụ bổ trợ riêng | Các ứng viên Bandit hoặc ESLint có báo |
| Semgrep ∪ CodeQL | Hợp hai công cụ nêu trong tên đề tài, đã gộp cảnh báo trùng |
| Hợp mọi nguồn | Toàn bộ ứng viên trước khi gạn |
| Sau gạn, chỉ công cụ mã nguồn mở | Bỏ các ứng viên bị gạn bởi quy tắc dùng Semgrep hoặc Bandit |
| Sau gạn, mọi quy tắc | Danh sách rà chính |
| Nhóm rà trước | Các ứng viên P1 và P2 của danh sách rà chính |

Vì mọi cấu hình được suy ra từ cùng một lượt quét, khác biệt giữa chúng không do khác phiên bản
mã hay khác lần chạy. Tiêu chí gạn được cố định trong mã trước khi chấm. Một lỗi thật bị gạn
được tính là thất bại của bước gạn, bất kể lý do.

## 3.3. Các chỉ số đánh giá

### 3.3.1. Số cảnh báo ban đầu và số cảnh báo sau thẩm định

**Python, dữ liệu phát triển (PY-1).**

| Bước | Số lượng |
|---|---:|
| Cảnh báo thô của mọi công cụ | 51 |
| Đơn vị (gộp theo lời gọi và vai trò đối số) | 24 |
| Ứng viên rà soát | 20 |
| Danh sách rà chính sau khi gạn | 18 |
| Đã gạn | 2 |
| Chỉ hạ ưu tiên, vẫn trong danh sách chính | 7 |

Gộp theo lời gọi giảm 51 cảnh báo thô xuống 20 mục cần rà mà không mất cảnh báo gốc nào.

**JavaScript/TypeScript, dữ liệu phát triển (JS-1).** Mười hai package cho 100 cảnh báo thô, gộp
thành 66 ứng viên; không ứng viên nào bị gạn; 52 ứng viên chỉ bị hạ ưu tiên. Riêng package
`node-gyp` kèm mã Python và sinh 51 lời gọi do Bandit báo, trong đó 42 lời gọi không công cụ nào
khác báo; tất cả ở mức P3. Đây là ví dụ thực tế về lượng cảnh báo mà công cụ khớp mẫu tạo ra.

**Dữ liệu độc lập.**

| Đợt | Lượt quét hoàn tất | Ứng viên ngoài vị trí có nhãn | Trong đó ở P1 / P2 / U / P3 | Đã gạn |
|---|---:|---:|---|---:|
| I1 | 3/3 | 3 | 0 / 0 / 0 / 3 | 0 |
| I2 | 43/52 (3 chạy dở, 6 lỗi) | 47 | 20 / 8 / 14 / 5 | 0 |
| I3 | 3/3 | 2 | 0 / 0 / 0 / 2 | 0 |
| I4 | 0/1 (lượt đã đăng ký lỗi; lượt quét lại sau khi sửa lỗi: chạy dở) | 200 | không tách | 0 |
| I5 | 18/20 (1 chạy dở, 1 lỗi) | 184 (không có nhãn) | 0 / 2 / 18 / 145 trong danh sách chính | 19 |

Ở các đợt I1 đến I4, bước gạn không chuyển ứng viên nào sang danh sách "Đã gạn". Ở I5, nó
chuyển 19 trong 145 ứng viên của 18 lượt quét hoàn tất. 47 ứng viên chưa có nhãn của I2 và 165
ứng viên còn lại của I5 là khối lượng người rà còn phải xem; không biết bao nhiêu trong số đó
là lỗi thật.

### 3.3.2. Mức giảm cảnh báo sai theo đối chiếu

**(a) Q1 và Q2 trên dữ liệu phát triển có đủ nhãn (PY-1).** 20 vị trí: 13 có lỗi, 7 an toàn.

| Cấu hình | Ứng viên | TP | FP | FN | Độ chính xác | Độ bao phủ | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Semgrep riêng | 14 | 7 | 7 | 6 | 0,50 | 0,54 | 0,52 |
| CodeQL riêng | 13 | 11 | 2 | 2 | 0,85 | 0,85 | 0,85 |
| Bandit riêng | 20 | 13 | 7 | 0 | 0,65 | 1,00 | 0,79 |
| Semgrep ∪ CodeQL | 18 | 11 | 7 | 2 | 0,61 | 0,85 | 0,71 |
| Hợp mọi nguồn | 20 | 13 | 7 | 0 | 0,65 | 1,00 | 0,79 |
| Sau gạn, chỉ công cụ mã nguồn mở | 19 | 13 | 6 | 0 | 0,68 | 1,00 | 0,81 |
| **Sau gạn, mọi quy tắc** | 18 | 13 | 5 | 0 | 0,72 | 1,00 | 0,84 |
| Nhóm rà trước (P1+P2) | 11 | 11 | 0 | 2 | 1,00 | 0,85 | 0,92 |

Tác động của bước thẩm định lên 20 vị trí:

| Nhóm sau thẩm định | Lỗi thật | An toàn |
|---|---:|---:|
| Đã gạn | 0 | 2 |
| — thỏa G3 (Semgrep CE) | 0 | 1 |
| — thỏa G1 (CodeQL) | 0 | 2 |
| — thỏa G2 (Bandit, lệnh hằng) | 0 | 0 |
| Giữ, nhóm rà trước P1+P2 | 11 | 0 |
| Giữ, chỉ hạ ưu tiên xuống P3 | 2 | 5 |

Một ứng viên có thể thỏa nhiều quy tắc: một ca thỏa cả G3 lẫn G1, một ca chỉ thỏa G1.

**(b) Lựa chọn công cụ cho bước gạn (PY-2).** Trên cùng 7 vị trí an toàn và 13 lỗi thật:

| Phương án | Loại bằng chứng | Cảnh báo sai có bằng chứng | Lỗi thật bị gạn nhầm | Thời gian thêm |
|---|---|---:|---:|---:|
| **Semgrep CE, luật nhánh chết** (được chọn) | Luồng chỉ đi qua nhánh điều kiện hằng không bao giờ chạy | 1/7 | 0/13 | 3,6 giây |
| Truy vấn bằng chứng CodeQL | Rào chắn: nhánh hằng, phần tử hằng, định tuyến cố định | 2/7 | 0/13 | 10,4 giây |
| Bandit, phân loại lệnh hằng | Mức LOW khi lệnh là chuỗi hằng | 0/7 | 0/13 | 1,8 giây |
| Semgrep CE, luật thử "lệnh là hằng" | Lan truyền hằng trong hàm | 0/7 | 0/13 | 1,4 giây |
| ESLint với eslint-plugin-security | Không có bằng chứng dùng được | — | — | — |

Semgrep CE được chọn làm công cụ mã nguồn mở cho bước gạn vì nó là phương án mã nguồn mở duy
nhất bác bỏ được một cảnh báo sai mà không gạn nhầm lỗi thật, và đầu ra của nó (vị trí lệnh, vị
trí phép gán chết) đủ để đối chiếu với đường đi mà công cụ khác báo. Truy vấn bằng chứng của
CodeQL được giữ làm lớp thứ hai. Năm vị trí an toàn còn lại an toàn vì lý do về giá trị (đọc đúng
khóa hằng của từ điển, hàm phụ trả về hằng); không phương án nào đã thử chứng minh được, nên
chúng được giữ.

**(c) Q1 trên lỗ hổng thật chưa từng xem (JS-3).** 52 package, mỗi package một vị trí lỗi đã công
bố. 43 lượt quét hoàn tất; theo giao thức đã định trước, đây là mẫu số của bảng.

| Cấu hình | Vị trí lỗi được báo (trên 43) | Tỷ lệ |
|---|---:|---:|
| Semgrep riêng | 12 | 0,28 |
| CodeQL riêng | 27 | 0,63 |
| ESLint riêng | 27 | 0,63 |
| Semgrep ∪ CodeQL | 29 | 0,67 |
| **Hợp mọi nguồn** | **32** | **0,74** |
| Sau gạn | 32 | 0,74 |
| Nhóm rà trước (P1+P2) | 29 | 0,67 |

- Ba vị trí chỉ CodeQL báo và ba vị trí chỉ ESLint báo; không vị trí nào chỉ Semgrep báo.
- Không vị trí lỗi nào bị gạn. Trong 32 vị trí được báo: 14 ở P1, 15 ở P2, 3 ở P3.
- Tính trên cả 52 nguồn, kể cả lượt chạy dở và lượt lỗi: 35 vị trí được báo, 17 không.

Chín nguồn không cho lượt quét hoàn tất:

| Số nguồn | Trạng thái | Nguyên nhân |
|---:|---|---|
| 4 | Lỗi | Phiên bản package không còn trên npm |
| 2 | Lỗi | **Lỗi của nguyên mẫu**: tệp nguồn dùng xuống dòng kiểu Windows làm bộ định vị lời gọi JavaScript dừng cả lượt quét |
| 3 | Chạy dở | ESLint không phân tích được một tệp; cả ba vị trí lỗi vẫn được báo |

Lỗi của nguyên mẫu đã được sửa và có kiểm thử hồi quy. Hai nguồn đó được quét lại sau khi sửa:
một lượt hoàn tất và vị trí lỗi được báo (ESLint và Semgrep, P2); một lượt chạy dở và vị trí lỗi
không được báo. Hai kết quả này **nằm ngoài** bảng đã đăng ký và không được cộng vào.

Đọc lại 11 vị trí không được báo trong các lượt hoàn tất (việc đọc lại này làm sau khi biết kết
quả, đúng như giao thức đã ghi):

| Số vị trí | Tình trạng |
|---:|---|
| 5 | Không công cụ nào báo gì trong tệp đó |
| 4 | Có công cụ báo đúng dòng, nhưng cảnh báo không gộp được vào lời gọi nào và nằm ở hàng U |
| 1 | CodeQL báo ở dòng khác và nêu dòng lỗi là vị trí liên quan |
| 1 | Công cụ chỉ báo dòng khác trong tệp |

Bốn ca thứ hai là thiếu sót của bộ định vị lời gọi JavaScript (nó không nhận ra một số cách khai
báo `child_process`), không phải của công cụ phát hiện. Người rà vẫn thấy các cảnh báo này ở
hàng U, nhưng chúng không được tính là "được báo" theo quy tắc đã định.

**(d) Q1 và phần "mất" của Q2 trên mã Python chưa từng xem (PY-3).** Bảy vị trí lỗi đã công bố
trong bốn ứng dụng (một của I1, sáu của I3; bốn trong sáu vị trí của I3 là hai lỗi lặp lại ở hai
tệp gần như trùng nhau).

| Chỉ số | Kết quả |
|---|---|
| Vị trí được báo bởi hợp mọi nguồn | 7/7 |
| Semgrep riêng / Bandit riêng / CodeQL riêng | 7/7, 7/7, 5/7 |
| Vị trí bị gạn | **0/7** |
| Mức ưu tiên | 5 ở P1, 1 ở P2, 1 ở P3 |

Ở bốn vị trí, truy vấn bằng chứng của CodeQL đã thực sự xét luồng dữ liệu và **vẫn báo luồng**,
nên ứng viên được giữ với lý do tương ứng. Đây là trường hợp bước gạn được kích hoạt trên lỗi
thật và quyết định đúng. Hai lời gọi có lệnh là chuỗi hằng trong cùng ứng dụng chỉ bị Bandit
báo; chúng ở P3 và không bị gạn vì chỉ có một nguồn bằng chứng.

**(e) Đợt I1.** Cả ba vị trí đã công bố đều được báo, không vị trí nào bị gạn: hai vị trí
JavaScript ở P1 (CodeQL và ESLint), vị trí Python ở P3 (Semgrep và Bandit; CodeQL im lặng).

**(f) Đủ chỉ số trên mã chưa từng xem (PY-5, JS-4).** Đợt I4 có 135 vị trí có lỗi và 75 vị trí an
toàn.

*Kết quả đã đăng ký:* lượt quét duy nhất đã đăng ký **thất bại**. Một tệp Python cố ý sai cú
pháp trong kho làm bộ định vị lời gọi Python của nguyên mẫu dừng cả lượt quét. Không có ứng
viên nào, nên mọi cấu hình có TP = 0 và FN = 135. Kết quả này cho biết nguyên mẫu không quét
được kho, không cho biết gì về chất lượng phát hiện.

*Kết quả của lượt quét lại sau khi sửa lỗi.* Lỗi được sửa (tệp không phân tích được bị bỏ qua,
lượt quét thành "chạy dở"), kho được quét lại một lần và chấm bằng đúng nhãn và script đã băm
trước lượt đầu. Vì giao thức ghi "quét một lần", bảng dưới đây **nằm ngoài kết quả đã đăng
ký**. Lượt đầu không sinh cảnh báo nào và bản sửa không đụng tới phát hiện, gộp, xếp ưu tiên
hay gạn; đó là căn cứ để vẫn trình bày bảng này như một kết quả mô tả.

Trên cả 210 vị trí:

| Cấu hình | TP | FP | FN | TN | Độ chính xác | Độ bao phủ | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Semgrep riêng | 49 | 7 | 86 | 68 | 0,88 | 0,36 | 0,51 |
| CodeQL riêng | 20 | 0 | 115 | 75 | 1,00 | 0,15 | 0,26 |
| Bandit riêng | 88 | 47 | 47 | 28 | 0,65 | 0,65 | 0,65 |
| ESLint riêng | 1 | 0 | 134 | 75 | 1,00 | 0,01 | 0,01 |
| Semgrep ∪ CodeQL | 49 | 7 | 86 | 68 | 0,88 | 0,36 | 0,51 |
| **Hợp mọi nguồn** | 96 | 49 | 39 | 26 | 0,66 | 0,71 | 0,69 |
| Sau gạn (chỉ công cụ mã nguồn mở, và mọi quy tắc) | 96 | 49 | 39 | 26 | 0,66 | 0,71 | 0,69 |
| Nhóm rà trước (P1+P2) | 37 | 3 | 98 | 72 | 0,93 | 0,27 | 0,42 |

Trên 146 vị trí thuộc kiểm thử của các luật mà quy trình **không** chạy (93 có lỗi, 53 an
toàn), tức là bỏ phần Semgrep được chấm bằng kỳ vọng của chính nó:

| Cấu hình | TP | FP | FN | TN | Độ chính xác | Độ bao phủ | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Semgrep riêng | 19 | 3 | 74 | 50 | 0,86 | 0,20 | 0,33 |
| CodeQL riêng | 0 | 0 | 93 | 53 | — | 0,00 | — |
| Bandit riêng | 62 | 35 | 31 | 18 | 0,64 | 0,67 | 0,65 |
| Semgrep ∪ CodeQL | 19 | 3 | 74 | 50 | 0,86 | 0,20 | 0,33 |
| **Hợp mọi nguồn** | 66 | 36 | 27 | 17 | 0,65 | 0,71 | 0,68 |
| Sau gạn | 66 | 36 | 27 | 17 | 0,65 | 0,71 | 0,68 |
| Nhóm rà trước (P1+P2) | 7 | 1 | 86 | 52 | 0,88 | 0,08 | 0,14 |

- **Bước gạn không gạn vị trí nào, an toàn hay có lỗi.** Lượt quét lại ở trạng thái "chạy dở"
  (bước định vị Python bỏ qua tệp sai cú pháp; CodeQL cho JavaScript chạy dở), và theo thiết
  kế một lượt chạy dở không gạn gì. Câu hỏi Q2 vì vậy **không có câu trả lời** trên I4; 49 cảnh
  báo sai còn nguyên trong danh sách, 46 trong số đó ở P3 hoặc P4.
- Hợp mọi nguồn có F1 cao nhất (0,69), nhờ độ bao phủ; độ chính xác của nó (0,66) thấp hơn
  Semgrep riêng (0,88) và CodeQL riêng (1,00).
- CodeQL báo ít (20/135) vì nhiều đoạn mã minh họa nhận dữ liệu từ nguồn mà truy vấn mặc định
  không mô hình hóa, như sự kiện của hàm đám mây hay tham số của hàm thường.
- Nhóm rà trước rất chính xác (0,93) nhưng chỉ chứa 37/135 vị trí có lỗi; 59 vị trí có lỗi nằm
  ở P3.

**(g) Bước gạn trên mã Python thật chưa từng xem (PY-6).** Hai mươi công cụ dòng lệnh viết bằng
Python được chọn bằng một truy vấn tìm kiếm cố định trên GitHub (20 kết quả đầu theo số sao).
Các kho này không có lỗ hổng đã biết, nên đợt I5 không đo phát hiện; nó chỉ hỏi bước gạn làm
gì ở lượt quét hoàn tất và có làm đúng không.

| Chỉ số | Kết quả |
|---|---|
| Lượt quét | 18 hoàn tất, 1 chạy dở, 1 lỗi (ứng dụng từ chối tệp nén có mục không an toàn) |
| Ứng viên ở 18 lượt hoàn tất | 145 |
| Đã gạn | **19** (13%), ở 2 trong 18 kho |
| Quy tắc | G2 (lệnh là hằng, Bandit cùng chứng minh của hệ thống): 19. G1: 0. G3: 0 |
| Phép kiểm độc lập đã chốt trước | 17 "lệnh là hằng"; 2 "không hằng" |

Phép kiểm độc lập không dùng mã của nguyên mẫu: nó đọc tệp ở commit đã ghim, phân tích cú pháp
bằng thư viện chuẩn của Python và xét đối số lệnh của lời gọi trên dòng đó. Theo diễn giải đã
chốt trước, **kết quả đã đăng ký là 17 ứng viên gạn đúng và 2 ứng viên bị đánh là gạn sai**.

Đọc lại hai ca đó sau khi có kết quả: ở cả hai dòng, lời gọi chạy lệnh nằm trong một lời gọi
bọc ngoài, `int(getoutput("nproc"))` và `bool(getoutput("pacman -Qs auto-cpufreq"))`. Lệnh là
chuỗi hằng; phép kiểm viết trước đã xét cả lời gọi bọc ngoài. Nhận định sau khi đọc lại là cả
19 ứng viên bị gạn đều có lệnh hằng, nhưng nhận định này là xem xét sau và không thay con số
đã đăng ký.

- Đây là lần đầu bước gạn hành động trên mã chưa từng xem, và ở lượt quét chạy dở nó không gạn
  gì (39 ứng viên được giữ), đúng thiết kế.
- Chỉ quy tắc dễ nhất hoạt động. Hai quy tắc dựa trên bằng chứng về luồng dữ liệu (G1, G3) không
  gạn ứng viên nào: trong 184 ứng viên, CodeQL chỉ báo 2.
- 177 trong 184 ứng viên chỉ do Bandit báo. Sau gạn, 145 ứng viên còn ở P3: bước gạn bỏ được
  phần chắc chắn an toàn, phần lớn khối lượng rà soát vẫn còn.
- Không có nhãn dương tính, nên đợt này không cho biết bước gạn có làm mất lỗi thật hay không
  ngoài 19 ứng viên đã kiểm.

**(h) Minh họa bổ sung: CWE-22 trên Python (PY-4).** Số liệu của giai đoạn nghiên cứu cho gói
bằng chứng CodeQL v0.2:

| Dữ liệu | Cảnh báo sai được loại | Lỗi thật bị loại nhầm |
|---|---|---|
| OWASP BenchmarkPython, nửa kiểm tra, 4 nhóm lỗi | 49/53 (92,5%) | 0/37 |
| Mã thật, nhãn do chủ đề án xác minh | 4/43 (khoảng 9%) | 0/7 |

Kết quả "không loại nhầm" trên mã thật dựa trên hai giả định gán nhãn; theo cách đọc thận trọng
hơn, ba cảnh báo bị loại ở một kho trở thành "chưa xác định". Chạy lại qua nguyên mẫu cho đúng
kết quả của nghiên cứu: một kho giữ cả 3 cảnh báo, một kho có cả 3 cảnh báo ở danh sách "Đã gạn".

**(i) CVE thật của tập phát triển `pairs-v1`, phiên bản 0.2 (JS-5, PY-7).** 34 cặp, mỗi cặp quét
bản có lỗi một lần; 30 lượt hoàn tất, 4 lượt chạy dở. Cả 34 nguồn được tải lại qua nguyên mẫu và
có đúng mã băm SHA-256 đã khóa. 26 cặp có vị trí lỗi đã biết, 22 trong số đó thuộc lượt hoàn
tất.

| Cấu hình | Vị trí lỗi đã biết được báo (trên 22) | Tỷ lệ |
|---|---:|---:|
| Semgrep riêng | 11 | 0,50 |
| CodeQL riêng | 18 | 0,82 |
| ESLint riêng | 12 | 0,55 |
| Semgrep ∪ CodeQL | 19 | 0,86 |
| **Hợp mọi nguồn** | **21** | **0,95** |
| Sau gạn | 21 | 0,95 |
| Nhóm rà trước (P1+P2) | 18 | 0,82 |

- Tính cả bốn lượt chạy dở: 25 trên 26 vị trí được báo. Hai vị trí chỉ CodeQL báo, một vị trí
  chỉ ESLint báo, một vị trí chỉ Bandit báo.
- Không vị trí lỗi đã biết nào bị gạn.
- Ngoài các vị trí đã biết còn 821 ứng viên chưa có nhãn, phần lớn ở các kho Python lớn; 71
  trong số đó bị gạn, tất cả theo quy tắc lệnh hằng (G2). Phép kiểm độc lập của đợt I5 xác nhận
  cả 71 có lệnh là chuỗi hằng.
- Đây là dữ liệu phát triển: các nguồn này được dự án chọn và chuẩn bị từ trước, dù chưa từng
  quét. Kết quả không thay cho đánh giá trên tập giữ lại.

**(j) Sửa đối sánh và thử điều kiện gạn cho JavaScript/TypeScript, phiên bản 0.3 (JS-6).** Ở
đợt I2, bốn vị trí lỗi có công cụ báo đúng dòng nhưng cảnh báo nằm ở hàng U. Chẩn đoán trên
đầu ra đã lưu cho thấy cả bốn do khâu định vị lời gọi: hai ca vì Semgrep bỏ qua thư mục
`build/`, hai ca vì luật định vị thiếu dạng bí danh hai bước. Phiên bản 0.3 sửa hai nguyên nhân
đó (mục 2.3.3) và thêm quy tắc gạn G4 (mục 2.4.3). 84 package npm đã quét trước đó được quét
lại; 10 package đã được đọc mã để tìm lỗi, 74 package chưa.

| Chỉ số (phiên bản 0.2 → 0.3) | 10 nguồn đã đọc mã | 74 nguồn chưa đọc mã | Cả 84 |
|---|---:|---:|---:|
| Ứng viên JavaScript | 18 → 15 | 132 → 131 | 150 → 146 |
| Ứng viên ở hàng U | 13 → 0 | 24 → 14 | 37 → 14 |
| Cảnh báo từng ở U, nay gộp vào đúng lời gọi | 13 | 10 | **23** |
| Cảnh báo mới gộp nhưng nằm ngoài vùng mã của lời gọi (ghép nhầm) | 0 | 0 | **0** |
| Cảnh báo trước gộp được, nay ở U | 0 | 0 | 0 |
| Vị trí lỗi đã biết được báo | 2 → 8 (trên 10) | 53 → 54 (trên 59) | 55 → 62 (trên 69) |
| Vị trí lỗi đã biết bị gạn | 0 | 0 | 0 |
| Ứng viên bị gạn | 1 | 0 | 1 |

- *Đối sánh.* 23 cảnh báo được gộp thêm, không ca nào ghép nhầm theo phép kiểm vùng mã, và
  không cảnh báo nào mất lời gọi đã có. Trên ca tổng hợp, bộ định vị v1 nhận đúng 13 dạng lời
  gọi phải định vị và bỏ qua đúng 6 dạng không phải `child_process`; hai lời gọi liền kề được
  giữ thành hai ứng viên.
- *Phần chưa gộp được.* 14 cảnh báo vẫn ở hàng U và được giữ riêng: 8 cảnh báo của CodeQL nêu
  cùng lúc nhiều lời gọi dùng chung một chuỗi lệnh; 4 cảnh báo của ESLint đặt ở dòng nhập
  module; 1 ở tệp đã đóng gói; 1 ở lời gọi qua thư viện bọc.
- *Điều kiện gạn.* Bằng chứng "lệnh là hằng" của Semgrep CE đúng trên 20 ca tổng hợp (6 ca hằng
  được nhận, 14 ca không hằng không bị nhận). Để có nhãn đối chứng, một bộ gán nhãn độc lập
  (dùng bộ phân tích cú pháp `espree`, không dùng Semgrep) xét cả 120 ứng viên gọi `exec` hoặc
  `execSync`: 1 ứng viên có lệnh hằng, 116 không hằng, 3 không đọc được. G4 gạn đúng ứng viên
  có lệnh hằng (1/1) và không gạn ứng viên nào có lệnh không hằng (0/116). Ứng viên bị gạn là
  `exec(ipCommand, ...)` trong `arpping`, biến chỉ nhận hai chuỗi hằng theo hệ điều hành; vị trí
  lỗi đã công bố của chính package đó vẫn ở danh sách rà chính.
- *Trên JavaScript có nhãn.* Bộ I4 có 25 vị trí JavaScript có nhãn (15 có lỗi, 10 an toàn). Quét
  lại bằng phiên bản 0.3, hợp mọi nguồn báo 12 vị trí có lỗi thay vì 6: độ bao phủ 0,40 → 0,80,
  độ chính xác 1,00 → 0,86 (2 vị trí an toàn nay được tính là báo sai), F1 0,57 → 0,83. Khác
  biệt đến từ đối sánh; công cụ phát hiện không đổi. Lượt quét chạy dở nên không quy tắc gạn
  nào hoạt động và không vị trí có nhãn nào bị gạn. Kho này đã được quét trước đó, nên đây là
  kết quả phát triển.
- *Tác động.* Nhóm cảnh báo sai mà G4 xử lý chỉ chiếm 1 trong 146 ứng viên JavaScript. G4 đúng
  nhưng gần như không giảm khối lượng rà soát trên dữ liệu này, vì các luật bắt mẫu cho
  JavaScript hiếm khi báo một lệnh hằng.
- *Điều không kết luận được.* Hàng U giảm chỉ chứng minh đối sánh tốt hơn. Nhãn đối chứng chỉ
  bao phủ nhóm lệnh hằng; các loại cảnh báo sai khác trên JavaScript chưa có nhãn nên chưa đo
  được. Số vị trí lỗi "được báo" tăng vì cách đếm cần một ứng viên có lời gọi; các công cụ đã
  báo những vị trí đó từ trước.

### 3.3.3. Thời gian chạy theo từng bước và tổng thời gian chạy

Mỗi nguồn được đo một lần trên máy cá nhân, các công cụ chạy song song từng đôi; các con số chỉ
cho biết bậc độ lớn.

| Dữ liệu | Số lượt | Tổng thời gian một lượt (giây) | Ghi chú |
|---|---:|---|---|
| D1 (Python) | 1 | 53 | Một lần đo khác trong ngày, khi máy bận, mất 171 giây |
| D2 (12 package npm) | 12 | 13 đến 43 | |
| I2 (52 package npm) | 52 | Trung vị 14,5; lớn nhất 28,8; tổng 720 | |
| I3 (3 ứng dụng Python) | 3 | Trung vị 15,3 | |
| I4 (một kho, hai ngôn ngữ), lượt quét lại | 1 | 165 | CodeQL phân tích: 39 giây (Python), 76 giây (JavaScript, chạy dở); bằng chứng CodeQL 28 giây, bằng chứng Semgrep 2 giây |
| I5 (20 kho Python) | 20 | Trung vị 17,0; lớn nhất 36,2; tổng 377 | |
| P1 (34 cặp, phiên bản 0.2) | 34 | Trung vị 14,8; lớn nhất 410; tổng 1.833 | Các kho Python lớn chiếm phần lớn thời gian |

Thời gian từng bước, trung vị trên 46 lượt của I2 có chạy công cụ, và lượt D1:

| Bước | I2, trung vị (giây) | D1 (giây) |
|---|---:|---:|
| Semgrep | 1,2 | 3,2 |
| Công cụ bổ trợ (ESLint hoặc Bandit) | 0,4 | 1,9 |
| CodeQL tạo cơ sở dữ liệu | 4,5 | 18,9 |
| CodeQL phân tích | 7,4 | 17,5 |
| Bằng chứng Semgrep | — | 3,6 |
| Bằng chứng CodeQL | — | 10,4 |

CodeQL chiếm phần lớn thời gian của mỗi lượt. Hai bước bằng chứng dùng lại dữ liệu sẵn có (mã đã
giải nén, cơ sở dữ liệu đã tạo), nên trên D1 chúng thêm khoảng 14 giây vào một lượt 53 giây.

## 3.4. Nhận xét và thảo luận

**Về Q1 — phát hiện.**

1. *Lấy hợp các nguồn báo được nhiều lỗi thật hơn mọi công cụ chạy riêng, trên cả dữ liệu phát
   triển lẫn dữ liệu độc lập.* Trên 43 lỗ hổng thật của package npm: 32 so với 27 của CodeQL và
   12 của Semgrep. Trên bảy vị trí Python độc lập: 7 so với 5 của CodeQL. Trên I4 (lượt quét lại):
   96/135 so với 88 của Bandit, 49 của Semgrep và 20 của CodeQL.
2. *Hai công cụ trong tên đề tài chưa đủ.* Semgrep ∪ CodeQL đạt 29/43; công cụ bổ trợ thêm 3 vị
   trí. Trên D1, hai lỗi thật chỉ Bandit báo. Việc đề cương đưa công cụ bổ trợ vào quy trình
   được số liệu ủng hộ.
3. *Điều chỉnh từ luồng nối tiếp sang lấy hợp có căn cứ trên dữ liệu độc lập.* Nếu CodeQL chỉ
   xét những vị trí công cụ quét nhanh đã báo, ba vị trí chỉ CodeQL báo trong I2 sẽ không vào
   danh sách.
4. *Độ bao phủ còn xa mức đầy đủ.* 11 trong 43 lỗ hổng thật không được báo theo quy tắc khớp;
   với 5 trong số đó không công cụ nào báo gì. Trên I4, 39/135 vị trí có lỗi không được báo.
5. *Cái giá của độ bao phủ là độ chính xác.* Trên I4, hợp mọi nguồn có F1 cao nhất (0,69)
   nhưng độ chính xác 0,66, thấp hơn Semgrep riêng (0,88) và CodeQL riêng (1,00). Phần lớn cảnh
   báo sai thêm vào đến từ Bandit (47 trong 49).

**Về Q2 — thẩm định.**

6. *Bước gạn không làm mất lỗi thật nào trong mọi phép đo:* 0/13 trên D1; 0/7 trên Python độc
   lập, trong đó bốn vị trí đã được truy vấn bằng chứng xét và giữ lại; 0 trên các vị trí
   JavaScript, nơi bước gạn không có gói bằng chứng.
7. *Lợi ích của bước gạn có thật nhưng hẹp.* Trên D1 nó loại 2/7 cảnh báo sai (1/7 nếu chỉ dùng
   công cụ mã nguồn mở). Trên dữ liệu độc lập: ở I1–I3 không ứng viên nào có bằng chứng bác bỏ;
   ở I4 lượt quét chạy dở nên bước gạn không hoạt động; ở I5 nó gạn 19 trong 145 ứng viên của
   các lượt hoàn tất, tất cả theo quy tắc "lệnh là hằng" và đều là lệnh hằng khi kiểm lại. Như
   vậy trên mã chưa từng xem, chỉ quy tắc dựa vào Bandit (G2) đã được thấy hoạt động; hai quy
   tắc dựa vào bằng chứng luồng dữ liệu (G3 của Semgrep, G1 của CodeQL) mới chỉ hoạt động trên
   dữ liệu phát triển. Các tình huống mà gói bằng chứng CWE-78 mô tả chủ yếu khớp mẫu của D1;
   với CWE-22, tỷ lệ loại trên mã thật (khoảng 9%) thấp hơn nhiều so với trên benchmark
   (92,5%). Nguyên tắc "chạy dở thì giữ" an toàn nhưng có giá: chỉ một tệp không phân tích
   được trong kho là đủ để tắt bước gạn cho cả lượt quét.
8. *Quy trình không vượt CodeQL chạy riêng về F1 trên D1* (0,84 so với 0,85): độ bao phủ cao hơn
   (1,00 so với 0,85) nhưng độ chính xác thấp hơn (0,72 so với 0,85). Phần cảnh báo sai còn lại
   đến từ luật khớp mẫu và không có bằng chứng bác bỏ.
9. *Xếp ưu tiên cho nhóm rà trước chính xác, nhưng độ bao phủ của nhóm đó phụ thuộc vào CodeQL.*
   Nhóm rà trước chứa 11/13 lỗi thật và không có cảnh báo sai trên D1; 29/32 trên I2; 6/7 trên
   Python độc lập. Trên I4, nơi CodeQL báo ít, nhóm này vẫn chính xác (0,93) nhưng chỉ chứa
   37/135 vị trí có lỗi; 59 vị trí có lỗi nằm ở P3. Mức P3 phản ánh việc thiếu bằng chứng về
   luồng dữ liệu, không phản ánh mức nguy hiểm; người rà chỉ đọc P1 và P2 sẽ bỏ sót.

**Về nguyên mẫu.**

10. Dữ liệu độc lập làm lộ bốn khiếm khuyết mà dữ liệu phát triển không cho thấy: lỗi xử lý ký
    tự xuống dòng làm hỏng lượt quét JavaScript (đã sửa); một tệp Python sai cú pháp làm hỏng cả
    lượt quét (đã sửa); bộ định vị lời gọi JavaScript bỏ qua một số cách khai báo, khiến 4 cảnh
    báo đúng nằm ở hàng U thay vì được gộp (chưa sửa: cần một phiên bản bộ định vị mới); và
    thông báo lỗi không rõ khi phiên bản package không còn tồn tại.

**Về phiên bản 0.3.**

11. *Một phần cảnh báo ở hàng U là lỗi của khâu định vị, không phải cảnh báo khó.* Sửa phạm vi
    tệp và luật định vị đưa 23 trong 37 cảnh báo về đúng lời gọi mà không ghép nhầm ca nào. Phần
    còn lại ở hàng U có lý do cụ thể và được giữ riêng.
12. *Quy tắc gạn cho JavaScript đúng nhưng tác động nhỏ.* Đối chiếu với nhãn đối chứng độc lập,
    quy tắc lệnh hằng gạn đúng 1/1 và gạn nhầm 0/116. Nhưng nhóm cảnh báo sai này chỉ có một ca
    trong 84 nguồn. Muốn giảm cảnh báo sai trên JavaScript một cách đáng kể cần bằng chứng cho
    các loại khác, và dữ liệu có nhãn an toàn để kiểm nghiệm chúng.
13. *Trên CVE thật của tập phát triển, lấy hợp các nguồn báo 21/22 vị trí đã biết* (CodeQL riêng
    18), và quy tắc lệnh hằng gạn 71 ứng viên, đều được kiểm lại là lệnh hằng.

**Giới hạn của kết luận.**

- Độ chính xác và F1 trên dữ liệu độc lập chỉ có ở I4: mã minh họa của luật, không phải mã ứng
  dụng, và từ lượt quét lại sau khi sửa lỗi chứ không phải lượt đã đăng ký. Trên mã ứng dụng
  thật cho CWE-78 vẫn chưa có số đo độ chính xác.
- Nhãn của I2 và I4 do bộ dữ liệu và tác giả luật công bố, nhãn của D1 do tác giả benchmark
  đưa ra; dự án không gán nhãn độc lập.
- Năm đợt độc lập được đăng ký bằng mã băm trong cùng phiên làm việc với lượt quét, chưa được
  công bố bằng commit; không có dấu thời gian bên ngoài chứng minh thứ tự. Script chấm của đợt 2
  phải sửa một dòng sau khi quét; sai lệch này được ghi lại và không đổi cách tính.
- Các lượt quét của ba đợt độc lập đầu chạy trên phiên bản nguyên mẫu còn lỗi xử lý ký tự xuống
  dòng. Ngoài hai lượt bị hỏng, lỗi này có thể đã làm sai vùng đối số ở tệp JavaScript khác có
  xuống dòng kiểu Windows, khiến số vị trí được báo thấp hơn thực tế. Các nguồn này không được
  quét lại, để giữ nguyên tắc mỗi nguồn quét một lần.
- Tập giữ lại của `pairs-v1` chưa được mở; nó được để dành cho phiên bản cuối. Kết quả trên tập
  phát triển của `pairs-v1` và trên 84 package quét lại là kết quả phát triển.
- Thời gian được đo một lần cho mỗi nguồn.
- Chưa có phép đo với người rà: chưa biết quy trình có giảm thời gian rà soát thực tế không.

## 3.5. Kết chương

Chương này đã đánh giá quy trình trên dữ liệu phát triển và trên năm đợt dữ liệu chưa từng xem.
Kết quả ủng hộ mục tiêu thứ nhất của quy trình: lấy hợp các nguồn phát hiện được nhiều lỗi thật
hơn từng công cụ, kể cả trên 43 lỗ hổng thật của package npm, với cái giá là độ chính xác thấp
hơn công cụ phân tích luồng dữ liệu chạy riêng. Với mục tiêu thứ hai, kết quả có hai mặt: bước
gạn chưa làm mất lỗi thật nào trong mọi phép đo và đã hành động đúng trên mã thật chưa từng
xem, nhưng phần nó loại được ở đó chỉ là các lời gọi có lệnh hằng; các quy tắc dựa trên bằng
chứng luồng dữ liệu mới chỉ thấy hoạt động trên dữ liệu phát triển. Thứ tự rà soát cho một
nhóm rà trước chính xác, nhưng nhóm đó chỉ bao phủ tốt khi CodeQL báo được luồng dữ liệu.

Bốn việc cần làm để có kết luận mạnh hơn: mở tập giữ lại của `pairs-v1` cho phiên bản cuối, theo
đúng giao thức; gán nhãn một mẫu ứng viên trên mã ứng dụng thật, nhất là JavaScript, để tính độ
chính xác và kiểm nghiệm quy tắc gạn G4; mở rộng bằng chứng gạn cho JavaScript/TypeScript ngoài
nhóm lệnh hằng; và xét lại phạm vi của nguyên tắc "chạy dở thì giữ" để một tệp không
phân tích được không tắt bước gạn của cả lượt quét.
