# Giao thức gán nhãn ứng viên JavaScript/TypeScript của phiên bản 0.3 (CWE-78)

Viết ngày 2026-11-15, **trước khi mở phiếu gán nhãn**. Mã băm của tệp này và của hai script
được ghi trong [PREREGISTRATION.json](PREREGISTRATION.json) trước khi phiếu được tạo.

## 1. Mục đích

Các đợt trước chỉ có nhãn "an toàn" cho một loại cảnh báo sai (chuỗi lệnh là hằng). Đợt này
gán nhãn cho **mọi ứng viên JavaScript/TypeScript** của 84 package npm đã quét bằng profile
`command-injection-v0.3` ([../js-matching-v0.3/inputs/](../js-matching-v0.3/README.md)) để trả
lời:

1. trong danh sách rà, bao nhiêu ứng viên là cảnh báo sai và chúng thuộc loại nào;
2. bước gạn hiện có chuyển đi bao nhiêu cảnh báo sai, bao nhiêu cảnh báo đúng, và loại cảnh báo
   sai nào còn nguyên trong danh sách;
3. độ chính xác của từng cấu hình trên các ứng viên có nhãn.

## 2. Ai gán nhãn — giới hạn chính của đợt này

- Nhãn do **trợ lý lập trình AI** gán bằng cách đọc mã nguồn, theo yêu cầu của chủ đề án
  ("tự động gán", 2026-11-15). Trợ lý này cũng là bên đã viết bộ định vị và quy tắc gạn G4,
  nên nhãn **không độc lập** với quy trình được đo.
- **Chưa có người nào kiểm nhãn.** Trường `reviewed_by` của [labels.json](labels.json) để
  `null` cho tới khi một người thật sự rà phiếu; khi đó ghi tên vai trò, ngày và những nhãn
  người đó sửa. Không ghi trước.
- 84 package này là dữ liệu phát triển của phiên bản 0.3; mã của mười package đã được đọc khi
  sửa đối sánh.
- Vì ba điều trên, kết quả là **ước lượng trên dữ liệu phát triển với nhãn chưa kiểm**, không
  phải đánh giá độc lập.

## 3. Đơn vị và phạm vi

- Một đơn vị là một ứng viên của báo cáo đã lưu nằm trong tệp `.js`, `.jsx`, `.ts`, `.tsx`,
  `.mjs` hoặc `.cjs`, xác định bằng package, tệp và dòng bắt đầu. Ứng viên Python nằm trong
  package npm không thuộc phạm vi.
- Ứng viên trùng một **vị trí lỗi đã biết** (nhãn CVE của đợt độc lập thứ hai và của tập phát
  triển `pairs-v1`) giữ nhãn "có lỗi" từ nguồn đó và không được gán lại.
- Mọi ứng viên còn lại được đưa vào phiếu. Không chọn mẫu.

## 4. Phiếu gán nhãn

[label_sheet.py](label_sheet.py) tải từng package từ npm, không chạy mã nào, và ghi cho mỗi
ứng viên: package, tệp, dòng và đoạn mã quanh dòng đó. Phiếu **không** ghi công cụ nào báo, mức
ưu tiên hay quyết định giữ/gạn. Khi đoạn mã không đủ để lần nguồn gốc giá trị, người gán nhãn
được đọc phần còn lại của package.

## 5. Tiêu chí, chốt trước

Câu hỏi cho mỗi ứng viên: *giá trị mà shell diễn giải có chứa dữ liệu do bên ngoài package
kiểm soát mà không được vô hiệu hóa không?* "Bên ngoài" gồm tham số của hàm mà package xuất ra
cho người dùng, tham số dòng lệnh, biến môi trường, nội dung tệp, dữ liệu mạng. Đây là quy ước
của chính các CVE trong bộ dữ liệu: một thư viện ghép tham số của hàm công khai vào chuỗi lệnh
được coi là có lỗi.

| Nhãn | Điều kiện |
|---|---|
| `vulnerable` | Thấy được đường đi từ dữ liệu bên ngoài tới chuỗi lệnh (hoặc tới đối số được shell diễn giải) và không có bước trích dẫn/kiểm tra nào chặn ký tự đặc biệt của shell |
| `safe` | Một trong các loại ở bảng dưới, thấy được trong mã |
| `undetermined` | Không quyết định được từ mã của package: giá trị đến từ cấu hình hay mô-đun khác mà nguồn gốc không rõ, hoặc có bước làm sạch mà độ chặt không đánh giá được |

| Loại `safe` | Nghĩa |
|---|---|
| `constant_command` | Toàn bộ chuỗi lệnh là hằng |
| `internal_values_only` | Chuỗi lệnh chỉ ghép từ hằng và giá trị do package tự quyết định (nền tảng, đường dẫn cố định, số, giá trị nội bộ) |
| `validated_or_escaped` | Dữ liệu bên ngoài đi qua danh sách cho phép, biểu thức chính quy chặt, ép kiểu số hoặc trích dẫn shell đúng trước khi ghép |
| `no_shell` | Lời gọi không qua shell (`spawn`/`execFile` với mảng đối số, không `shell: true`) và tên chương trình không do bên ngoài kiểm soát |
| `not_a_command_sink` | Dòng được báo không chạy lệnh hệ điều hành (ví dụ `exec` của đối tượng khác, hoặc dòng `require`) |
| `test_or_example_code` | Mã kiểm thử, ví dụ hoặc script dựng của package, chạy lệnh với giá trị do chính nó đặt |

Quy tắc phụ:

- Khi phân vân giữa `safe` và `undetermined`, chọn `undetermined`. Khi phân vân giữa
  `vulnerable` và `undetermined`, chọn `undetermined`.
- Mỗi nhãn kèm một câu lý do nêu giá trị nào đi vào lệnh và nó đến từ đâu.
- Nhãn không nói lỗi có khai thác được trong một ứng dụng cụ thể hay không.

## 6. Chấm điểm

[score_labels.py](score_labels.py), viết trước khi gán nhãn và kiểm trên dữ liệu tổng hợp:

- Cấu hình: Semgrep riêng, CodeQL riêng, ESLint riêng, Semgrep ∪ CodeQL, hợp mọi nguồn, sau
  gạn, nhóm rà trước (P1+P2) sau gạn.
- Với mỗi cấu hình: TP (ứng viên `vulnerable`, gồm vị trí lỗi đã biết), FP (ứng viên `safe`),
  số `undetermined`, độ chính xác TP/(TP+FP).
- Độ bao phủ: TP chia cho tổng số vị trí có lỗi được biết, gồm cả vị trí lỗi đã biết mà không
  công cụ nào báo. Mẫu số này **thiếu** các lỗi không công cụ nào báo và không có CVE, nên độ
  bao phủ và F1 là cận trên.
- Bước gạn: số `safe`, `vulnerable`, `undetermined` bị gạn; số `safe` còn lại trong danh sách
  rà theo loại và theo mức ưu tiên.
- Mọi bảng tính thêm riêng cho 74 package mà mã chưa từng được đọc khi sửa đối sánh.

## 7. Diễn giải đã chốt trước

- Một ứng viên `vulnerable` bị gạn là thất bại của bước gạn.
- Một ứng viên `safe` còn trong danh sách rà **không** là lỗi của bước gạn: quy trình chỉ gạn
  khi có bằng chứng. Nó cho biết loại bằng chứng nào còn thiếu.
- `undetermined` không được tính là đúng hay sai.
- Kết quả được báo dù thuận hay không thuận, và luôn kèm câu "nhãn do trợ lý AI gán, chưa được
  người kiểm" cho tới khi `reviewed_by` được điền.
