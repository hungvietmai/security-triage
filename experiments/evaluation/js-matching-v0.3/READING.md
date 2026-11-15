# Đối sánh và điều kiện gạn cho JavaScript/TypeScript: chẩn đoán, kết quả và phần đọc lại

Ghi ngày 2026-11-15. Số liệu: [results/compare.json](results/compare.json), dựng lại bằng
[compare.py](compare.py). Toàn bộ là **dữ liệu phát triển** (xem [README.md](README.md)).

## 1. Bốn ca ghép hụt đã biết

Ở đợt kiểm tra độc lập thứ hai, bốn vị trí lỗi đã công bố có công cụ báo đúng dòng nhưng cảnh báo
nằm ở hàng U. Chẩn đoán dùng báo cáo đã lưu của v0.2 và đầu ra của luật định vị chạy riêng trên
từng package:

| Package | Cảnh báo ở hàng U | Nguyên nhân | Thuộc bước |
|---|---|---|---|
| `adb-driver@0.1.8` | ESLint, `build/AdbDriver.js:26` | Semgrep tự bỏ qua thư mục `build/`, nên luật định vị không chạy trên tệp này; CodeQL và ESLint vẫn quét nó | Chọn tệp cho bộ định vị |
| `umount@1.1.6` | CodeQL, `build/umount.js:52` | Như trên | Chọn tệp cho bộ định vị |
| `kill-process-by-name@1.0.5` | CodeQL và ESLint, `index.js:9`, `:12` | `var exec = childProcess.exec; exec(...)`: bí danh hai bước, luật định vị v0 không có dạng này | Luật của bộ định vị |
| `node-unrar@0.1.0` | ESLint, `lib/index.js:23` | Bí danh hai bước | Luật của bộ định vị |

Không ca nào do bước chuẩn hóa vị trí hay bước đối sánh: khi lời gọi được định vị, cảnh báo gộp
được theo các căn cứ sẵn có của `reconcile-v0.1`. Hai phát hiện kèm theo:

- **Phạm vi tệp của Semgrep do mã bị quét quyết định được.** Một tệp `.semgrepignore` trong mã bị
  quét, kể cả ở thư mục con, làm Semgrep bỏ qua tệp tùy ý (đã thử với Semgrep 1.178.0). Lỗi
  này ảnh hưởng cả luật phát hiện lẫn luật bằng chứng, không riêng bộ định vị.
- `ps-visitor@0.0.2` dùng `util.promisify(require('child_process').exec)`; cảnh báo của CodeQL ở
  đó chỉ nêu lời gọi như một vị trí liên quan.

## 2. Bản sửa

Profile `command-injection-v0.3` ([đặc tả](../../../profiles/command-injection-v0.3/PRIORITY_V0_3.md)):

1. worker ghi tệp `.semgrepignore` của riêng nó (chỉ bỏ `node_modules/`) và xóa mọi tệp cùng tên
   trong bản giải nén;
2. bộ định vị v1 giữ nguyên mọi luật của v0 và thêm: bí danh hai bước, destructuring, hàm đã
   `promisify`, `require` nội tuyến, tiền tố `node:`.

Lượt chạy đầu của v0.3 làm lộ một ca đi lùi: `monorepo-build@0.1.9` dùng destructuring có đổi tên
(`const { execSync: _execSync } = require('child_process')`), dạng mà luật v0 nhận được nhờ
phép tương đương của Semgrep nhưng bản nháp v1 bỏ sót. v1 được sửa thành tập cha của v0 theo cấu
trúc, và cả 84 nguồn được quét lại; số liệu dưới đây là của lượt quét lại đó. Kết quả so sánh của
lượt đầu được giữ ở [results/compare-first-draft.json](results/compare-first-draft.json).

## 3. Trước–sau trên 84 nguồn npm (v0.2 → v0.3)

| Chỉ số | 10 nguồn đã đọc mã để sửa | 74 nguồn chưa đọc mã | Cả 84 |
|---|---:|---:|---:|
| Ứng viên JavaScript | 18 → 15 | 132 → 131 | 150 → 146 |
| Ứng viên ở hàng U | 13 → 0 | 24 → 14 | 37 → 14 |
| Cảnh báo từng ở U, nay gộp vào một lời gọi | 13 | 10 | **23** |
| Cảnh báo vẫn ở U | 0 | 14 | 14 |
| Cảnh báo mới gộp nhưng không nằm trong vùng mã của lời gọi (ghép nhầm) | 0 | 0 | **0** |
| Cảnh báo trước gộp được, nay ở U | 0 | 0 | 0 |
| Vị trí lỗi đã biết được báo | 2 → 8 (trên 10) | 53 → 54 (trên 59) | 55 → 62 (trên 69) |
| Vị trí lỗi đã biết bị gạn | 0 | 0 | 0 |
| Ứng viên bị gạn | 1 | 0 | 1 |

- Trạng thái lượt quét sau: 78 hoàn tất, 6 chạy dở. Hai nguồn từng hỏng ở v0.2 vì lỗi ký tự xuống
  dòng nay quét được.
- Trong 23 cảnh báo mới gộp, 2 nhờ sửa phạm vi tệp (`adb-driver`, `umount`), 21 nhờ các dạng lời
  gọi mà v1 định vị thêm.
- **Phép kiểm ghép nhầm:** với mỗi cảnh báo mới gộp, vùng mã chính của nó, hoặc một vị trí liên
  quan của nó, phải nằm trong vùng mã của lời gọi mà ứng viên bắt đầu. Vùng mã lời gọi lấy từ
  đầu ra của luật định vị v1 chạy riêng ([v1-sinks.json](v1-sinks.json)). Phép kiểm này xác nhận
  cảnh báo trỏ vào lời gọi được gộp; nó không chứng minh lời gọi đó là lỗi.

**Cách đọc.** Hàng U giảm cho thấy đối sánh tốt hơn, không cho thấy cảnh báo sai giảm. Số vị
trí lỗi đã biết "được báo" tăng vì quy tắc đếm cần một ứng viên có lời gọi; các công cụ đã báo
những vị trí đó từ trước.

## 4. Mười bốn cảnh báo vẫn ở hàng U, và lý do giữ riêng

| Số cảnh báo | Nguồn | Vì sao chưa đủ căn cứ để gộp |
|---:|---|---|
| 8 | `extra-asciinema` (7), `codecov` (1) | Cảnh báo `js/shell-command-constructed-from-input` của CodeQL nằm ở chuỗi lệnh được dựng trong một hàm và nêu **nhiều** lời gọi dùng chuỗi đó. Các lời gọi đều đã được định vị, nhưng một cảnh báo không thuộc riêng lời gọi nào; gộp vào một lời gọi là đoán |
| 4 | `git-parse` | Cảnh báo của ESLint nằm ở dòng `require("child_process")`, tức ở lệnh nhập module, không ở một lời gọi |
| 1 | `@thi.ng/egf` | Cảnh báo của ESLint ở dòng 1 của tệp UMD đã đóng gói; lời gọi nhận `child_process` qua tham số của hàm bọc |
| 1 | `local-devices` | Lời gọi dùng `require('mz/child_process')`, một lớp bọc; v1 chỉ nhận module `child_process` |

Cả 14 được giữ là ứng viên riêng ở hàng U và vẫn hiện cho người rà.

## 5. Điều kiện gạn hẹp cho JavaScript: lệnh là hằng (G4)

**Nhóm được chọn.** Cảnh báo bắt mẫu (ESLint `detect-child-process` báo mọi `exec()` có đối số
không phải literal) trên lời gọi mà chuỗi lệnh thực ra là hằng. Căn cứ rõ: một chuỗi lệnh hằng
không thể bị chèn qua chính đối số đó.

**Công cụ có cung cấp đủ bằng chứng không.** Có, với Semgrep CE: phép lan truyền hằng của nó cho
biết đối số đầu là hằng, và vùng mã nó báo đủ để đối chiếu đúng lời gọi. Trên 20 ca tổng hợp
(Semgrep 1.178.0): 6/6 ca hằng được nhận, 0/14 ca không hằng bị nhận nhầm, gồm biến bị gán lại ở
hàm khác và biến đổi trong closure. Bản không lan truyền hằng chỉ nhận 2/5 ca hằng ở lần thử đầu.

**Dữ liệu để kiểm tra.** Rất mỏng. Trong 83 nguồn có đầu ra thử, 162 lời gọi được định vị có lệnh
hằng, nhưng chỉ **một** lời gọi mang cảnh báo. Không nguồn JavaScript nào có nhãn an toàn (10 vị
trí an toàn của đợt kiểm tra độc lập thứ tư không bị công cụ nào báo).

**Nhãn đối chứng.** Với riêng nhóm này, nhãn dựng được một cách cơ học và không dùng Semgrep:
[constant_reference.cjs](constant_reference.cjs) phân tích tệp bằng `espree` và coi lệnh là hằng
chỉ khi mọi phép gán tới tên đó đều là hằng (trong hàm chứa lời gọi nếu tên được khai báo ở
đó, nếu không thì trong cả tệp). Trên 19 ca tổng hợp có kỳ vọng, nó đúng cả 19. Bộ gán nhãn
được sửa hai lần sau khi chạy trên chính dữ liệu này, cả hai lần vì chọn nhầm lời gọi khi nhiều
lời gọi cùng điểm bắt đầu; bản cuối khớp lời gọi bằng cả điểm đầu và điểm cuối.

**Kết quả** ([results/constant-reference.json](results/constant-reference.json)).

| Trên 120 ứng viên gọi `exec`/`execSync` của 84 nguồn | Số lượng |
|---|---:|
| Nhãn đối chứng: lệnh là hằng | 1 |
| Nhãn đối chứng: lệnh không hằng | 116 |
| Không đọc được lời gọi | 3 |
| Cảnh báo sai thuộc nhóm lệnh hằng (lệnh hằng, chỉ có cảnh báo bắt mẫu) | 1 |
| — G4 gạn đúng | **1/1** |
| — G4 bỏ sót | 0 |
| Ứng viên có lệnh không hằng bị G4 gạn (gạn nhầm) | **0/116** |
| Vị trí lỗi đã biết bị gạn | 0/62 |

Trên ca tổng hợp của bước thẩm định (`test_javascript_matching.py`): 1/1 ca phải gạn được gạn;
7/7 ca phải giữ được giữ (có công cụ khẳng định luồng; bước bằng chứng lỗi; lượt chạy dở; `spawn`;
bằng chứng về lời gọi khác trên cùng dòng; không có bước bằng chứng; lời gọi liền kề không có
bằng chứng).

Ứng viên bị gạn là `arpping@2.0.0`, `index.js:60`, `exec(ipCommand, ...)`, chỉ ESLint báo;
`ipCommand` chỉ được gán hai chuỗi hằng (`'ipconfig'`, `'ifconfig'`) theo hệ điều hành. Vị trí
lỗi đã công bố của chính package đó vẫn ở danh sách rà chính.

**Kết luận có căn cứ.**

- *Về độ đúng:* đối chiếu với nhãn đối chứng, G4 gạn đúng mọi cảnh báo sai thuộc nhóm lệnh
  hằng (1/1) và không gạn nhầm ứng viên nào có lệnh không hằng (0/116).
- *Về tác động:* nhóm này chỉ chiếm 1 trong 120 ứng viên gọi `exec`/`execSync`, tức 1 trong 146
  ứng viên JavaScript. Trên dữ liệu này G4 **gần như không giảm khối lượng rà soát**. Lý do nằm
  ở khâu phát hiện: luật của ESLint và hai luật `spawn(..., {shell: true})` của Semgrep hiếm khi
  báo một lệnh hằng.
- *Trên JavaScript có nhãn hai phía:* bộ kiểm thử luật của semgrep-rules có 25 vị trí. Quét lại
  bằng v0.3, hợp mọi nguồn đạt độ chính xác 0,86, độ bao phủ 0,80, F1 0,83 (v0.2: 1,00, 0,40,
  0,57); lượt quét chạy dở nên G4 không hoạt động ở đó. Xem
  [../independent-labeled/DEVIATIONS.md](../independent-labeled/DEVIATIONS.md), mục 4.
- *Điều chưa đo được:* các loại cảnh báo sai khác trên JavaScript. Nhãn đối chứng ở đây chỉ nói
  lệnh có hằng hay không; nó không nói một lệnh không hằng có khai thác được hay không.

**Đầu vào còn thiếu để kiểm nghiệm bước gạn cho JavaScript:**

1. nhãn an toàn cho các loại cảnh báo sai **ngoài** nhóm lệnh hằng: một tập mã
   JavaScript/TypeScript có nhãn cho cảnh báo CWE-78, hoặc một người gán nhãn 17 ứng viên P3 và
   14 ứng viên U còn lại trong 84 nguồn này;
2. mã có nhiều cảnh báo bắt mẫu trên lệnh hằng hơn. Hai luật Semgrep về `spawn(..., {shell: true})`
   và luật của ESLint hiếm khi báo một lệnh hằng, nên nhóm này nhỏ ngay từ khâu phát hiện;
3. dữ liệu chưa từng xem: 84 nguồn này đã dùng để phát triển, và tập giữ lại của `pairs-v1` đang
   được để dành cho phiên bản cuối (Amendment 07).
