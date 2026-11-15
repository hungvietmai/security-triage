# Kết quả cho Chương 3 — Thử nghiệm và đánh giá

Mọi bảng dưới đây tái lập được từ tệp đã lưu trong repo; lệnh ở
[experiments/evaluation/README.md](../../experiments/evaluation/README.md). Ngày đo: 2026-11-14.

> **Giới hạn chung, đọc trước.** Mục 3.2–3.6 dùng **dữ liệu phát triển**: đã được quét và xem ở
> các giai đoạn trước, và quy tắc gạn được thiết kế khi đã biết các ca an toàn của benchmark.
> Mục 3.7 là đợt kiểm tra đầu tiên trên mã chưa từng xem. Hai đợt sau (52 package npm có CVE
> thật; ba ứng dụng Python) được trình bày trong bản thảo
> [chuong-3-thuc-nghiem.md](chuong-3-thuc-nghiem.md), mục 3.3. Tập CVE lỗi/vá `pairs-v1`
> (50 cặp, 16 cặp giữ lại) được quét sau đó, ngày 2026-11-15; xem mục 3.3.2 (i) và (k) của bản thảo.

## 3.1 Thiết lập

| Mục | Giá trị |
|---|---|
| Profile | `command-injection-v0.2` (CWE-78), `path-traversal-v0.2` (CWE-22) |
| Công cụ phát hiện | Semgrep CE 1.178.0, CodeQL 2.27.1, Bandit 1.9.4, ESLint 10.15.0 + eslint-plugin-security 4.2.1 |
| Bước gạn | `adjudicate-v0.2`: luật bằng chứng nhánh chết của Semgrep CE (G3), truy vấn bằng chứng an toàn của CodeQL v0.2 (G1), lệnh là hằng với Bandit (G2) |
| Môi trường | Docker Compose trên máy cá nhân (Windows, Docker Desktop); worker giới hạn CodeQL 2 GB RAM |
| Đơn vị đếm | Ứng viên rà soát: một lời gọi thực thi lệnh. Một vị trí có nhãn được tính là "được báo" khi có ứng viên của nó trong cấu hình |
| Nhãn CWE-78 (mục 3.2) | Kỳ vọng của tác giả OWASP BenchmarkPython (13 lỗi thật, 7 an toàn), đã được một lượt rà mã nguồn không mù xác nhận |
| Đầu vào đã lưu | [experiments/evaluation/inputs/](../../experiments/evaluation/inputs/) và [independent/inputs/](../../experiments/evaluation/independent/inputs/): báo cáo JSON và SARIF hợp nhất do ứng dụng xuất, kèm SHA-256 |

## 3.2 Kịch bản chính: CWE-78 trên Python

Nguồn: OWASP BenchmarkPython, commit `f129148`, 20 vị trí CWE-78. Kết quả:
[results/owasp-benchmarkpython-v0.2.json](../../experiments/evaluation/results/owasp-benchmarkpython-v0.2.json).

**Các bước của quy trình.**

| Bước | Số lượng |
|---|---:|
| Cảnh báo thô của mọi công cụ | 51 |
| Đơn vị (gộp theo lời gọi và vai trò đối số) | 24 |
| Ứng viên rà soát (mỗi lời gọi một mục) | 20 |
| Danh sách rà chính sau khi gạn | 18 |
| Đã gạn vì có bằng chứng | 2 |
| Chỉ hạ ưu tiên (P3), vẫn trong danh sách chính | 7 |

**So sánh trước–sau trên cùng 20 vị trí.**

| Cấu hình | Ứng viên | Đúng (TP) | Sai (FP) | Bỏ sót (FN) | Độ chính xác | Độ bao phủ | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Semgrep riêng | 14 | 7 | 7 | 6 | 0,50 | 0,54 | 0,52 |
| CodeQL riêng | 13 | 11 | 2 | 2 | 0,85 | 0,85 | 0,85 |
| Bandit riêng | 20 | 13 | 7 | 0 | 0,65 | 1,00 | 0,79 |
| Semgrep ∪ CodeQL, đã khử trùng | 18 | 11 | 7 | 2 | 0,61 | 0,85 | 0,71 |
| Hợp mọi nguồn, đã khử trùng | 20 | 13 | 7 | 0 | 0,65 | 1,00 | 0,79 |
| Hợp mọi nguồn, gạn chỉ bằng công cụ mã nguồn mở | 19 | 13 | 6 | 0 | 0,68 | 1,00 | 0,81 |
| **Hợp mọi nguồn, sau gạn (mọi quy tắc)** | 18 | 13 | 5 | 0 | 0,72 | 1,00 | 0,84 |
| Nhóm rà trước (P1+P2), sau gạn | 11 | 11 | 0 | 2 | 1,00 | 0,85 | 0,92 |

**Tác động của bước thẩm định.**

| Nhóm sau thẩm định | Lỗi thật | An toàn |
|---|---:|---:|
| Đã gạn | 0 | 2 |
| — theo G3, bằng chứng nhánh chết của Semgrep CE (mã nguồn mở) | 0 | 1 |
| — theo G1, bằng chứng an toàn của CodeQL | 0 | 2 |
| Giữ, nhóm rà trước P1+P2 | 11 | 0 |
| Giữ, chỉ hạ ưu tiên xuống P3 | 2 | 5 |

Một ứng viên có thể thỏa nhiều quy tắc: ca 01097 thỏa cả G3 lẫn G1, ca 01098 chỉ thỏa G1.

**Đóng góp riêng của từng nguồn.**

| Công cụ | Ứng viên có báo | Chỉ công cụ này báo |
|---|---:|---:|
| Bandit | 20 | 2 |
| Semgrep | 14 | 0 |
| CodeQL | 13 | 0 |

**Cách đọc.**

1. *Phát hiện rộng.* Hợp các nguồn báo đủ 13/13 lỗi thật. Semgrep ∪ CodeQL chỉ đạt 11/13; hai
   lỗi còn lại (00899, 01191) chỉ Bandit báo. Trong tập này Bandit báo mọi lời gọi `subprocess`,
   nên **Bandit riêng đã cho đúng kết quả của tập hợp trước khi gạn** (13 đúng, 7 sai). Phần
   Semgrep và CodeQL đóng góp là thông tin để xếp hạng và gạn, không phải thêm lỗi được phát hiện.
2. *Gạn bằng công cụ mã nguồn mở.* Luật bằng chứng của Semgrep CE gạn 1 trong 7 cảnh báo sai
   (01097: lệnh chỉ nhận dữ liệu đầu vào qua một nhánh có điều kiện hằng không bao giờ chạy) và
   **không gạn nhầm lỗi thật nào**.
3. *Gạn với mọi quy tắc.* Thêm truy vấn bằng chứng của CodeQL thì gạn được 2 trong 7 (thêm 01098:
   đoạn đường dẫn bị route cố định). 5 cảnh báo sai còn lại không có bằng chứng bác bỏ: chúng chỉ
   do rule bắt mẫu `shell=True` báo, CodeQL im lặng, và im lặng không được coi là bằng chứng.
4. *So với đối chứng.* Danh sách sau gạn có độ bao phủ cao hơn CodeQL riêng (1,00 so với 0,85)
   nhưng độ chính xác thấp hơn (0,72 so với 0,85); **F1 xấp xỉ, thấp hơn 0,01** (0,84 so với
   0,85). Quy trình không vượt CodeQL riêng về F1 trên tập này.
5. *Nhóm rà trước.* Nếu người rà chỉ đọc P1 và P2 thì gặp 11 lỗi thật và không gặp cảnh báo sai
   nào; hai lỗi thật còn lại nằm ở P3 cùng 5 cảnh báo sai. Đây là **giảm cảnh báo sai trong nhóm
   rà trước**, không phải loại bỏ chúng.

**Giới hạn riêng của bảng này.** 20 vị trí là mã tổng hợp sinh từ một bộ mẫu, không phải 20 dự
án độc lập. Các cơ chế bằng chứng (nhánh điều kiện hằng, route cố định) được phát triển trên chính
benchmark này. Nhãn là kỳ vọng của tác giả benchmark.

## 3.3 CWE-78 trên JavaScript/TypeScript: đóng góp nguồn và gộp

Nguồn: `curling@0.2.0` và 11 package npm của các đợt phát triển 01–03. Chưa có nhãn đủ để tính độ
chính xác: các đợt trước không xác nhận được cảnh báo sai nào trong phạm vi, và nhãn do assistant
viết chưa có người duyệt. Bảng chỉ cho biết số lượng. Kết quả:
[results/summary.json](../../experiments/evaluation/results/summary.json).

| Package | Cảnh báo thô | Ứng viên | Đã gạn | Chỉ hạ ưu tiên | Semgrep (chỉ riêng) | CodeQL (chỉ riêng) | ESLint (chỉ riêng) | Bandit (chỉ riêng) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `curling@0.2.0` | 7 | 1 | 0 | 0 | — | 1 (0) | 1 (0) | — |
| `execa@10.0.1` | 0 | 0 | 0 | 0 | — | — | — | — |
| `grunt-shell@4.0.0` | 2 | 1 | 0 | 0 | 1 (0) | — | 1 (0) | — |
| `gulp-shell@0.8.0` | 4 | 1 | 0 | 0 | 1 (1) | — | — | — |
| `launch-editor@2.14.1` | 3 | 2 | 0 | 0 | 2 (1) | — | 1 (0) | — |
| `node-gyp@13.0.2` | 71 | 52 | 0 | 50 | 10 (1) | — | — | 51 (42) |
| `node-notifier@10.0.1` | 4 | 1 | 0 | 0 | 1 (0) | 1 (0) | 1 (0) | — |
| `nodemon@3.1.14` | 4 | 4 | 0 | 1 | — | — | 4 (4) | — |
| `npm-run-all@4.1.5` | 0 | 0 | 0 | 0 | — | — | — | — |
| `open@11.0.4` | 0 | 0 | 0 | 0 | — | — | — | — |
| `release-it@21.1.0` | 2 | 2 | 0 | 0 | 1 (1) | — | 1 (1) | — |
| `shelljs@0.10.0` | 3 | 2 | 0 | 1 | 1 (0) | — | 2 (1) | — |
| **Tổng 12 package** | 100 | 66 | 0 | 52 | | | | |

**Cách đọc.**

- `curling@0.2.0` là ca duy nhất có vị trí lỗi đã biết (`lib/curl-transport.js:56`): 7 cảnh báo
  thô (6 của CodeQL, 1 của ESLint) gộp thành **một** ứng viên ở P1.
- Bước gạn **không gạn ứng viên JS/TS nào**: chưa có gói bằng chứng cho JavaScript.
- Tính riêng phần JavaScript (bỏ mã Python của `node-gyp`), 11 package còn lại cho 14 ứng viên:
  9 ứng viên chỉ do một công cụ báo, 5 ứng viên do từ hai công cụ trở lên báo. ESLint báo 11
  ứng viên, trong đó 6 ứng viên không công cụ nào khác báo; CodeQL báo 2 ứng viên và không có
  ứng viên nào chỉ riêng nó báo. Chưa có nhãn nên không biết các ứng viên chỉ một công cụ báo
  là lỗi thật hay cảnh báo sai.
- `node-gyp` kèm mã Python (gyp); Bandit báo 51 lời gọi ở đó, trong đó 42 không công cụ nào khác
  báo. Tất cả ở P3: bị hạ ưu tiên, không bị gạn. Đây là ví dụ thật về lượng cảnh báo mà công cụ
  bắt mẫu sinh ra trên mã thực tế.

## 3.4 Lựa chọn công cụ cho bước gạn

Thử trên cùng snapshot OWASP BenchmarkPython (7 vị trí an toàn, 13 lỗi thật). Hai dòng đầu là kết
quả của lượt quét thật ở mục 3.2; hai dòng thử nghiệm lấy từ
[tool-trials/owasp-benchmarkpython.json](../../experiments/evaluation/tool-trials/owasp-benchmarkpython.json).

| Công cụ | Phiên bản, giấy phép | Loại bằng chứng | Điều kiện gạn | Cảnh báo sai có bằng chứng (trên 7) | Lỗi thật bị gạn nhầm (trên 13) | Chi phí chạy thêm |
|---|---|---|---|---:|---:|---|
| **Semgrep CE, luật nhánh chết** (được chọn) | 1.178.0, LGPL-2.1 | Cặp luật taint đối chứng/bằng chứng: luồng từ dữ liệu request tới lệnh chỉ đi qua phép gán nằm trong nhánh có điều kiện số nguyên hằng không bao giờ chạy | Luật đối chứng báo lệnh, luật bằng chứng không báo; mọi đường đi công cụ khác báo đều qua nhánh đó; bằng chứng CodeQL không mâu thuẫn (G3) | 1 | 0 | 3,6 giây |
| Truy vấn bằng chứng CodeQL | CodeQL 2.27.1 + gói v0.2. Truy vấn và thư viện: MIT. **CLI không phải mã nguồn mở** | Barrier chặn luồng: nhánh điều kiện hằng, đọc phần tử hằng, route cố định | Truy vấn gốc báo, truy vấn có bằng chứng không còn báo, không công cụ nào khác khẳng định luồng (G1) | 2 | 0 | 10,4 giây; dùng lại database, không trích xuất lại |
| Bandit, phân loại lệnh hằng | 1.9.4, Apache-2.0 | `B602`/`B605` ở mức LOW khi đối số lệnh là chuỗi hằng | Cùng với chứng minh lệnh hằng của hệ thống, không ai khẳng định luồng (G2) | 0 | 0 | 1,8 giây |
| Semgrep CE, luật thử "lệnh là hằng" (không dùng) | 1.178.0, LGPL-2.1 | Lan truyền hằng trong hàm | Lệnh khớp mẫu `"..."` | 0 | 0 | 1,4 giây |
| ESLint + eslint-plugin-security | 10.15.0 + 4.2.1, MIT / Apache-2.0 | Không có: chỉ báo `exec()` có đối số không phải hằng | Không dùng để gạn; là nguồn phát hiện | — | — | — |

**Kết luận lựa chọn.**

- Công cụ mã nguồn mở được chọn cho bước gạn là **Semgrep CE**, với luật bằng chứng nhánh chết
  ([rules/semgrep/command-injection-evidence-v0.1/](../../rules/semgrep/command-injection-evidence-v0.1/README.md)).
  Lý do: đầu ra của nó đủ để kiểm tra lại ứng viên (vị trí lệnh, vị trí phép gán chết), nó đã có
  sẵn trong quy trình, và nó bác bỏ được một cảnh báo sai mà không gạn nhầm lỗi thật. Luật đạt
  13/13 ca tổng hợp, gồm 9 ca phải giữ lại.
- Bandit được giữ làm nguồn phát hiện (báo riêng 2 lỗi thật) và cung cấp bằng chứng lệnh hằng
  (G2). Trên dữ liệu đánh giá G2 không gạn ca nào: cả 7 ca an toàn đều truyền lệnh qua biến.
- Truy vấn bằng chứng của CodeQL gạn thêm một ca (01098) mà Semgrep không chứng minh được. Bộ máy
  CodeQL không phải mã nguồn mở; luận văn cần nói rõ phần nào của kết quả đến từ đâu, như hàng
  "gạn chỉ bằng công cụ mã nguồn mở" ở mục 3.2.
- Năm ca an toàn còn lại an toàn vì lý do về giá trị (đọc đúng khóa hằng của dict, `ConfigParser`,
  hàm phụ trả hằng). Không công cụ nào đã thử chứng minh được, nên chúng được giữ.
- Chưa thử: Joern (đồ thị thuộc tính mã, Apache-2.0). Nó cần bước trích xuất riêng và luồng dữ
  liệu của nó không phân biệt khóa dict hay nhánh hằng; dự đoán không xử lý được các ca còn lại,
  nhưng đây là dự đoán, chưa có số đo.

## 3.5 Minh họa bổ sung: CWE-22 trên Python

Bằng chứng an toàn v0.2 của CodeQL cho CWE-22 đã được đánh giá ở giai đoạn nghiên cứu
([research.md §3.3, §3.10](../research.md)). Số liệu dưới đây lấy nguyên từ đó.

| Dữ liệu | Cảnh báo sai được loại | Lỗi thật bị loại nhầm | Ghi chú |
|---|---|---|---|
| OWASP BenchmarkPython, nửa kiểm tra, 4 nhóm lỗi | 49/53 (92,5%) | 0/37 | Hai nửa sinh từ cùng bộ mẫu |
| Mã thật (đợt B và C), nhãn do chủ đề án xác minh | 4/43 (khoảng 9%) | 0/7 | Một người rà, một lượt, không mù |

**Hai cách đọc nhãn mã thật.** Kết quả "không loại nhầm" dựa trên hai giả định gán nhãn: `resolve()`
chạy trước bước kiểm tra không tính là lỗ hổng CWE-22 (P1), và kẻ tấn công không tạo được file
hay symlink (A-SYM). Theo cách đọc thận trọng (coi mọi nhãn phụ thuộc hai giả định này là chưa xác
định), ở đợt C cả 3 cảnh báo v0.2 loại đều thành "chưa xác định", nên không khẳng định được là
không loại nhầm. Luận văn cần trình bày cả hai.

**Chạy lại qua ứng dụng** (profile `path-traversal-v0.2`, cùng commit với nghiên cứu):

| Nguồn | Ứng viên | Danh sách rà chính | Đã gạn | Khớp nghiên cứu |
|---|---:|---:|---:|---|
| `pallets-eco/flask-admin@4f8be45` | 3 | 3 | 0 | Đợt A: 3 cảnh báo, v0.2 loại 0 |
| `pipecat-ai/pipecat@7519c26` | 3 | 0 | 3 | Đợt C: 3 cảnh báo, v0.2 loại 3 |

Trên giao diện, 3 cảnh báo của pipecat nằm ở danh sách "Đã gạn" và mở lại được cùng cảnh báo gốc.

## 3.6 Chi phí thời gian

Một lần đo cho mỗi nguồn, trên máy cá nhân, các công cụ chạy song song từng đôi nên có tranh chấp
CPU. Không dùng các số này để so tốc độ giữa công cụ. Cột CodeQL phân tích cộng cả hai ngôn ngữ
của lượt quét.

| Nguồn | Tổng thời gian lượt quét (giây) | Semgrep | Bandit | ESLint | CodeQL tạo database | CodeQL phân tích | Semgrep luật bằng chứng | CodeQL truy vấn bằng chứng |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `pallets-eco/flask-admin` | 40 | — | — | — | 5,9 | 32,9 | — | — |
| `curling` | 15 | 1,2 | — | 0,4 | 4,5 | 8,2 | — | — |
| `execa` | 16 | 1,3 | — | 0,8 | 5,5 | 8,1 | — | — |
| `grunt-shell` | 13 | 1,2 | — | 0,4 | 4,4 | 7,1 | — | — |
| `gulp-shell` | 14 | 1,2 | — | 0,4 | 4,6 | 7,2 | — | — |
| `launch-editor` | 14 | 1,2 | — | 0,4 | 4,7 | 7,5 | — | — |
| `node-gyp` | 43 | 3,8 | 1,2 | 0,7 | 12,7 | 19,8 | 4,3 | 5,7 |
| `node-notifier` | 17 | 1,4 | — | 0,5 | 5,3 | 9,2 | — | — |
| `nodemon` | 15 | 1,3 | — | 0,5 | 5,0 | 8,2 | — | — |
| `npm-run-all` | 15 | 1,2 | — | 0,5 | 4,7 | 7,7 | — | — |
| `open` | 14 | 1,3 | — | 0,4 | 4,8 | 7,5 | — | — |
| `release-it` | 18 | 1,3 | — | 0,9 | 6,1 | 9,3 | — | — |
| `shelljs` | 15 | 1,3 | — | 0,5 | 4,9 | 7,9 | — | — |
| `OWASP-Benchmark/BenchmarkPython` | 53 | 3,2 | 1,9 | 0,7 | 18,9 | 17,5 | 3,6 | 10,4 |
| `pipecat-ai/pipecat` | 35 | — | — | — | 12,4 | 21,6 | — | — |

**Cách đọc.**

- Hai bước bằng chứng dùng lại dữ liệu sẵn có: luật của Semgrep chạy trên mã nguồn đã giải nén,
  truy vấn của CodeQL chạy trên database đã tạo, không trích xuất lại.
- **Thời gian dao động mạnh giữa các lần chạy.** Cùng nguồn OWASP, một lần đo trước đó trong ngày
  (khi máy đang chạy việc khác) mất 171 giây. Các số ở đây chỉ cho biết bậc độ lớn.
- Bandit, ESLint và Semgrep mỗi công cụ mất vài giây ở mọi nguồn; CodeQL chiếm phần lớn thời
  gian. Cụm từ "quét nhanh" của đề cương đúng với ba công cụ đầu trong các lần đo này.

## 3.7 Kiểm tra độc lập quy mô nhỏ

Giao thức: [independent/PROTOCOL.md](../../experiments/evaluation/independent/PROTOCOL.md), viết
và băm trước khi quét ([PREREGISTRATION.json](../../experiments/evaluation/independent/PREREGISTRATION.json),
13:59 UTC ngày 2026-11-14). Kết quả:
[independent/results/known-sites.json](../../experiments/evaluation/independent/results/known-sites.json).

Ba ứng dụng "cố ý có lỗ hổng" công khai, **chưa từng được dự án quét hay xem**, mỗi cái có một lỗi
chèn lệnh do chính tác giả công bố. Mỗi nguồn quét đúng một lần với profile đã cố định. Nhãn chỉ
gồm vị trí lỗi đã công bố; không có nhãn an toàn.

| Nguồn | Ngôn ngữ | Vị trí đã công bố | Được báo | Công cụ báo | Mức | Bị gạn |
|---|---|---|---|---|---|---|
| `appsecco/dvna@9ba473a` | JavaScript | `core/appHandler.js:39` | Có | CodeQL, ESLint | P1 | Không |
| `stamparm/DSVW@9ca3c9a` | Python | `dsvw.py:31` | Có | Semgrep, Bandit | P3 | Không |
| `snyk-labs/nodejs-goof@add14ba` | JavaScript | `routes/index.js:174` | Có | CodeQL, ESLint | P1 | Không |

| Nguồn | Ứng viên | Chưa có nhãn | Chưa có nhãn, trong danh sách chính | Chưa có nhãn, bị gạn |
|---|---:|---:|---|---:|
| `dvna` | 1 | 0 | — | 0 |
| `DSVW` | 4 | 3 | 3 ở P3 (chỉ Bandit báo, trong thư mục `tests/`) | 0 |
| `nodejs-goof` | 1 | 0 | — | 0 |

**Cách đọc.**

- *Phát hiện:* cả 3/3 vị trí đã công bố đều được báo. Không công cụ nào báo đủ cả ba: CodeQL báo
  2/3 (im lặng ở DSVW, nơi dữ liệu vào qua `http.server`), Semgrep báo 1/3, Bandit báo 1/1 vị trí
  Python, ESLint báo 2/2 vị trí JavaScript. Lỗi thật ở DSVW chỉ có nhờ lấy hợp các nguồn.
- *An toàn của bước gạn:* không vị trí công bố nào bị gạn, và không ứng viên nào khác bị gạn.
- *Xếp hạng:* 2/3 lỗi thật ở P1; lỗi thật ở DSVW ở **P3**, cùng mức với 3 cảnh báo chưa có nhãn
  của Bandit trong mã kiểm thử. Người rà chỉ đọc P1–P2 sẽ bỏ qua lỗi này. Đây là kết quả không
  thuận cho bước xếp ưu tiên: mức P3 phản ánh việc không công cụ nào đưa ra luồng dữ liệu, không
  phản ánh mức nguy hiểm.

**Giới hạn.** Ba nguồn, ba vị trí, chọn có chủ đích; ứng dụng cố ý có lỗ hổng viết lỗi ở dạng dễ
thấy. Không tính được độ chính xác vì không có nhãn an toàn. Giao thức được băm trong cùng phiên
làm việc, chưa công bố bằng commit. Kết quả này **không** thay cho đánh giá trên `pairs-v1`.

## 3.8 Kết luận nào đủ bằng chứng

**Có thể nói, kèm điều kiện "trên dữ liệu phát triển":**

- Trên 20 vị trí CWE-78 của OWASP BenchmarkPython, hợp các nguồn báo đủ 13 lỗi thật, nhiều hơn
  Semgrep ∪ CodeQL (11) và từng công cụ đó chạy riêng.
- Bước gạn bằng công cụ mã nguồn mở (Semgrep CE) loại 1/7 cảnh báo sai; với thêm bằng chứng của
  CodeQL loại 2/7. Cả hai không loại nhầm lỗi thật nào trong 13.
- Sau gạn, nhóm rà trước (P1+P2) gồm 11 lỗi thật và không có cảnh báo sai.
- Gộp theo lời gọi giảm 51 cảnh báo thô xuống 20 mục rà soát mà không mất cảnh báo gốc nào.
- Với CWE-22 trên mã thật: v0.2 loại khoảng 9% cảnh báo sai và không loại nhầm lỗi thật, theo
  nhãn đã xác minh và hai giả định gán nhãn.

**Có thể nói, trên mã chưa từng xem (ba đợt, chỉ nhãn dương tính):**

- Đợt 1 (ba vị trí): hợp các nguồn báo cả ba lỗi chèn lệnh đã công bố; CodeQL chạy riêng bỏ
  sót một lỗi.
- Đợt 2 (43 lượt quét hoàn tất trên 52 package npm có CVE thật): hợp các nguồn báo 32 vị
  trí, CodeQL riêng 27, Semgrep riêng 12, Semgrep ∪ CodeQL 29.
- Đợt 3 (sáu vị trí Python): 6/6 được báo; cùng đợt 1 là 7/7 vị trí Python, CodeQL riêng 5/7.
- Bước gạn không đưa lỗi thật nào ra khỏi danh sách rà chính ở cả ba đợt.

**Chưa thể nói:**

- Quy trình tốt hơn CodeQL chạy riêng: F1 xấp xỉ (0,84 so với 0,85), và chỉ trên 20 vị trí tổng hợp.
- Tỷ lệ gạn 1/7 hay 2/7 đại diện cho mã thật: cơ chế nhánh hằng và route cố định chủ yếu khớp mẫu
  của benchmark. Trên cả ba đợt dữ liệu độc lập, bước gạn không gạn gì.
- Xếp ưu tiên đưa mọi lỗi thật lên trước: một lỗi thật độc lập nằm ở P3.
- Bất kỳ kết luận nào về độ chính xác trên JavaScript/TypeScript hay trên mã thật cho CWE-78.
- Thời gian rà soát của người dùng giảm: chưa có phép đo với người rà.

**Còn thiếu để có đánh giá độc lập đầy đủ, và vì sao chưa làm:**

1. Quét `pairs-v1` bằng profile `command-injection-v0.2`. Việc này **cần chủ đề án quyết định**:
   tập giữ lại chỉ dùng được một lần, và giao thức nghiên cứu yêu cầu công bố giao thức bằng
   commit và push trước khi quét, trong khi mọi thay đổi hiện được giữ ở máy cục bộ. Bộ lưu
   trữ nguồn đã khóa (`artifacts/pair-sources/`) cũng không có trên máy này. Bốn điều kiện
   chặn và các lệnh chạy: [pairs-v1/README.md](../../experiments/evaluation/pairs-v1/README.md).
2. Nhãn cho các ứng viên ngoài vị trí CVE đã biết, hoặc một mẫu ngẫu nhiên có người rà, để tính
   được độ chính xác và số cảnh báo sai được gạn đúng trên mã thật.
