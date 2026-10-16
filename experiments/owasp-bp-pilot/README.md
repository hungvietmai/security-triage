# Thí điểm BenchmarkPython — Semgrep CE, CodeQL, Bandit (nửa phát triển)

Ngày chạy: 2026-10-15. Phần 1 chỉ báo cáo nửa phát triển; nửa kiểm tra chỉ được chạy một lần ở Phần 2, sau khi đóng băng v0.1.

## Thiết lập

- Dữ liệu: OWASP BenchmarkPython 0.1, commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`,
  4 CWE: 22, 78, 79, 643 (463 ca).
- Chia tập: `split.json` (sha256 `2f00d6c3…7998`), phân tầng theo (CWE, nhãn), thứ tự
  `sha256("security-triage/owasp-bp-split-v1/" + tên ca)`, nửa đầu là phát triển.
  Nửa phát triển: **235 ca — 82 lỗi, 153 an toàn**.
- Semgrep 1.178.0: toàn bộ 61 rule cộng đồng Python (`semgrep-rules@a84ff9c`) có CWE 22/78/79/643
  trong metadata (`semgrep_rules.json`): CWE-78 có 20 rule taint + 13 rule mẫu, CWE-79 có 6 taint + 17
  mẫu, CWE-22 có 5 rule mẫu, **CWE-643 không có rule nào**.
- CodeQL 2.27.1, `python-queries` 1.8.11, bộ `python-security-extended`.
- Bandit 1.9.4, chỉ tính cho CWE-78.
- Cách tính: một công cụ "báo" một ca khi có cảnh báo trong file của ca đó với rule ánh xạ đúng CWE
  của ca (quy ước chấm điểm OWASP). Đơn vị là (ca, CWE).

## Kết quả theo từng công cụ

| CWE | Lỗi/An toàn | Semgrep TP/FP/FN | CodeQL TP/FP/FN | Hợp S∪Q TP/FP/FN | CodeQL P / R / FPR |
|---|---|---|---|---|---|
| 22 | 33 / 52 | 1 / 0 / 32 | 24 / 31 / 9 | 24 / 31 / 9 | 0.44 / 0.73 / 0.60 |
| 78 | 7 / 4 | 7 / 4 / 0 | 5 / 2 / 2 | 7 / 4 / 0 | 0.71 / 0.71 / 0.50 |
| 79 | 16 / 29 | 0 / 12 / 16 | 0 / 6 / 16 | 0 / 12 / 16 | 0.00 / 0.00 / 0.21 |
| 643 | 26 / 68 | 0 / 0 / 26 | 9 / 22 / 17 | 9 / 22 / 17 | 0.29 / 0.35 / 0.32 |
| **Tổng** | 82 / 153 | 8 / 16 / 74 | 38 / 61 / 44 | 40 / 69 / 42 | 0.38 / 0.46 / 0.40 |

Bandit trên CWE-78: 7 / 4 / 0, trùng hoàn toàn với Semgrep.

## Bảng tám ô

| CWE | Chỉ S: lỗi / an toàn | Chỉ Q: lỗi / an toàn | Cả hai: lỗi / an toàn | Không ai: lỗi / an toàn |
|---|---|---|---|---|
| 22 | 0 / 0 | 23 / 31 | 1 / 0 | 9 / 21 |
| 78 | 2 / 2 | 0 / 0 | 5 / 2 | 0 / 0 |
| 79 | 0 / 6 | 0 / 0 | 0 / 6 | 16 / 17 |
| 643 | 0 / 0 | 9 / 22 | 0 / 0 | 17 / 46 |
| **Tổng** | **2 / 8** | **32 / 53** | **6 / 8** | **42 / 84** |

## Nguyên nhân (đọc mã nguồn, chỉ tập phát triển)

**FP của CodeQL (53 ca chỉ-CodeQL ở CWE-22 + 643)** gần như đều thuộc các mẫu sinh của benchmark:
nhánh điều kiện hằng (`7 * 18 + num > 200`, `match` trên ký tự hằng, `'should' not in TestParam`),
lấy phần tử hằng của list sau `pop(0)` (`lst[1]`), và điều kiện chặn: kiểm tra `'../' in bar`,
`resolve()` + `startswith`, kiểm tra hoặc `replace` dấu nháy trong XPath. Theo bộ gắn nhãn regex
(`mechanisms.py`, chỉ là công cụ hỗ trợ rà soát): 30/31 FP của CWE-22 và 15/22 FP của CWE-643 khớp ít
nhất một mẫu. Nhưng các mẫu `match`/dict cũng xuất hiện ở ca lỗi thật, nên chỉ có phép tính giá trị
chính xác mới phân biệt được; regex không thể dùng làm luật loại.

**Semgrep không cung cấp bằng chứng nào ở CWE-22 và CWE-643**: không có rule cho XPath, và các rule
path traversal chỉ bắt mẫu `open(request...)` trực tiếp.

**CWE-79: cả hai công cụ đều có recall 0.** Benchmark khai báo route bên trong `init(app)` với `app`
là tham số, nên CodeQL không nhận ra giá trị trả về của handler là HTTP response. Cả 12 FP còn lại đều
là `make_response((text, {header: bar}))`: dữ liệu vào header, không vào body.

**2 TP chỉ Semgrep thấy ở CWE-78** (00899, 01191) đọc tham số qua `helpers.separate_request.request_wrapper`.
CodeQL không mô hình hóa nguồn qua lớp bọc này, nên việc CodeQL im lặng ở đây **không** mang thông tin.

## Kiểm tra điều kiện dừng (tính bổ trợ Semgrep–CodeQL)

| Nhóm ứng viên | Số ca | Ghi chú |
|---|---:|---|
| FP chỉ-CodeQL mà Semgrep cung cấp được bằng chứng an toàn | **0** | Semgrep im lặng ở CWE-22/643 |
| FP chỉ-Semgrep, CodeQL im lặng (ứng viên F′) | 8 | 2 ở CWE-78, 6 ở CWE-79 (header) |
| TP chỉ-Semgrep có cùng dạng "CodeQL im lặng" | 2 | Ở CWE-78; F′ sẽ loại nhầm nếu không kiểm tra độ phủ nguồn |
| FP chỉ-CodeQL khớp mẫu có thể loại bằng điều kiện trong chính CodeQL | khoảng 45 / 53 | Thuộc về cấu hình E, không phải F |

**Kết luận thí điểm:** với rule cộng đồng, gần như toàn bộ khả năng giảm FP nằm ở **bằng chứng an toàn
bổ sung cho CodeQL** (cấu hình E). Bằng chứng chéo từ Semgrep chỉ ảnh hưởng tối đa 8 FP, đều ở
CWE-78/79, và đi kèm rủi ro loại nhầm 2 TP. Điều kiện dừng của hướng F (ít ứng viên, tập trung ở ít
CWE) đã bị chạm.

## Thời gian (tham khảo, các công cụ chạy song song nên có tranh chấp CPU)

Semgrep khoảng 258 s, Bandit khoảng 10 s, tạo CodeQL database khoảng 91 s, chạy truy vấn CodeQL 39 s.
Chưa dùng làm số liệu đánh giá thời gian.

## Tệp

- `scripts/run.sh`, `make_split.py`, `evaluate.py`, `mechanisms.py`
- `split.json`, `semgrep_rules.json`, `pilot_development.json` (chỉ tập phát triển, kèm danh sách cảnh báo
  từng ca), `mechanisms_development.json`
- SARIF/JSON thô ở `artifacts/owasp-bp-pilot/` (không commit)

---

# Phần 2 — Tầng bằng chứng an toàn CodeQL v0.1

## Cách làm

`ql/SafetyEvidence.qll` định nghĩa 5 cơ chế bằng chứng, gắn làm **sanitizer bổ sung** vào đúng các
truy vấn mặc định (`PathInjection`, `CommandInjection`, `ReflectedXss`, `XpathInjection`).
`ql/gen.py` sinh 28 truy vấn: 4 CWE × {none, constbranch, collection, guard, route, header, all}.
Biến thể `none` cho đúng số kết quả của truy vấn mặc định (125/13/7/59): dùng làm phép kiểm tra.

| Cơ chế | Nội dung |
|---|---|
| constbranch | Mã không bao giờ chạy do điều kiện if / if-expression / match tính ra hằng (số nguyên có chặn, chuỗi, chỉ số hằng vào chuỗi hằng) |
| collection | Đọc phần tử list/dict cục bộ mà giá trị là hằng, bằng mô phỏng tuần tự `append`/`pop`/gán theo khóa |
| guard | `'..' in x` / `"'" in x` bị từ chối; đường dẫn đã chuẩn hóa (`resolve`/`realpath`) kiểm tra bằng `startswith`; `replace` dấu nháy trước XPath |
| route | Đoạn `request.path.split('/')[k]` bị cố định bởi route literal của handler |
| header | Giá trị ở vị trí header/status của tuple response Flask (không thuộc body) |

Bộ quyết định (`scripts/evaluate_evidence.py`): cảnh báo CodeQL bị đề xuất loại khi biến thể `all`
không còn luồng; cảnh báo Semgrep taint luôn giữ; cảnh báo Semgrep theo mẫu chỉ bị loại khi CodeQL
có báo ca đó và bằng chứng loại hết luồng (ghép ở cấp ca, là xấp xỉ); cảnh báo chỉ-Semgrep được giữ
(F′ chưa triển khai).

Phát triển trên nửa phát triển. Một chỉnh sửa sau lần chạy đầu: coi receiver của `resolve()`/`realpath()`
không phải truy cập file nguy hiểm khi kết quả được kiểm tra `startswith` (5 FP cuối của CWE-22).
Sau đó **đóng băng v0.1** (`FREEZE_v0.1.sha256`) và chạy nửa kiểm tra **một lần**.

## Kết quả (TP / FP / FN, precision, recall)

| Cấu hình | Phát triển (82 lỗi / 153 an toàn) | Kiểm tra (78 lỗi / 150 an toàn) |
|---|---|---|
| A — Semgrep | 8 / 16 / 74 — P 0.33, R 0.10 | 7 / 9 / 71 — P 0.44, R 0.09 |
| B — CodeQL mặc định | 38 / 61 / 44 — P 0.38, R 0.46 | 37 / 53 / 41 — P 0.41, R 0.47 |
| C — A ∪ B | 40 / 69 / 42 — P 0.37, R 0.49 | 37 / 59 / 41 — P 0.39, R 0.47 |
| **E — CodeQL + bằng chứng** | **38 / 0 / 44 — P 1.00, R 0.46** | **37 / 0 / 41 — P 1.00, R 0.47** |
| F — C + bộ quyết định | 40 / 8 / 42 — P 0.83, R 0.49 | 37 / 6 / 41 — P 0.86, R 0.47 |

Tập kiểm tra theo CWE (E): CWE-22 21/0/11, CWE-78 6/0/0, CWE-79 0/0/15, CWE-643 10/0/15.
**TP bị mất do bằng chứng: 0 ở cả hai nửa.**

Quy công (số FP của B được loại khi chỉ bật một cơ chế; các cơ chế chồng lấn nên tổng > 53):

| Cơ chế | Phát triển | Kiểm tra |
|---|---:|---:|
| guard | 32 | 27 |
| constbranch | 24 | 15 |
| route | 11 | 8 |
| collection | 10 | 8 |
| header | 6 | 1 |
| tất cả | 61 / 61 | 53 / 53 |

## Diễn giải và giới hạn

- **Gần như toàn bộ hiệu quả đến từ E** (bằng chứng viết trong CodeQL). Đưa Semgrep vào (F) thêm
  2 TP ở phát triển nhưng 0 ở kiểm tra, trong khi thêm 8 và 6 FP chỉ-Semgrep. Khi chưa có F′, việc
  kết hợp Semgrep **làm giảm** precision.
- **Nửa kiểm tra không đo được khả năng tổng quát sang dạng mã mới.** BenchmarkPython sinh từ một tập
  mẫu chung; chia theo hash tên ca không tách mẫu, nên hai nửa dùng chung các mẫu nguồn → sink. Kết quả
  kiểm tra chỉ xác nhận v0.1 không "học thuộc" từng ca cụ thể. Precision 1.00 **không** phải ước lượng
  cho code thật.
- constbranch và route chủ yếu là mẹo của bộ sinh benchmark; guard (kiểm tra `..`, chuẩn hóa +
  `startswith`, thoát dấu nháy) là dạng phổ biến ở code thật. Cần kiểm chứng trên dự án thật.
- Recall không đổi vì tầng này chỉ loại; FN của CodeQL (CWE-79 do route trong `init(app)`, CWE-643 và
  22 do lớp bọc `helpers.separate_request`) nằm ngoài phạm vi giảm FP.
- Đánh giá ở cấp (ca, CWE); chưa có nhãn ở cấp cảnh báo.

Tệp thêm: `ql/` (thư viện, bộ sinh, qlpack), `scripts/evaluate_evidence.py`, `evidence_development.json`,
`evidence_test.json`, `FREEZE_v0.1.sha256`. SARIF của 28 biến thể ở `artifacts/owasp-bp-pilot/evidence.sarif`.

---

# Phần 3 — Bộ phản ví dụ và v0.2

## Bộ phản ví dụ (`counterexamples/`)

47 hàm Flask nhỏ, viết từ ngữ nghĩa của từng điều kiện an toàn (không từ đáp án OWASP). Mỗi hàm tên
`<cơ chế>_<id>_bad` (bắt buộc vẫn bị báo) hoặc `_good` (an toàn, được phép loại). `scripts/evaluate_cex.py`
so truy vấn mặc định với biến thể `all`:

- **UNSOUND**: ca nguy hiểm bị bằng chứng loại (phải bằng 0);
- **VACUOUS**: ca nguy hiểm mà CodeQL mặc định cũng không báo (ca thử không kiểm tra được gì);
- **MISSED**: ca an toàn vẫn bị báo (bỏ lỡ, chấp nhận được).

| Phiên bản | UNSOUND | MISSED | VACUOUS | ok |
|---|---:|---:|---:|---:|
| v0.1 (đóng băng) | **10** | 4 | 2 | 31 |
| v0.2 | **0** | 4 | 2 | 41 |

10 lỗi loại nhầm của v0.1:
- `startswith` không có dấu phân cách (2: dạng `abort` và dạng `return`; receiver của `resolve()` bị chặn cả lan truyền);
- `..` + `os.path.join` / pathlib `/` với đường dẫn tuyệt đối (2);
- route bị handler khác gọi;
- tuple trả về từ hàm phụ;
- nháy XPath sai loại (2);
- giá trị nằm ngoài literal;
- thay nháy bằng chuỗi lại chứa nháy.

4 ca MISSED của v0.2 đều kết thúc guard bằng `abort()`: CodeQL không coi `abort()` là không trả về,
nên guard không chi phối sink. Đây là giới hạn đã biết, theo hướng an toàn.
2 ca VACUOUS (`lst[0] = x`, `dict.update`) không được CodeQL mặc định theo dõi.

## Thay đổi v0.1 → v0.2 (`ql_v02/`, `FREEZE_v0.2.sha256`)

| Cơ chế | v0.2 |
|---|---|
| guard `..` | Chỉ khi giá trị được ghép sau một literal kết thúc bằng `/` (f-string, `+`, `"".join`); không áp cho `os.path.join` / pathlib `/` |
| guard chứa | `startswith(base + os.sep)`, `startswith(f"{base}/")` hoặc `is_relative_to(base)` trên đường dẫn đã chuẩn hóa; receiver của `resolve()` là **loại trừ sink**, không còn là barrier |
| guard nháy XPath | Từ chối/thay đúng loại nháy bao literal ở **cả hai phía** giá trị; chuỗi thay thế không chứa nháy đó |
| header | Chỉ tuple trong `make_response(...)` hoặc tuple `return` từ hàm có route |
| route | Mọi lời gọi tới handler phải từ handler có cùng đoạn route |
| bằng chứng | `table/Evidence.ql` xuất bảng: file, dòng, hàm, CWE, cơ chế, loại bằng chứng, vai trò (barrier / loại trừ sink) |

Lưu ý tái lập: `codeql database analyze` dùng lại kết quả đã cache khi đường dẫn truy vấn không đổi.
Mọi lần chạy v0.2 dùng `--rerun`. Kết quả v0.1 ở Phần 2 không bị ảnh hưởng (lần chạy lại CWE-22 ở
thư mục truy vấn khác; đã kiểm lại).

## BenchmarkPython với v0.2 (CodeQL + bằng chứng, cấu hình E)

| | v0.1 TP / FP | v0.2 TP / FP | Precision v0.1 → v0.2 |
|---|---|---|---|
| Phát triển | 38 / 0 | 38 / 5 | 1.00 → 0.88 |
| Kiểm tra | 37 / 0 | 37 / 4 | 1.00 → 0.90 |

Mốc CodeQL mặc định: phát triển 38 / 61 (P 0.38), kiểm tra 37 / 53 (P 0.41). **TP bị mất: 0 ở cả hai nửa.**
Theo CWE ở nửa kiểm tra: CWE-22 FP 34 → 4, CWE-643 18 → 0, CWE-79 1 → 0, CWE-78 0 → 0.

**Nhóm "nhãn OWASP còn tranh cãi"** (`disputed_v02.json`): cả 9 FP còn lại (5 phát triển + 4 kiểm tra)
đều dùng `str(p).startswith(str(testfiles))` không có dấu phân cách. OWASP gán nhãn an toàn, nhưng về
ngữ nghĩa thì một thư mục anh em cùng tiền tố (ví dụ `testfiles-x`) vượt qua được phép kiểm tra này.
v0.2 giữ các cảnh báo này và báo riêng; không coi là FP của công cụ, cũng không âm thầm loại.

Quy công ở nửa kiểm tra (FP của CodeQL được loại khi chỉ bật một cơ chế): guard 23, constbranch 15,
route 8, collection 8, header 1; tất cả 49/53.

Bảng bằng chứng toàn benchmark (`artifacts/owasp-bp-pilot/evidence_table_v02.csv`, cả hai nửa và mọi file): constbranch 4060,
route 448, collection 264, guard 94 (dotdot 24, từ chối nháy 34, thay nháy 36), header 16. Mỗi dòng là một
nút được chặn, nên một đoạn mã có thể sinh nhiều dòng.

## Còn lại

- v0.2 mới chỉ chứng minh không loại nhầm trên bộ phản ví dụ tự viết; chưa kiểm chứng trên dự án thật.
- Bộ quyết định F vẫn tính bằng chênh lệch giữa các biến thể; bảng bằng chứng đã có nhưng chưa nối vào
  bản ghi quyết định cho từng cảnh báo.
- Semgrep: F vẫn kém E (thêm 6–8 FP chỉ-Semgrep); đã tạm dừng theo kế hoạch.

## Ghi chú định dạng sau đóng băng

Sau khi đóng băng, các script được định dạng bằng ruff 0.16.9 (không đổi logic). Đã chạy lại và đối chiếu:
`split.json`, `pilot_development.json`, `mechanisms_development.json`, kết quả v0.1/v0.2 cả hai nửa và các
truy vấn sinh ra giống hệt từng byte; bộ phản ví dụ (đổi số dòng) được dựng lại database và cho cùng kết quả
(v0.1: 10 loại nhầm, v0.2: 0). Hash sau định dạng:

- `scripts/evaluate.py` f3791bdbad08e412d455f690ca4e1e5a307e3744cbcc6efdddc92c16484c46ec
- `scripts/evaluate_evidence.py` d44bf24be907c977b8ff6bdc8c0c8a596cc0deb355f642e71dea163b6e781a98
- `scripts/evaluate_cex.py` 3d824a61cf680b075f6b14fdbffc511f3fafcb24d392d8f97e7420e2c4f66e6a
- `ql/gen.py` f0525371fca7caef71fb878d2569472aaeb49d3c9307651ba3abe3b4b86f34ef
- `ql_v02/gen.py` 4e8eb475efe84a9f90e16aeb543db209f9c621c7b911a3d3205e077b8b9943b6

`scripts/evaluate_evidence.py` cũng đã được thêm tham số đường dẫn SARIF sau lúc đóng băng v0.1 (để chạy v0.2);
đầu ra v0.1 với tham số mặc định không đổi.
