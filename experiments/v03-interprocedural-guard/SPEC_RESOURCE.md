# Đặc tả bổ sung — hợp đồng gốc suy ra từ tài nguyên (`resource-derived`), một vòng có điều kiện dừng

Ngày 2026-10-20. Bổ sung cho `SPEC.md` mục 4.0; không sửa quy tắc nào khác. Đường cơ sở `strict` là v0.3 đã đóng băng
trong `FREEZE_v0.3_strict.sha256` (lưu trữ `artifacts/v03/v03_strict_baseline.tar.gz`, sha256 `789b426a…c240`).

## 1. Mức bằng chứng và hai chế độ

| Mức | Nguồn `AllowedRoot` | Chế độ dùng |
|---|---|---|
| `proved` | hợp đồng khai báo độc lập (`sinkAllowedRoot`); hợp đồng cục bộ của một phép kiểm tra containment trên chính giá trị tới sink (SPEC 4.0, mức B — ranh giới viết tường minh trong mã, ngữ nghĩa phép kiểm tra đã xác minh) | `strict` và `scoped` |
| `scoped` | hợp đồng tài nguyên (mục 2) | chỉ `scoped` |
| `unknown` | không có | giữ cảnh báo |

`strict` = truy vấn `cwe22_v03.ql` (rule `st/cwe-22/v03`); `scoped` = `cwe22_v03s.ql` (`st/cwe-22/v03s`). Báo cáo đếm riêng cảnh báo
bị loại theo mức. Chuỗi tập con mở rộng thành `R_v03s ⊆ R_v03 ⊆ R_v0.2 ⊆ R_mặc định`.

Ghi chú phân loại: hợp đồng cục bộ (gốc của `safe_join(B, p)`, `resolve(p).is_relative_to(B)`) được xếp vào `proved` như
đã chấp thuận ở vòng trước; nó là một phần của đường cơ sở `strict` đã đóng băng.

## 2. Gốc tài nguyên

Một biến cấp module `R` là **gốc tài nguyên** với giá trị `r` khi đồng thời:

1. **Nguồn gốc phía máy chủ.** `R` được gán đúng một lần ở cấp module bằng một biểu thức gốc: giá trị T1 tĩnh (SPEC mục 3),
   hoặc `tempfile.gettempdir()` nối với ít nhất một đoạn hằng (giá trị ký hiệu `$TMPDIR/<đoạn>…`). Với `$TMPDIR`: không có
   phép ghi `tempfile.tempdir`, không có phép ghi biến môi trường `TMPDIR`/`TEMP`/`TMP` với khóa hằng (`os.environ[…] =`,
   `os.putenv`, `os.environ.setdefault`).
2. **Ổn định, tuyệt đối, chuẩn hóa, khác `/`.** Không có phép gán lại, ghi qua thuộc tính, `setattr`, `globals()`/`exec`
   (T2). Giá trị T1 thỏa T3/T4; giá trị `$TMPDIR/…` có ít nhất một đoạn riêng, mỗi đoạn khác rỗng, `.`, `..`. Giả định
   A-SYM áp dụng, mở rộng cho thư mục tạm (S-TMP).
3. **Bằng chứng là kho tài nguyên của chính ứng dụng.**
   - (a) Chương trình **tạo** đúng thư mục `R`: `R.mkdir(…)`, `os.makedirs(R, …)` hoặc `os.mkdir(R, …)`.
   - (b) **Mọi** lần dùng `R` là một lần dùng kiểu kho: tạo, kiểm tra tồn tại (`R.exists()`, `R.is_dir()`,
     `os.path.exists/isdir(R)`), làm gốc phép nối (`R / x`, `os.path.join(R, x)`), hoặc `dir=R` của
     `tempfile.mkstemp/mkdtemp/NamedTemporaryFile/TemporaryDirectory`. `R` không được module khác đọc
     (`from m import R`, `m.R`, `from m import *`).
   - (c) Tên trong kho là **một đoạn**: giá trị nối vào `R` mang `Segment` (kho phẳng). Một tên nhiều đoạn (`SafeRel`)
     không được: nó có thể vào một kho khác lồng bên trong `R`.
4. Giá trị tới sink là `R / s` hoặc `os.path.join(R, s)` với `s` mang `Segment` (`ProvenContained(·, r)`, cách `join-segment`),
   có thể qua giá trị trả về của một hàm có đúng một `return` (tóm tắt biến đổi, SPEC 4.3 (b)).
5. Không có hợp đồng khai báo phủ sink đó (hợp đồng khai báo là căn cứ duy nhất khi có).
6. Không còn đường dữ liệu chưa kiểm chứng tới sink: sự kiện là tính chất bắt buộc của chính đối số tại sink (SPEC mục 5).

Điều kiện 3 **không** được thay bằng việc chỉ thấy `join(B, v)`: phép nối là điều kiện 4, không phải bằng chứng kho.

## 3. Giả định của mức `scoped` (công bố, không chứng minh)

- **S-PURPOSE.** Một thư mục ứng dụng tự tạo và chỉ dùng như kho phẳng là thư mục sink được phép truy cập. Đây là giả định
  về mục đích của ứng dụng, không phải chứng minh phân quyền.
- **S-TEST.** Mã kiểm thử không chạy trong môi trường triển khai. Ở mức `scoped`, phép gán và lần dùng trong tệp kiểm thử
  (thư mục `test/`, `tests/`, `testing/`; `test_*.py`, `*_test.py`, `conftest.py`) không được xét cho điều kiện 1–3.
  `strict` vẫn xét toàn chương trình. (mlflow: `tests/server/assistant/test_session.py` gán lại `SESSION_DIR`.)
- **S-TMP.** Không người dùng cục bộ nào khác tạo được mục trong thư mục tạm (mở rộng A-SYM; `/tmp` dùng chung là nơi tấn
  công symlink cổ điển, nằm ngoài mô hình đe dọa "kẻ tấn công điều khiển dữ liệu request").
- **S-ENV.** Biến môi trường không bị đặt từ dữ liệu không tin cậy qua khóa không phải hằng.

## 4. Phạm vi của vòng này

Chỉ thêm quy tắc gốc tài nguyên. Không mở rộng tham số hay thuộc tính tổng quát; không áp cho phép nối với tên nhiều đoạn;
`strict` không đổi. RC-M1 không dùng để phát triển quy tắc này cho tới khi xác định được điều kiện tin cậy của gốc artifact
(SPEC mục 6). Django `document_root`, `werkzeug.safe_join` và đối số từ khóa ghi vào danh sách MISSED kỹ thuật.

## 5. Phản ví dụ (`counterexamples/resources.py`, `counterexamples_tmpdir/`)

Kỳ vọng trong `expectations/resources_expectations.csv`, khóa trước lần chạy đầu. `scoped` được phép loại chỉ ba ca an
toàn có gốc tài nguyên hợp lệ; mọi ca khác giữ ở cả hai chế độ.

| Ca | Tình huống | `strict` | `scoped` |
|---|---|---|---|
| `res_1_good` | gốc `$TMPDIR/cex-sessions`, tạo bằng `mkdir`, tên UUID, qua hàm trả về một `return` | keep (không hợp đồng) | may |
| `res_2_good` | gốc hằng `/srv/store` | keep | may |
| `res_11_good` | gốc chỉ bị gán lại trong mã kiểm thử (S-TEST) | keep | may |
| `res_3_bad` | gốc bị gán lại từ request (`global`) | keep | keep |
| `res_4_bad` | gốc lấy từ cấu hình do request khác ghi | keep | keep |
| `res_5_good` | gốc chỉ được nối, không bao giờ được tạo | keep | keep |
| `res_6_good` | gốc còn được đưa cho mã khác (`shutil.rmtree`) | keep | keep |
| `res_7_bad` | tên nhiều đoạn vào kho `SECRETS` lồng trong `STORE` (nhiều gốc cạnh tranh) | keep | keep |
| `res_8_bad` | hợp đồng khai báo cho sink yêu cầu `/srv/other` (xung đột) | keep | keep |
| `res_9_good` | chính thư mục tạm, không có đoạn riêng | keep | keep |
| `res_10_bad` | gốc bị ghi qua thuộc tính từ module khác | keep | keep |
| `tmp_1_bad` | `tempfile.tempdir` bị đặt từ request trước khi module kho được nạp | keep | keep |

Bộ v0.3 cũ (`ipg_*`) được chạy ở cả hai chế độ với cùng bảng kỳ vọng: `scoped` không được đổi kết quả nào của nó.

## 6. Điều kiện dừng (đặt trước khi chạy)

| Tiêu chí | Yêu cầu |
|---|---|
| Phản ví dụ nguy hiểm | 0 UNSOUND ở cả hai chế độ |
| Phản ví dụ an toàn | báo đủ MISSED |
| RC-M6 | giữ hai cảnh báo |
| Chuỗi tập con | luôn đạt |
| Hợp đồng suy ra | bằng chứng (nơi tạo, các lần dùng) và giả định cho từng trường hợp |
| RC-M3 | báo số FP loại được ở `strict` và `scoped` |
| RC-M1 | không tự động loại |
| BenchmarkPython | không mất TP so với đường cơ sở |

Nếu sau đúng một vòng không có hợp đồng tài nguyên đủ chặt để loại cảnh báo nào, chuyển sang hướng 2: đóng băng v0.3 với
kết quả thực tế, ghi rõ nguyên nhân và chuyển sang thiết kế đánh giá. Không có quy tắc riêng cho mlflow.

## 7. Kết quả của vòng (2026-10-20)

`scripts/run_cex.sh` → `results/cex_resource_round.json`; `scripts/run_dev.sh` → `results/dev_resource_round.json`. Bảng kỳ
vọng khóa trước lần chạy đầu (`EXPECTATIONS.sha256`).

| Tiêu chí | Kết quả |
|---|---|
| Phản ví dụ nguy hiểm | 0 UNSOUND, 0 VACUOUS ở cả hai chế độ: bộ ipg (bốn kịch bản), bộ tài nguyên, bộ `tmpdir` |
| Phản ví dụ an toàn | `scoped` loại đúng `res_1_good`, `res_2_good`, `res_11_good`; MISSED duy nhất là `ipg_11_good` (validator `bool`, ngoài phạm vi), ở cả hai chế độ |
| `scoped` không đổi bộ ipg | kết quả từng ca của `scoped` trùng `strict` ở cả bốn kịch bản |
| `strict` so với đường cơ sở đóng băng | trùng từng ca: bộ ipg (bốn kịch bản) và bộ pilot |
| RC-M3 (8 FP) | `strict` loại 0; `scoped` loại 8/8, mỗi cảnh báo có gốc `$TMPDIR/mlflow-assistant-sessions`, bằng chứng tạo ở `session.py:148`, `:195`, tên là UUID một đoạn |
| RC-M6 (2) | giữ 2/2 ở cả hai chế độ |
| RC-M1 (7) | giữ 7/7 ở cả hai chế độ |
| TP/unknown khác | mlflow 4/4, Django 4/4 giữ ở cả hai chế độ |
| Chuỗi tập con | đạt mọi lượt; mlflow `v03s` 18 ⊆ `v03` 26 ⊆ v0.2 26 ⊆ mặc định 27 |
| BenchmarkPython | không mất TP ở cả hai chế độ (CWE-22 cấu hình E: phát triển TP 24, FP 5; kiểm tra TP 21, FP 4) |

Trong mlflow, chỉ `SESSION_DIR` thỏa điều kiện gốc tài nguyên; các hằng đường dẫn khác bị loại vì "never created",
"non-store use" hoặc "imported" (`V03Resources.ql`). Django và BenchmarkPython: không có gốc tài nguyên, không cảnh báo nào
bị loại.

**Đánh giá trung thực.** Quy tắc thỏa mọi điều kiện dừng, nên theo §6 hướng 3 đáng tiếp tục. Nhưng:

- Tám FP RC-M3 thuộc tập phát triển và đã được xem khi thiết kế quy tắc: đây là kết quả phát triển, **không** phải bằng
  chứng kiểm chứng độc lập.
- Việc loại tám FP này **phụ thuộc** vào các giả định `scoped`: S-TEST (mã kiểm thử của mlflow gán lại `SESSION_DIR`;
  không có S-TEST thì gốc không ổn định), S-TMP (kho nằm trong thư mục tạm dùng chung), S-PURPOSE. Ở `strict`, không cảnh
  báo nào được loại.
- Manifest `FREEZE_v0.3_strict.sha256` có một dòng của `.ruff_cache/` (tệp cache, đã nằm trong `.gitignore`); dòng đó
  không thuộc đường cơ sở.
