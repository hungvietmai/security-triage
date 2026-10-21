# Đặc tả v0.3 — kiểm chứng guard liên thủ tục chặn bằng ngoại lệ (CWE-22, Python)

Trạng thái: đã sửa theo vòng duyệt thứ hai (2026-10-16), quyết định về ca 17 và quyết định về nguồn hợp đồng
(2026-10-20). Mức A, cả ba bước (a) `Segment`, (b) `SafeRel`, (c) `Contained`, đã cài đặt (`ql/`).

Thay đổi ở vòng duyệt thứ nhất:
1. Chỉ loại cảnh báo khi trạng thái an toàn **phù hợp với thao tác của sink và đúng thư mục gốc tin cậy** (mục 3, 4.0).
2. Dạng hội của validator: mọi khả năng trả về bình thường phải **độc lập** chứng minh an toàn cho **cùng** thư mục gốc
   (mục 4.2).
3. Chỉ bảo toàn trạng thái qua phép biến đổi **đã có tóm tắt chứng minh**; không mặc định mọi lời gọi hàm (mục 4.3).
4. Tách quy tắc duyệt thư mục và symlink khỏi lõi v0.3; để sang chặng 2 (mục 4.3, 6, 9).

Thay đổi ở vòng duyệt thứ hai:
5. `trusted_root` cần nguồn gốc tin cậy được chứng minh, giá trị ổn định, tuyệt đối đã chuẩn hóa và khác `/`; "không bị
   nhiễm bởi nguồn đang xét" chỉ là điều kiện cần (mục 3, `ipg_24_bad`).
6. Bỏ phép nối f-string/cộng chuỗi với tiền tố `B` khỏi chặng 1; chỉ công nhận `os.path.join(B, v)` và `Path(B) / v`
   (mục 4.3, `ipg_22_bad`).
7. Tách sự kiện `Contained` đúng về toán học khỏi quyết định loại: `Contained(v, "/")` không bao giờ loại cảnh báo
   (mục 4.0, 4.1, `ipg_23_bad`, `ipg_13_good`).
8. Giả định symlink A-SYM ghi rõ, kể cả symlink có sẵn; mọi lần loại dựa trên kiểm tra từ vựng phụ thuộc A-SYM (mục 2).
9. Tiêu chí chấp nhận thêm chuỗi tập con `R_v0.3 ⊆ R_v0.2 ⊆ R_mặc định` (mục 1, 8).

Thay đổi sau quyết định về ca 17:
10. Gốc mà sink được phép truy cập là **hợp đồng khai báo độc lập** (`sinkAllowedRoot`, qua model pack), không mặc định là
    gốc dùng để dựng đường dẫn; không có hợp đồng ⇒ giữ cảnh báo (mục 4.0, `ipg_17_bad`, `ipg_14_good`).
11. Hai mức: A — lõi chứng minh với T1 nghiêm ngặt; B — mở rộng nguồn gốc tin cậy có kiểm chứng (mục 6, 9).
12. Cài đặt: sự kiện là tính chất bắt buộc của nút CFG/SSA, không dùng trạng thái luồng (mục 4.2–4.4, 5).

Thay đổi sau quyết định về nguồn hợp đồng (2026-10-20), thay mục 10 ở trên:
13. Tách `ProvenContained(v, B)` khỏi `AllowedRoot(sink, B)`; chỉ loại khi cả hai cùng đúng (mục 4.0).
14. Nguồn `AllowedRoot` theo thứ tự: (A) API có đối số gốc riêng; (B) hợp đồng cục bộ — gốc của một phép kiểm tra
    containment áp lên chính giá trị tới sink; (C) cấu hình framework, thuộc tính, tham số — thuộc mức B của kế hoạch.
    Không bắt buộc hợp đồng khai báo cho mọi cảnh báo; không lấy hợp đồng từ mọi phép nối đường dẫn (mục 4.0).
15. Hợp đồng khai báo (`sinkAllowedRoot`) chỉ là dữ liệu kiểm thử hoặc khai báo trước khi quét, có ghi nguồn; khi có thì
    là căn cứ duy nhất cho sink đó. Không điền gốc sau khi xem một FP rồi dùng chính FP ấy làm bằng chứng (mục 4.0, 8).
16. Bộ phản ví dụ chấm theo bảng kỳ vọng độc lập, khóa trước khi chạy, trên bốn kịch bản hợp đồng (mục 7).

Bổ sung một vòng (2026-10-20): hợp đồng gốc suy ra từ tài nguyên, mức `scoped`, và hai chế độ `strict`/`scoped` — xem
`SPEC_RESOURCE.md` (điều kiện, giả định, điều kiện dừng và kết quả). `strict` là đường cơ sở đóng băng
(`FREEZE_v0.3_strict.sha256`).

## 1. Mục tiêu và phạm vi

v0.3 chỉ thêm **một** cơ chế vào v0.2: loại một cảnh báo CWE-22 của CodeQL khi chứng minh được rằng trên **mọi** luồng
CodeQL báo cho cảnh báo đó, giá trị tới sink đã đi qua một hàm kiểm tra ở hàm khác chỉ trả về bình thường khi giá trị an
toàn, giá trị không bị biến đổi làm mất điều kiện an toàn trước khi tới sink, và điều kiện an toàn **đúng với thao tác và
thư mục gốc mà sink này yêu cầu**.

Ngoài phạm vi chặng 1: validator trả về `bool` dùng trong `if` (ghi MISSED), duyệt thư mục (`os.listdir`/`scandir`/
`iterdir`) và symlink, luồng không khả thi qua callback (F3), khóa thuộc tập do server sinh (F2), CWE khác ngoài 22.

Đường cơ sở là truy vấn CWE-22 mặc định của CodeQL (python-queries 1.8.11, python-all 7.2.6). v0.3 kế thừa v0.2 và chỉ
được **bớt** cảnh báo: `R_v0.3 ⊆ R_v0.2 ⊆ R_mặc định`, với `R` là tập cảnh báo được giữ, đối chiếu theo khóa thống nhất
(CWE, tệp, dòng, cột của sink). Kiểm bằng `scripts/subset_check.py` trên SARIF thật, không chỉ dựa vào thiết kế; vế sau
bắt trường hợp v0.3 vô tình làm mất một cơ chế giảm FP của v0.2.

## 2. Mô hình đe dọa

POSIX. Kẻ tấn công kiểm soát dữ liệu yêu cầu (nguồn CodeQL mô hình hóa), không kiểm soát nội dung thư mục gốc. Tranh
chấp hệ thống tệp giữa kiểm tra và dùng (TOCTOU) ngoài phạm vi. Mọi kết luận "an toàn" chỉ đúng trong mô hình này và được
ghi rõ trong bằng chứng từng cảnh báo.

**Giả định A-SYM.** Không có liên kết tượng trưng nào trên đường truy cập — kể cả symlink có sẵn, không do kẻ tấn công tạo
ra — làm đường dẫn thực tế vượt khỏi ranh giới đã chứng minh bằng đường dẫn từ vựng. v0.3 không chứng minh A-SYM; nó là
tiền đề của kết luận. Hệ quả:

- Sự kiện từ vựng (`SafeRel`, `Segment` rồi nối dưới gốc; `abspath`/`normpath` + `startswith`; `safe_join`) chỉ loại cảnh
  báo **với điều kiện A-SYM**. Bằng chứng từng cảnh báo ghi `basis = lexical (A-SYM)`, và báo cáo đếm riêng nhóm này.
- `Contained` từ `resolve`/`realpath` trên chính giá trị được dùng ghi `basis = canonical`: symlink đã được giải tại lúc
  kiểm tra (TOCTOU vẫn ngoài phạm vi).
- Dự án mà A-SYM không giữ (ví dụ thư mục gốc chứa symlink ra ngoài) thì sự kiện từ vựng chỉ là sự kiện, không là cơ sở
  loại. Phản ví dụ symlink thuộc bộ kiểm thử chặng 2.

## 3. Sự kiện an toàn (safety facts)

`SafeRel` và `Segment` là **tính chất của giá trị**, tự chúng **không** loại cảnh báo. Chỉ `Contained(v, B)` — gắn kèm
thư mục gốc `B` — mới là cơ sở loại, và chỉ tại sink mà hợp đồng cho phép gốc `B` (mục 4.0).

| Sự kiện | Định nghĩa | Vai trò |
|---|---|---|
| `SafeRel(v)` | `v` tương đối (không bắt đầu `/`) **và** không có thành phần `..` khi tách theo `/` | trung gian: chỉ thành `Contained` khi nối dưới một gốc tin cậy |
| `Segment(v)` | `v` không chứa `/`, `\` và có ít nhất một ký tự khác `.` | trung gian: như trên (một thành phần, không thể là `.`/`..`) |
| `Contained(v, B)` (= `ProvenContained`) | dạng chuẩn tắc của `v` nằm trong thư mục gốc `B` | loại được cảnh báo ở sink dùng trực tiếp `v`, khi có `AllowedRoot(sink, B)` (mục 4.0) |

**Thư mục gốc tin cậy (`trusted_root`).** "Không bị nhiễm bởi nguồn của luồng đang xét" là điều kiện **cần, không đủ**:
một giá trị có thể sạch với request hiện tại nhưng do một nguồn không tin cậy khác ghi ra (`ipg_24_bad`). `trusted_root(B)`
khi **đồng thời**:

- **T1 nguồn gốc tin cậy** (danh sách đóng chặng 1): `B` là hằng chuỗi; hoặc tên cấp module được gán **đúng một lần** trong
  toàn chương trình bằng một biểu thức T1; hoặc `Path(t)`, `os.path.join(t, c)`, `t / c`, `os.path.normpath(t)`,
  `os.path.abspath(t)` với `t` thỏa T1 và `c` là hằng chuỗi. Chặng 1 **không** công nhận: tham số hàm, thuộc tính
  (`self.x`, `obj.x`), phần tử chứa (`d[k]`, `d.get(k)`), biến môi trường, giá trị đọc từ tệp/CSDL/cấu hình động, giá trị
  trả về của hàm ngoài danh sách trên. Thuộc tính như `self.artifact_dir` không được công nhận theo tên; muốn công nhận
  phải có quy tắc chứng minh nguồn gốc và cách dùng, kèm phản ví dụ riêng (mục 9).
- **T2 ổn định**: giá trị không đổi từ lúc kiểm tra tới lúc dùng — hằng chuỗi bất biến; tên module không bị gán lại, không
  bị ghi qua `global` hay qua thuộc tính module.
- **T3 cùng hệ quy chiếu**: giá trị tĩnh của `B` tính được, là đường dẫn POSIX tuyệt đối và bằng `normpath` của chính nó.
  Hai gốc là cùng gốc khi giá trị tĩnh bằng nhau.
- **T4 phạm vi**: `B ≠ "/"` (mục 4.0). Ngoài điều này, v0.3 chứng minh giá trị nằm trong `B`; việc sink có được truy cập
  `B` hay không do hợp đồng của sink quyết định (mục 4.0), không do v0.3 suy ra.

Một chuỗi hằng kết thúc bằng `/` **không** tự động là gốc tin cậy chỉ vì hình dạng của nó; nó phải thỏa T1–T4.

`Segment` mạnh hơn `SafeRel`. Kiểm tra dấu `\` chỉ bắt buộc ngoài POSIX và được ghi lại nếu có. `Contained` của hai gốc
khác nhau là hai sự kiện khác nhau.

## 4. Các quy tắc

### 4.0 Loại cảnh báo ở sink — khớp thao tác và gốc

**Hai khái niệm tách rời.** `ProvenContained(v, B)` (`contained` trong QL): mã chứng minh giá trị `v` nằm trong `B`.
`AllowedRoot(sink, B)` (`allowedRoot`): có căn cứ độc lập rằng thao tác tại sink được phép trong `B`. Một cảnh báo bị loại
khi **chính đối số tại sink** có `ProvenContained(·, r)` và `AllowedRoot(sink, r)`, với `r` là `trusted_root`. Gốc dùng để
dựng đường dẫn **không** mặc định là gốc được phép. Không có `AllowedRoot` ⇒ chưa đủ bằng chứng ⇒ giữ cảnh báo; cảnh báo đó
cũng **không** được tính là TP đã xác minh.

Nguồn `AllowedRoot`, theo thứ tự ưu tiên:

| Mức | Nguồn | Trạng thái |
|---|---|---|
| A | API có đối số gốc riêng, ví dụ `flask.send_from_directory(directory, path)` | không cài: CodeQL (`Flask.qll`, `getAVulnerablePathArgument`) đã loại đối số `path`/`filename` khỏi sink, nên không có cảnh báo nào để hợp đồng API tác động. Đối số `directory` vẫn là sink và không được loại: chính nó là gốc. Cài khi gặp API được CodeQL báo mà mang gốc riêng |
| B | hợp đồng cục bộ: gốc `r` của một phép kiểm tra containment (mục 4.1: `safe_join(r, p)`, `resolve(p).is_relative_to(r)`, `abspath(p).startswith(r + sep)`, …) mà sự kiện của nó tới **chính** giá trị tại sink | cài |
| C | cấu hình framework, thuộc tính đối tượng, tham số qua nhiều hàm | mức B của kế hoạch (mục 9) |
| — | hợp đồng khai báo `sinkAllowedRoot(tệp, hàm \| "*", gốc)` (model pack) | dữ liệu kiểm thử của bộ phản ví dụ, hoặc khai báo trước khi quét, có ghi nguồn |

Hợp đồng cục bộ **không** đến từ phép nối: `SafeRel`/`Segment` nối dưới `B` cho `ProvenContained` nhưng không cho
`AllowedRoot` — không coi mọi thư mục trong `os.path.join()` là thư mục được phép. Hợp đồng cục bộ chứng minh truy cập bị
giới hạn trong gốc đã xác minh, **không** chứng minh mọi chính sách phân quyền của ứng dụng được đáp ứng.

**Xung đột.** Hợp đồng khai báo phủ một sink là căn cứ duy nhất cho sink đó: một phép kiểm tra với gốc khác không thêm gốc
(đó là "bằng chứng về chính sách khác xung đột"). `ipg_17_bad` và `ipg_14_good` có cùng mã (nối dưới `PUBLIC_ROOT`, chứng
minh nằm trong `PUBLIC_ROOT` bằng `resolve`). Với hợp đồng khai báo của bộ phản ví dụ, ca 17 chỉ được `BASE` ⇒ giữ; ca 14
được thêm `PUBLIC_ROOT` ⇒ có thể loại. Không có hợp đồng khai báo, cả hai có hợp đồng cục bộ `PUBLIC_ROOT` ⇒ có thể loại:
nhãn "nguy hiểm" của ca 17 thuộc về hợp đồng khai báo, không thuộc về mã.

Hợp đồng khai báo **không** được tạo sau khi xem một cảnh báo FP rồi dùng chính cảnh báo ấy làm bằng chứng hiệu quả. Trên
dữ liệu đánh giá, mỗi hợp đồng khai báo phải có trước khi quét và ghi nguồn; báo cáo đếm riêng cảnh báo bị loại theo
từng nguồn (`declared`, `local`).

`SafeRel(v)`/`Segment(v)` tới thẳng sink mà **không** qua bước nối dưới một `trusted_root` **không** loại cảnh báo
(`ipg_15_bad`: `SafeRel` đọc tương đối thư mục làm việc).

**Suy sự kiện tách khỏi quyết định loại.** Bước 1 suy `Contained(v, B)` khi đúng về toán học, kể cả `B = "/"` (nhánh 3 của
`safe_join`). Bước 2, tại sink, chỉ loại khi `trusted_root(B)`. Vì T4 loại `B = "/"`, `Contained(v, "/")` — mọi đường
dẫn tuyệt đối POSIX đều thỏa — **không bao giờ** tự nó loại cảnh báo (`ipg_23_bad`); cảnh báo được giữ trừ khi có bằng
chứng độc lập rằng truy cập toàn hệ thống tệp là được phép, điều chặng 1 không mô hình hóa.

### 4.1 Điều kiện 1 — validator thật sự áp đặt điều kiện an toàn phù hợp

Tóm tắt (summary) của hàm `V` là bộ `(V, đích, sự kiện)` với `đích ∈ {tham số i, giá trị trả về}`, chỉ suy ra khi **mọi
đường từ đầu hàm tới một điểm thoát bình thường** đi qua nhánh "không ném" của một kiểm tra được công nhận trên đúng biến
SSA `s`:

- đích là tham số i nếu `s` là định nghĩa ban đầu của tham số (không bị gán lại trước kiểm tra), hoặc `s = resolve(p)`/
  `realpath(p)` của chính tham số đó;
- đích là giá trị trả về nếu mọi `return` trả về đúng `s`.

Kiểm tra được công nhận (danh sách đóng):

| Dạng (điều kiện để **không** ném) | Sự kiện góp phần |
|---|---|
| `".." in s.split("/")` sai, hoặc `".." in s` sai | "không có `..`" |
| `os.path.isabs(s)`, `PurePosixPath(s).is_absolute()`, `s.startswith("/")` sai | "tương đối" |
| `uuid.UUID(s)` hoàn tất bình thường | `Segment(s)` |
| `resolve/realpath(x).is_relative_to(B)` đúng | `Contained(x, B)` |
| `resolve/realpath(x).startswith(B + sep)` đúng | `Contained(x, B)` |
| `abspath/normpath(x).startswith(B + sep)` đúng | `Contained` chỉ cho chính `abspath/normpath(x)`, **không** cho `x` |
| lời gọi `V'(s)` có tóm tắt `(V', tham số, f)` | `f(s)` (bắc cầu, mục 4.3) |

`SafeRel(s)` chỉ thành lập khi **đủ cả** "không có `..`" và "tương đối" trên cùng `s` (`ipg_8_bad`, `ipg_9_bad` thiếu một
nửa). `B` trong các dòng containment phải là `trusted_root`.

**Dạng hội dẫn tới `raise` (điều kiện 2 của duyệt).** Khi điều kiện ném là một hội `if C1 and C2 and ... and Cn: raise`,
phủ định cho tuyển `¬C1 ∨ ¬C2 ∨ ... ∨ ¬Cn`: mỗi `¬Ci` là một khả năng thoát bình thường. Chỉ suy ra sự kiện khi **mọi**
`¬Ci` **độc lập** kéo theo cùng một sự kiện an toàn đối với **cùng** một gốc. Nếu một `¬Ci` không tự nó an toàn (ví dụ
`startswith(base)` thiếu dấu phân cách — `ipg_16_bad`), không suy ra sự kiện.

Riêng `safe_join` của Django (`not A and B and C: raise`, với `A ≡ final.startswith(base+sep)`, `B ≡ final != base`,
`C ≡ dirname(base) != base`), sau khi xác định `base`, `final` là đường dẫn tuyệt đối đã chuẩn hóa, công nhận ba nhánh —
mỗi nhánh độc lập cho `Contained(final, base)`:

1. `A` đúng: `final` có tiền tố `base + sep`.
2. `¬B`: `final == base`.
3. `¬C`: `base` là gốc hệ thống tệp POSIX (`dirname(base) == base`), nên mọi `final` dưới nó đều nằm trong `base`.

`normcase(·)` áp cho cả hai vế được coi là trung lập. Chỉ công nhận đúng ba nhánh này; không công nhận quy tắc hội tổng
quát tự suy. Tóm tắt vẫn là `Contained(trả về, base)` cho cả ba nhánh; nhánh 3 chỉ xảy ra khi `base` là `/`, mà khi đó
4.0 không loại. Với `base` là gốc tin cậy thì `dirname(base) != base`, nên chỉ nhánh 1–2 góp phần vào việc loại
(`ipg_13_good` loại được, `ipg_23_bad` — cùng validator, gốc `/` — giữ).

**Cài đặt bước (c).** Mỗi kiểm tra là một cạnh nhánh của CFG (CodeQL rẽ nhánh trên chính nút `not`, nên `not X` đảo cực
của `X`). Một cạnh mang `Contained(x, r)` khi:

- `x.startswith(r + os.sep)` (hoặc `+ "/"`) đúng, `x == r` đúng, hay `x != r` sai, với `x` đã qua `abspath` (cơ sở
  `lexical`), hoặc `x.startswith(r + os.sep)`/`x.is_relative_to(r)` đúng với `x` đã qua `realpath`/`resolve()` (cơ sở
  `canonical`; sự kiện cũng thuộc về chính đối số của `resolve`/`realpath`);
- `dirname(r) == r` đúng (hay `!=` sai) với `r` đã qua `abspath`: `r` là `/`, nên mọi `x` đã qua `abspath` nằm trong `r`.

`r` là tham số của validator (tham chiếu được dịch sang đối số tại nơi gọi) hoặc một `trusted_root`; `r` ở dạng thô (không
qua `abspath`/`resolve`) được chấp nhận ở `startswith`/`is_relative_to`/`==` — giá trị đã chuẩn hóa chỉ khớp tiền tố hay
bằng `r` khi chính `r` đã chuẩn hóa — nhưng **không** ở `dirname(r) == r` (vì `dirname("") == ""`). `str(·)` và
`normcase(·)` được bóc. Dạng hội: mọi cạnh cùng mang một sự kiện cho cùng giá trị được chặn **cùng lúc**; nếu không còn
đường tới lối thoát bình thường thì mọi lối thoát đã đi qua ít nhất một cạnh, mỗi cạnh độc lập kéo theo sự kiện — đúng
yêu cầu "mọi `¬Ci` độc lập an toàn". `startswith(r)` thiếu dấu phân cách không phải cạnh như vậy (`ipg_16_bad`).

### 4.2 Điều kiện 2 — đường tới sink bắt buộc đi qua kiểm tra thành công

Với lời gọi `c = V(arg)`:

- đích là giá trị trả về: chỉ nút kết quả của `c` mang sự kiện (nút này chỉ tồn tại khi `c` trả về bình thường);
- đích là tham số: một lần dùng `u` của cùng biến SSA với `arg` (biến phi xét từ điểm hợp nhánh) mang sự kiện khi **không** có đường CFG
  nào từ định nghĩa của biến tới `u` mà tránh được cạnh hoàn tất bình thường của `c` và không đi qua lại định nghĩa đó.
  Tương đương: `c` thống trị `u` và không tới được `u` từ nút kế tiếp ngoại lệ của `c` với cùng giá trị; đường quay lại
  định nghĩa (vòng lặp gán giá trị mới) bắt đầu một giá trị mới, sẽ phải qua `c` lần nữa.

### 4.3 Điều kiện 4+5 — bảo toàn trạng thái: danh sách đóng các phép biến đổi

Cài đặt: sự kiện là **tính chất bắt buộc** của một nút CFG — giá trị tại nút mang sự kiện trên mọi lần thực thi tới nút
— và chỉ được suy ra bằng các quy tắc đóng: tóm tắt validator (4.1), quy tắc phía gọi (4.2), bước giá trị SSA (lần dùng
của biến SSA không phải phi được gán một giá trị mang sự kiện) và các phép biến đổi trong bảng dưới. Không dùng trạng
thái luồng: bước taint của CodeQL tự mang trạng thái qua mọi phép biến đổi (kể cả `unquote`), nên danh sách đóng chỉ áp
được bằng một định nghĩa tường minh như vậy. Truy vấn v0.3 là truy vấn v0.2 `all` cộng đúng một điều kiện loại ở sink.

Chỉ các bước sau giữ/nâng sự kiện; **mọi** bước khác (giải mã, `unquote`, cắt chuỗi, ghép với dữ liệu khác, phương thức
chưa liệt kê, nút phi hợp nhất nhiều định nghĩa) cho giá trị **chưa kiểm tra**:

| Từ | Bước | Tới |
|---|---|---|
| `SafeRel(v)`/`Segment(v)` | `os.path.join(B, v)` (đúng hai đối số), `B / v` (`B` kiểu `Path`), với `B` là `trusted_root` | `Contained(result, B)` |
| `Segment(v)` | ghép với hằng chuỗi không chứa `/`, `\` (ví dụ `f"{v}.json"`) | `Segment` |
| `SafeRel(v)` | `posixpath/os.path.dirname`, `basename`, `normpath` | `SafeRel` |
| `Contained(v, B)` | `Path(v)`, `str(v)`, `os.fspath(v)` | `Contained(·, B)`, giữ cơ sở |
| `Contained(v, B)`, cơ sở `lexical` | `abspath(v)`, `normpath(v)` | `Contained(·, B)`. Không áp cho cơ sở `canonical`: gộp `..` theo từ vựng mà không theo symlink có thể đổi tệp đích của một đường dẫn đã giải |

**Không công nhận ghép chuỗi với `B` ở chặng 1.** `f"{B}{v}"`, `B + v` (kể cả khi `B` tin cậy và `v` là `SafeRel`) đưa
luồng về chưa kiểm tra: thiếu dấu phân cách cho đường dẫn ngoài `B` (`"/srv/data"` + `"-evil/x"` → `/srv/data-evil/x`,
`ipg_22_bad`). Dạng `f"{B}/{v}"` an toàn nhưng chỉ được công nhận khi chứng minh được dấu phân cách đúng ranh giới thư
mục và kết quả tương đương phép nối hợp lệ; để ngoài chặng 1 (MISSED chấp nhận).

**Liên thủ tục không mặc định bảo toàn.** Đi qua tham số/giá trị trả về của một hàm `g` chỉ giữ trạng thái khi `g` có
tóm tắt đã chứng minh một trong hai: (a) trả về đúng giá trị đầu vào không đổi (identity), hoặc (b) thực hiện đúng một
phép biến đổi có dòng tương ứng trong bảng trên. Không có tóm tắt ⇒ giá trị trả về **chưa kiểm tra** (`ipg_18_bad`,
`ipg_19_bad`: hàm thêm `../`).

Sự kiện gắn với biến SSA/nút giá trị, không gắn với tên biến: gán lại tạo định nghĩa mới không mang sự kiện
(`ipg_4_bad`). Không theo dõi qua thuộc tính (`self.x`), phần tử chứa (`d[k]`, `xs[i]`) hay biến toàn cục.

**Đã bỏ khỏi chặng 1:** quy tắc `Contained → Contained` qua `os.listdir`/`scandir`/`iterdir`. Lý do: danh sách thư mục có
thể chứa symlink, và ba API trả về kiểu khác nhau (tên, `DirEntry`, `Path`); một phần tử "trong thư mục" về mặt tên chưa
chắc trỏ tới tệp trong thư mục. Chấp nhận bỏ lỡ một vài FP (mục 6) hơn là thêm quy tắc chưa chứng minh đủ.

### 4.4 Điều kiện 3 — thất bại không tới sink, kể cả qua bắt ngoại lệ

Hệ quả của 4.1 (một `except` nuốt lỗi trong `V` tạo đường thoát bình thường không qua kiểm tra ⇒ `V` không có tóm tắt,
`ipg_3_bad`) và 4.2 (`except: pass` ở phía gọi làm `u` tới được từ nút ngoại lệ, `ipg_2_bad`; `except: return/continue/
raise` thì không, `ipg_6_good`, `ipg_12_good`). Dùng phân tích chặt: có bất kỳ đường ngoại lệ nào trong CFG tới `u` với
cùng giá trị (kể cả qua vòng lặp mà không gán lại biến) ⇒ không gán sự kiện.

## 5. Khi CodeQL không chứng minh được, và nhiều đường tới cùng sink

- **Không đủ dữ kiện ⇒ không `Validated`.** Nếu CodeQL không phân giải được đích lời gọi (gọi động, `getattr`, hàm bị
  ghi đè) hoặc không dựng đủ cạnh ngoại lệ, không gán sự kiện cho luồng đó; cảnh báo được **giữ** (`ipg_21_bad`).
- **Mọi đường phải được kiểm chứng.** Một cảnh báo chỉ bị loại khi **mọi** luồng nguồn→sink mà CodeQL báo cho sink đó đều
  mang sự kiện phù hợp (4.0). Còn một luồng chưa kiểm chứng ⇒ giữ cảnh báo (`ipg_20_bad`). Vì sự kiện là tính chất bắt
  buộc của chính đối số tại sink, mọi luồng tới sink đều đi qua giá trị đó; một nhánh chưa kiểm chứng tạo nút phi (hoặc
  một định nghĩa khác) không mang sự kiện, nên đối số tại sink không mang sự kiện.

## 6. Đối chiếu với tập phát triển (đợt B)

Kết quả mức A, 2026-10-20, không có hợp đồng khai báo (`scripts/run_dev.sh`, `results/dev_stage1_abc.json`; phía fixed:
mlflow@`6e801f42`, Django@`05413afa`; lần chạy sau khi sửa các lỗ hổng nhận dạng). Cột "Lõi nhận ra" lấy từ
`queries/V03Summaries.ql`: mlflow 11 tóm tắt, Django 2, BenchmarkPython 0.

| Nhóm | Validator | Lõi nhận ra | Gốc tại nơi gọi | Kết quả |
|---|---|---|---|---|
| RC-M1 `upload_artifact_handler` (2) | `validate_path_is_safe` | có (sau khi sửa ba lỗ hổng nhận dạng, xem dưới): giá trị trả về `SafeRel` | `tmpdir` (không thỏa T1); dù vậy chỉ là phép nối, không có `AllowedRoot` | giữ |
| RC-M1 `list_artifacts`, `download_artifacts`, `_download_file` | `validate_path_within_directory` | có: `Contained` `canonical` cho tham số 1 và giá trị trả về, gốc tham số 0 | `self.artifact_dir` (thuộc tính) | giữ: gốc không thỏa T1 |
| RC-M1 phụ thuộc duyệt thư mục | — | cần chặng 2 | — | giữ |
| RC-M3 phiên trợ lý (8) | `SessionManager.validate_session_id` (`uuid.UUID`) | có: `Segment` cho tham số 0, và bắc cầu qua các `staticmethod` `get_session_file`, `save`, `get_process_file`, `save_process_pid` | `SESSION_DIR = Path(tempfile.gettempdir()) / …` (đối chiếu mã mlflow@`6e801f4259`); chỉ là phép nối, không có `AllowedRoot` | giữ |
| RC-D2 Django `static.serve` (4) | `django.utils._os.safe_join` | có: `Contained` `lexical` cho giá trị trả về, gốc tham số 0 (sau khi nhận dạng `normcase` bên trong phép thử, xem dưới) | `document_root` (tham số) | giữ: gốc không thỏa T1 |
| **RC-M6** (2, phản ví dụ âm tính) | `validate_path_is_safe` | có (trả về `SafeRel`), nhưng handler bỏ giá trị trả về và dùng chuỗi gốc | — | **giữ** |

| Repo | Cảnh báo CWE-22 của v0.2 | Có `AllowedRoot` | Có `ProvenContained` | Bị v0.3 loại | TP/unknown còn giữ |
|---|---:|---:|---:|---:|---|
| mlflow | 26 | 0 | 0 | 0 | 4/4 (gồm 2 RC-M6) |
| Django | 9 | 0 | 0 | 0 | 4/4 |

Như vậy 0/35 cảnh báo xác định được hợp đồng; tập đủ điều kiện rỗng; 0 FP được loại. Mức A **không phải** phiên bản để đo
hiệu quả giảm FP thực tế; nó kiểm tính đúng của lõi. Chẩn đoán cho thấy lõi nhận ra cả hai validator containment thật,
và chặn lại đúng ở T1: các lời gọi truyền gốc là thuộc tính (`self.artifact_dir`, `self.location`), tham số (`document_root`,
`root` của `staticfiles.finders`) hoặc biến vòng lặp trên cấu hình (`template_dir`). Đó là đầu việc cụ thể của mức C (mục 9).

**Chỉnh sửa dựa trên tập phát triển (ghi lại, không báo cáo như kết quả đánh giá).** Chẩn đoán lần đầu cho thấy `safe_join`
thật của Django **không** được nhận ra: Django đặt `normcase(·)` bên trong từng phép thử (`normcase(base_path + sep)`,
`dirname(normcase(base_path)) != normcase(base_path)`), còn fixture đặt `normcase` lúc gán. Sửa tổng quát: `normcase`/`str`
là đồng nhất trên POSIX và được bóc ở cả hai vế. Thêm `ipg_15_good` mang đúng bố cục đó; bảng kỳ vọng được khóa lại trước
lần chạy đầu với ca này (hash cũ ghi trong `EXPECTATIONS.sha256`). Không có ngoại lệ theo tên dự án.

Lần chẩn đoán thứ hai cũng cho thấy `validate_path_is_safe` của mlflow không có tóm tắt vì ba lỗ hổng nhận dạng tổng quát:
`PurePosixPath(s).is_absolute()` chưa được nhận, biến được kiểm là biến phi (`if is_file_uri(path): path = …` trước kiểm
tra), và lời gọi phương thức chưa được phân giải (`SessionManager.validate_session_id`). Cả ba được sửa tổng quát (mục 10),
kèm `ipg_16_good`–`ipg_19_good`, `ipg_25_bad`, `ipg_26_bad`; bảng kỳ vọng được khóa lại trước lần chạy đầu với các ca này.

**Nguồn gốc của ba gốc mức C (đối chiếu mã đã quét, 2026-10-20).** Trước khi viết quy tắc mức C:

| Gốc | Nguồn gốc trong mã | Quy tắc tái sử dụng được sẽ kết luận |
|---|---|---|
| `self.artifact_dir` (mlflow `LocalArtifactRepository`) | `local_file_uri_to_path(self.artifact_uri)`; `artifact_uri` đến từ `run.info.artifact_uri`, `logged_model.artifact_location`, … đọc từ store. Handler `create_experiment` nhận `artifact_location` từ request; `_validate_artifact_root_uri` chỉ từ chối fragment/params, tiền tố `runs:` và độ dài | **không tin cậy**: một phần nguồn là dữ liệu client đặt qua API (T1) |
| `document_root` (Django `views.static.serve`) | tham số; `serve` chỉ được đăng ký trong URLconf (`conf/urls/static.py`), không có lời gọi trực tiếp nào trong repo | **không tin cậy**: không có nơi gọi nào để truy |
| `SESSION_DIR` (mlflow phiên trợ lý) | `Path(tempfile.gettempdir()) / "mlflow-assistant-sessions"`, hằng cấp module | có thể công nhận (trạng thái máy chủ, tuyệt đối, khác `/` nhờ đoạn hằng); nhưng RC-M3 chỉ có containment qua **phép nối**, không có `AllowedRoot` (4.0) ⇒ vẫn giữ |

Hệ quả: các quy tắc mức C đúng sẽ **không** loại cảnh báo nào trong 19 F1 của tập phát triển. Nhãn FP của RC-M1 (đợt B) ngầm
giả định gốc artifact là tin cậy; giả định đó cần người gán nhãn xem lại, vì client đặt được `artifact_location`. Nhãn đã
khóa, không sửa ở đây.

FP không loại được vì thiếu bằng chứng là MISSED hợp lệ. Tập phát triển gồm 19 cảnh báo F1 + 2 RC-M6.

## 7. Bộ phản ví dụ (`counterexamples/`)

19 trường hợp an toàn (`ipg_<n>_good`) và 26 trường hợp nguy hiểm (`ipg_<n>_bad`); validator ở `validators.py` (module
riêng ⇒ guard luôn liên thủ tục).

**Bảng kỳ vọng độc lập.** `expectations/ipg_expectations.csv` (khóa bởi `EXPECTATIONS.sha256` trước lần chạy đầu tiên của
bước c; `run_cex.sh` dừng nếu hash lệch) ghi cho từng (kịch bản, ca): `keep` hay `may` (được phép loại), các gốc sink được
truy cập trong kịch bản đó, và lý do (`escape`, `contract-forbids`, `no-contract`, `local-contract`, `safe`). Bảng viết
từ ngữ nghĩa fixture, không từ kết quả truy vấn, và không đọc model pack. Bốn kịch bản:

| Kịch bản | Hợp đồng khai báo (model pack) | Kỳ vọng chính |
|---|---|---|
| `declared` | `policy/`: mọi hàm `/srv/data`, `ipg_14_good` thêm `/srv/public` | 19 ca an toàn `may`, 26 ca nguy hiểm `keep` |
| `none` | không có | chỉ ca có hợp đồng cục bộ `may` (g3, g4, g13, g15 ở `/srv/data`; g14, b17 ở `/srv/public`); 14 ca an toàn còn lại `keep` vì không có hợp đồng |
| `wrong_root` | `policy_scenarios/wrong_root`: mọi hàm chỉ `/srv/other` | mọi ca `keep` |
| `conflict` | `policy_scenarios/conflict`: mọi hàm chỉ `/srv/data` | như `declared`, trừ g14 `keep` (hợp đồng khai báo mâu thuẫn với hợp đồng cục bộ của nó) |

`scripts/check_semantics.py` kiểm bảng bằng thực thi đường dẫn thật (không đọc/ghi tệp), tách khỏi logic QL: dòng `may`
⇒ không đầu vào nào trong 29.929 chuỗi thử được ca chấp nhận mà ra ngoài các gốc; `keep`/`escape` ⇒ đầu vào chứng ra
ngoài; `keep`/`contract-forbids` ⇒ có đầu vào được chấp nhận ra ngoài; `keep`/`no-contract` không là tuyên bố nguy hiểm.
`scripts/evaluate_scenarios.py` so kết quả QL với bảng: UNSOUND khi một dòng `keep` bị v0.3 bỏ cảnh báo mà v0.2 còn báo
(hoặc, với `escape`/`contract-forbids`, cảnh báo mà truy vấn mặc định báo).

| Điều kiện | An toàn | Nguy hiểm |
|---|---|---|
| 1 validator thật sự kiểm tra | g1, g2, g4, g5, g7, g16 (`PurePosixPath(s).is_absolute()`), g17 (`startswith("/")`, biến phi) | b3 (nuốt lỗi), b8 (thiếu kiểm tuyệt đối), b9 (thiếu `..`), b10 (chỉ ném khi strict), b11 (`bool` bị bỏ), b16 (prefix thiếu sep), b25 (`PureWindowsPath`) |
| 2 bắt buộc đi qua | g6, g9 | b2 |
| 3 thất bại không tới sink | g6, g12 | b2, b3 |
| 4.0 khớp thao tác & gốc | g1, g3, g4, g5, g10, g14 (cùng mã với b17, hợp đồng cho `PUBLIC_ROOT`) | b15 (`SafeRel` thẳng vào sink), b17 (`Contained` dưới `PUBLIC_ROOT`, hợp đồng chỉ cho `BASE`), b14 |
| 4.0/4.1 gốc `/` không loại | g13 (`safe_join` ba nhánh, gốc `BASE`), g15 (ba nhánh, `normcase` trong từng phép thử như Django) | b23 (cùng validator với g13, gốc `FS_ROOT = "/"`) |
| 3 `trusted_root` T1 | — | b24 (gốc do request khác ghi vào `SETTINGS`) |
| 4.3 bảo toàn / liên thủ tục | g2, g8 | b1 (bỏ giá trị trả về), b5, b6, b7, b12, b13, b18 (hàm thêm `../`), b19 (trung gian thêm `../`), b22 (`f"{BASE}{v}"` thiếu dấu phân cách) |
| 5 không đủ dữ kiện / nhiều đường | g18 (`staticmethod`), g19 (phương thức thường, đối số lệch 1) | b20 (một đường chưa kiểm chứng), b21 (gọi động), b26 (hai đích, bản ghi đè không kiểm tra) |
| 5 không bị vô hiệu | g2 | b4 |
| ngoài phạm vi | g11 (MISSED chấp nhận) | — |

Đường cơ sở trên bộ này (CodeQL 2.27.1, 2026-10-20): mặc định báo cả 24 ca nguy hiểm và 15 ca an toàn (0 VACUOUS); v0.2
không loại ca nào; hai vị trí sink v0.2 bớt là `Path(candidate).resolve()` trong `validators.py`, ngoài mọi ca.
`scripts/check_semantics.py` báo 0 failures trên 156 dòng của bảng. Kết quả v0.3 ở mục 8. Một nhóm phản ví dụ riêng cho
symlink sẽ thêm ở chặng 2 để xác định rõ giới hạn A-SYM.

## 8. Tiêu chí chấp nhận (chạy sau mỗi chặng)

1. Bộ phản ví dụ v0.3: 0 UNSOUND, 0 VACUOUS; MISSED liệt kê kèm lý do.
2. Bộ phản ví dụ pilot (v0.1/v0.2): 0 UNSOUND.
3. Tập phát triển: hai cảnh báo RC-M6 được giữ; báo số cảnh báo F1 loại được và lý do cho từng cảnh báo không loại được.
4. BenchmarkPython: 0 TP bị loại (chỉ để tìm lỗi kỹ thuật, không phải đánh giá độc lập).
5. `R_v0.3 ⊆ R_v0.2 ⊆ R_mặc định` trên mọi đầu vào đã chạy (`scripts/subset_check.py none,all,<v03>`), khóa
   (CWE, tệp, dòng, cột của sink). Không yêu cầu v0.3 loại đủ 19 FP của tập phát triển.
6. Mỗi cảnh báo bị loại ghi `basis` (`lexical (A-SYM)` hoặc `canonical`); báo cáo đếm theo `basis`.

Kết quả mức A, bước (a)+(b)+(c), 2026-10-20 (`scripts/run_cex.sh` → `results/cex_stage1_abc.json`; `scripts/run_dev.sh`
→ `results/dev_stage1_abc.json`). Lượt chỉ có (a)+(b), 2026-10-16, ở `results/cex_stage1_ab.json`.

| Tiêu chí | Kết quả |
|---|---|
| 1 bộ v0.3 (19 an toàn, 26 nguy hiểm) | `declared`: 0 UNSOUND, 0 VACUOUS, 44 ok, 1 MISSED (g11, `bool`, ngoài phạm vi). `none`: 45 ok — đúng 6 ca có hợp đồng cục bộ bị loại (g3, g4, g13, g14, g15, b17), 14 ca chỉ có phép nối được giữ. `wrong_root`: 45 ok, không sink nào bị loại. `conflict`: 44 ok, 1 MISSED (g11); g14 được giữ |
| 2 bộ pilot | 0 UNSOUND; kết quả từng ca trùng v0.2 (41 ok, 4 MISSED, 2 VACUOUS). Bảng bằng chứng v0.3 có 2 sink `canonical` (kiểm tra trong hàm, hợp đồng khai báo) ở `guard_prefix_r2_good`/`r3_good` — hai ca v0.2 đã loại |
| 3 tập phát triển | RC-M6 giữ 2/2; TP/unknown giữ 8/8; 0/35 cảnh báo có hợp đồng, 0 FP loại được; lý do từng nhóm ở mục 6 |
| 4 BenchmarkPython | không hợp đồng khai báo: 0 sink bị loại, 0 TP mất; CWE-22 cấu hình E giữ nguyên (phát triển TP 24, FP 5; kiểm tra TP 21, FP 4); không tìm thấy tóm tắt validator nào (benchmark dùng kiểm tra trong hàm) |
| 5 chuỗi tập con | đạt mọi lượt: bộ v0.3 v0.3 {27, 40, 46, 28} ⊆ v0.2 46 ⊆ mặc định 48 theo bốn kịch bản; pilot CWE-22 v0.3 25 ⊆ v0.2; mlflow 26 ⊆ 26 ⊆ 27; Django 9 ⊆ 9 ⊆ 9; BenchmarkPython 63 ⊆ 63 ⊆ 125 |
| 6 `basis` | `declared`: 19 sink bị loại, 17 `lexical (A-SYM)`, 2 `canonical`, nguồn `declared`. `none`: 6 sink, 3 `lexical (A-SYM)`, 3 `canonical`, nguồn `local`. `conflict`: 18 sink (17 lexical, 1 canonical) |

Mỗi sink bị loại được liệt kê kèm gốc, cơ sở và nguồn hợp đồng trong các tệp kết quả; chuỗi tập con không thay thế việc
xem bằng chứng từng cảnh báo bị loại.

## 9. Kế hoạch

- **Mức A — lõi chứng minh (chặng 1):** tóm tắt validator, theo dõi giá trị trả về/tham số, xác minh ngoại lệ, danh sách
  đóng ở 4.3, `trusted_root` T1–T4 nghiêm ngặt, `AllowedRoot` từ hợp đồng khai báo hoặc cục bộ. Mục tiêu: tính đúng của máy sự kiện,
  validator và ngoại lệ; chấp nhận nhiều MISSED. Thứ tự cài đặt, mỗi bước phải vượt các phản ví dụ liên quan trước khi
  ghép vào truy vấn CWE-22 hoàn chỉnh: (a) `Segment` qua `uuid.UUID` (g5, g9, b12) — **xong**; (b) `SafeRel` qua validator
  chặn bằng ngoại lệ (g1, g2, g6, g7, g8, g10, g12; b1–b11, b13, b15, b18–b22) — **xong**; (c) `Contained` qua
  `safe_join`/`resolve` (g3, g4, g13, g14; b14, b16, b17, b23, b24) cùng hợp đồng cục bộ — **xong**.
- **Mức B — mở rộng nguồn gốc tin cậy có kiểm chứng:** sau khi lõi hoạt động; quy tắc tổng quát cho gốc do hệ thống tạo
  (ví dụ `tempfile.gettempdir()`), tham số truy ngược được tới cấu hình máy chủ, thuộc tính chỉ gán từ cấu hình, và nguồn
  hợp đồng sink cho dự án thật. Mỗi quy tắc cần bằng chứng nguồn gốc, tính ổn định, chuẩn hóa và phản ví dụ riêng; không
  ngoại lệ theo tên dự án. Hoàn thành mức B trước khi khóa v0.3 để đánh giá trên repository mới, nếu mục tiêu là đo giá trị
  giảm FP chứ không chỉ tính đúng của lõi.
- **Chặng 2 — mở rộng có kiểm soát:** quy tắc duyệt thư mục (`listdir`/`scandir`/`iterdir`) kèm điều kiện symlink, các phép
  biến đổi đường dẫn phức tạp. Chỉ mở rộng khi có phản ví dụ đủ tốt.

Chạy lại mục 8 sau mỗi bước. Không nới quy tắc chỉ để đạt chỉ tiêu số lượng.

## 10. Giới hạn đã biết

- Danh sách kiểm tra và bước bảo toàn là danh sách đóng; validator viết khác sẽ bị MISSED (an toàn nhưng không giảm FP).
- `Contained` từ `abspath/normpath`, `SafeRel`/`Segment` nối dưới gốc và `safe_join` là chuẩn hóa từ vựng, không theo
  symlink; chỉ đúng dưới A-SYM (mục 2).
- T4 chỉ loại gốc `/`; v0.3 không biết thư mục nào ứng dụng định cho truy cập, nên gốc tin cậy nhưng quá rộng (ví dụ
  `/etc`) vẫn được chấp nhận như chính sách của nhà phát triển.
- Mô hình CFG ngoại lệ và phân giải lời gọi của CodeQL quyết định 4.2 và mục 5; thiếu dữ kiện ⇒ giữ cảnh báo.
- Cài đặt nhận các dạng của 4.1: `os.path.isabs(s)`, `PurePosixPath/Path/PurePath/PosixPath(s).is_absolute()`,
  `s.startswith("/")` sai (không nhận `PureWindowsPath`, vì trên POSIX `"/etc/passwd"` không tuyệt đối với kiểu đó —
  `ipg_25_bad`); `".." in s.split("/")`/`".." in s` sai; `uuid.UUID(s)` hoàn tất; các dạng containment ở "Cài đặt bước
  (c)"; lời gọi bắc cầu tới hàm có tóm tắt. Lời gọi được phân giải khi tới **đúng một** hàm: hàm thường, `staticmethod`,
  phương thức gọi qua lớp (đối số khớp tham số từ 0), phương thức thường và `classmethod` gọi qua đối tượng/lớp (đối số k
  khớp tham số k + 1, vì `self`/`cls` đã gắn). Lời gọi có nhiều đích (ghi đè, `ipg_26_bad`) hoặc động không có tóm tắt.
  Biến được kiểm có thể là biến phi (gán lại có điều kiện trước kiểm tra, `ipg_17_good`); đường đi được xét từ điểm hợp
  nhánh của nó; bước giá trị SSA (`v = e`) vẫn chỉ dùng biến một định nghĩa. Chưa nhận đối số từ khóa; biểu thức bị
  `finally` nhân bản trong CFG không mang sự kiện; `werkzeug.safe_join` (trả về `None` thay vì ném) chưa được mô hình hóa.
  Thiếu sót này chỉ gây MISSED.
- Hợp đồng API (mức A) chưa có API nào để áp dụng (mục 4.0).
