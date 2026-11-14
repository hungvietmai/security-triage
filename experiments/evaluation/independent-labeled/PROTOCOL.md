# Giao thức kiểm tra độc lập đợt 4 — vị trí có nhãn "có lỗi" và "an toàn" (CWE-78)

Viết ngày 2026-11-14, **trước khi quét nguồn dưới đây**. Mã băm của tệp này, của
[labels.json](labels.json), của hai script và của cấu hình quyết định hành vi được ghi trong
[PREREGISTRATION.json](PREREGISTRATION.json) trước lượt quét.

## 1. Mục đích

Ba đợt trước chỉ có nhãn dương tính, nên không tính được độ chính xác và F1 trên mã chưa từng
xem, và bước gạn không có cảnh báo sai đã biết nào để thử. Đợt này dùng một nguồn có **cả hai
loại nhãn** để trả lời:

1. *Trước–sau có đủ chỉ số:* TP, FP, FN, TN, độ chính xác, độ bao phủ và F1 của Semgrep riêng,
   CodeQL riêng, công cụ bổ trợ riêng, Semgrep ∪ CodeQL, hợp mọi nguồn và danh sách sau gạn;
2. *Bước gạn:* nó chuyển bao nhiêu vị trí an toàn và bao nhiêu vị trí có lỗi sang "Đã gạn".

Đây **không** phải đánh giá trên tập giữ lại của `pairs-v1`; không cặp nào của tập đó bị quét.

## 2. Nguồn và nhãn

- **Nguồn:** `semgrep/semgrep-rules`, commit `a84ff9cc2453ca91d581380de4b8b3f272f6f4be`. Đây là
  commit mà các luật Semgrep của profile được chép từ đó; dự án chỉ chép tệp luật (`.yaml`),
  chưa từng chép, đọc hay quét các tệp kiểm thử của kho này.
- **Nhãn do tác giả luật viết.** Cạnh mỗi luật, kho có tệp kiểm thử với chú thích
  `ruleid: <tên luật>` (dòng mã kế tiếp phải bị báo) và `ok: <tên luật>` (không được báo). Với
  luật theo dõi dữ liệu không tin cậy tới lệnh hệ điều hành, hai chú thích này là phát biểu của
  tác giả luật rằng dòng kế tiếp **có** hay **không có** lỗi chèn lệnh.
- **Quy tắc chọn, không chọn tay** ([build_labels.py](build_labels.py)): mọi tệp luật dưới
  `python/`, `javascript/`, `typescript/` có `mode: taint` và gắn `CWE-78`; tệp kiểm thử cùng tên
  của chúng; mỗi chú thích `ruleid:`/`ok:` nêu một luật đã chọn gán nhãn cho dòng mã kế tiếp.
  Chú thích `todoruleid:`/`todook:` (kết quả sai đã biết của luật) không phải nhãn. Một dòng vừa
  có `ruleid` vừa có `ok` của hai luật khác nhau được coi là có lỗi.
- **Kết quả:** 25 luật, **210 vị trí**: Python 120 có lỗi và 65 an toàn; JavaScript/TypeScript 15
  có lỗi và 10 an toàn.
- **Đã xem trước khi quét:** script đọc tệp nén trong bộ nhớ và chỉ in số lượng cùng tên tệp
  luật. Không ai đọc nội dung các tệp kiểm thử, và chưa công cụ quét nào chạy trên kho này.

## 3. Thiên lệch biết trước của nhãn

- **Semgrep được chấm bằng chính kỳ vọng của luật Semgrep.** 64 vị trí thuộc kiểm thử của các
  luật mà profile đang chạy (`profile_rule: true`); ở đó Semgrep riêng gần như chắc chắn đạt điểm
  tối đa. Vì vậy mọi bảng được tính thêm trên tập con **"kiểm thử của luật mà profile không
  chạy"** (146 vị trí), và kết luận về Semgrep chỉ dựa trên tập con đó.
- Nhãn "an toàn" nghĩa là *không có luồng dữ liệu không tin cậy theo mô hình của luật*; nhãn "có
  lỗi" nghĩa là *có luồng như vậy*. Dự án không kiểm lại nhãn bằng cách đọc mã.
- Mã kiểm thử luật là đoạn mã ngắn viết để minh họa, không phải mã ứng dụng.

## 4. Cấu hình cố định

- Profile `command-injection-v0.2` (manifest `6993df05…`), bước gạn `adjudicate-v0.2` và các gói
  bằng chứng: đúng các tệp đã băm ở ba đợt trước, không đổi.
- Image worker là bản sau khi sửa lỗi đọc ký tự xuống dòng (`acquisition.py`), tức khác bản đã
  chạy ba đợt trước ở đúng điểm đó.
- Quét **một lần** toàn bộ kho qua ứng dụng đang chạy bằng
  [../collect_report.py](../collect_report.py), lưu vào `input/`. Không quét lại.
- Lượt quét lỗi hoặc dở được giữ nguyên và vẫn được chấm; trạng thái từng bước được in kèm.

## 5. Đơn vị đếm và chỉ số

Tính bằng [labeled_sites.py](labeled_sites.py), viết và kiểm thử trên dữ liệu tổng hợp trước
khi quét.

- Một vị trí là một dòng của một tệp. Một cấu hình "báo" vị trí khi có ứng viên của nó cùng tệp
  và bắt đầu đúng dòng đó (quy tắc khớp của các đợt trước).
- TP: vị trí có lỗi được báo. FN: vị trí có lỗi không được báo. FP: vị trí an toàn được báo.
  TN: vị trí an toàn không được báo.
- Bước gạn: số vị trí an toàn và số vị trí có lỗi mà mọi ứng viên của nó đều ở "Đã gạn", theo
  từng quy tắc; số vị trí chỉ bị hạ xuống P3/P4.
- Bảng được tính cho: mọi vị trí; riêng Python; riêng JavaScript; và hai tập con loại bỏ kiểm
  thử của luật mà profile chạy.
- Ứng viên ngoài mọi vị trí có nhãn chỉ được đếm.

## 6. Diễn giải đã chốt trước

- Một vị trí có lỗi bị gạn là **thất bại** của bước gạn, bất kể lý do, và được liệt kê.
- Một vị trí an toàn bị gạn là cảnh báo sai được gạn đúng theo nhãn của tác giả luật.
- Nếu bước Python của lượt quét không `completed`, bước gạn theo thiết kế không gạn gì; khi đó
  đợt này chỉ trả lời câu hỏi 1, và điều đó được ghi rõ thay vì quét lại.
- Kết quả được báo cáo dù thuận hay không thuận, kể cả khi danh sách sau gạn không hơn một công
  cụ chạy riêng.

## 7. Giới hạn biết trước

- Một kho, 210 dòng mã minh họa: không đại diện cho mã ứng dụng, và các vị trí trong cùng tệp
  không độc lập với nhau.
- Mẫu JavaScript nhỏ (25 vị trí), và bước gạn không có gói bằng chứng cho JavaScript.
- Dòng được gán nhãn là dòng mà luật Semgrep khớp; nếu lời gọi bắt đầu ở dòng khác thì vị trí
  không được tính là "được báo".
- Kho chứa nhiều tệp cố ý sai cú pháp hoặc viết cho phiên bản ngôn ngữ cũ; công cụ có thể chạy dở.
- Giao thức được viết và băm trong cùng phiên làm việc với lượt quét, chưa được công bố bằng
  commit hay push.
