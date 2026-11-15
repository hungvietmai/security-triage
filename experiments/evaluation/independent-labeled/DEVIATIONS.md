# Kết quả đã đăng ký và phần làm thêm sau đó (đợt 4)

Ghi ngày 2026-11-14, sau khi quét. [PREREGISTRATION.json](PREREGISTRATION.json) và mọi tệp có
mã băm trong đó được giữ nguyên.

## 1. Kết quả đã đăng ký: lượt quét thất bại

- Lượt quét duy nhất đã đăng ký (`input/`, 15:08–15:10 UTC) kết thúc ở trạng thái **`failed`**:
  `SyntaxError: positional argument follows keyword argument (python37.py, line 13)`.
- Nguyên nhân là lỗi của nguyên mẫu, không phải của công cụ quét: bộ định vị lời gọi Python
  dùng bộ phân tích cú pháp của thư viện chuẩn và **dừng cả lượt quét khi gặp một tệp Python sai
  cú pháp**. Kho `semgrep-rules` có tệp kiểm thử cố ý sai cú pháp.
- Theo giao thức, lượt lỗi vẫn được chấm: [results/registered.json](results/registered.json).
  Không có ứng viên nào, nên mọi cấu hình có TP = 0, FN = 135, FP = 0, TN = 75. **Đây là kết quả
  đã đăng ký của đợt 4.** Nó không cho biết gì về chất lượng phát hiện hay bước gạn; nó cho biết
  nguyên mẫu không quét được kho này.

## 2. Sửa lỗi và lượt quét lại (ngoài kết quả đã đăng ký)

- `backend/app/workflows/scans/analysis.py`: tệp Python không phân tích cú pháp được nay bị bỏ
  qua ở bước định vị lời gọi, bước đó ghi `partial`, và lượt quét của ngôn ngữ thành `partial`.
  Vì lượt chạy dở, bước gạn không gạn gì (`run_incomplete`), đúng nguyên tắc "chạy dở thì giữ".
  Có kiểm thử hồi quy. Tệp này không nằm trong danh sách đã băm; các tệp đã băm không đổi.
- Kho được quét lại **một lần** bằng worker đã sửa: [posthoc-after-fix/](posthoc-after-fix/),
  chấm bằng đúng script và nhãn đã băm:
  [results/posthoc-after-fix.json](results/posthoc-after-fix.json). Tệp nén được quét có cùng
  SHA-256 với tệp đã dùng để dựng nhãn.
- **Vì sao kết quả quét lại vẫn đáng tin ở mức mô tả:** nhãn, script chấm và mọi tệp cấu hình
  được băm trước lượt quét đầu; lượt quét đầu không sinh cảnh báo nào, nên không có thông tin
  về kết quả lọt ra trước khi sửa; bản sửa không đụng tới phát hiện, gộp, xếp ưu tiên hay gạn.
- **Vì sao nó vẫn không phải kết quả đã đăng ký:** giao thức ghi "quét một lần, không quét
  lại". Mọi nơi dẫn số liệu của lượt quét lại phải nói rõ đó là lượt sau khi sửa lỗi.

## 3. Điều đợt này không trả lời được

Câu hỏi 2 của giao thức (bước gạn chuyển đi bao nhiêu vị trí an toàn và có lỗi) **không có câu
trả lời**: lượt quét lại ở trạng thái `partial` (bước định vị Python bỏ qua tệp sai cú pháp;
CodeQL JavaScript chạy dở), nên theo thiết kế bước gạn không hoạt động. Mục 6 của giao thức đã
lường trước trường hợp này.

## 4. Quét lại bằng profile v0.3 (2026-11-15, dữ liệu phát triển)

Sau khi profile `command-injection-v0.3` có bộ định vị lời gọi JavaScript v1, kho được quét thêm
một lần bằng v0.3 ([v0.3-rescan/](v0.3-rescan/)) và chấm bằng cùng nhãn và script:
[results/v0.3-rescan.json](results/v0.3-rescan.json). Lúc này kho đã được quét hai lần và kết
quả đã được xem, nên đây là **dữ liệu phát triển**, không còn là kiểm tra độc lập.

| 25 vị trí JavaScript có nhãn (15 có lỗi, 10 an toàn), hợp mọi nguồn | TP | FP | FN | TN | Độ chính xác | Độ bao phủ | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| v0.2 (lượt quét lại ở mục 2) | 6 | 0 | 9 | 10 | 1,00 | 0,40 | 0,57 |
| v0.3 | 12 | 2 | 3 | 8 | 0,86 | 0,80 | 0,83 |

- Khác biệt đến từ đối sánh: với v0.2, cảnh báo ở sáu vị trí có lỗi và hai vị trí an toàn không
  gộp được vào lời gọi nào nên không được tính là "được báo". Công cụ phát hiện không đổi.
- 185 vị trí Python cho kết quả y hệt hai lượt (F1 0,69).
- Trên cả 210 vị trí: F1 0,69 → 0,71.
- Lượt quét vẫn `partial`, nên không quy tắc gạn nào hoạt động, kể cả G4; không vị trí có nhãn
  nào bị gạn. Đợt này vì thế không đo được G4.
- Hai vị trí an toàn bị báo (`typescript/mcp/security/mcp-command-injection-typescript.ts`, dòng 46
  và 64) là lời gọi `exec` do ESLint và luật luồng dữ liệu `detect-child-process` của Semgrep cùng
  báo. Một công cụ khẳng định luồng dữ liệu ở đó, nên G4 sẽ giữ cả hai kể cả khi lượt quét hoàn
  tất: đây là loại cảnh báo sai khác, không thuộc nhóm lệnh hằng.
- 11 trong 25 vị trí JavaScript thuộc kiểm thử của các luật Semgrep mà profile đang chạy; ở đó
  Semgrep được chấm bằng kỳ vọng của chính nó.
