# Đợt 5: kết quả đã đăng ký và phần đọc lại sau đó

Ghi ngày 2026-11-15, sau khi quét. [PREREGISTRATION.json](PREREGISTRATION.json) và mọi tệp có
mã băm trong đó được giữ nguyên; không script nào bị sửa sau khi quét.

## 1. Kết quả đã đăng ký

Nguồn: [results/filtered-candidates.json](results/filtered-candidates.json) và
[results/verified.json](results/verified.json).

| Chỉ số | Kết quả |
|---|---|
| Lượt quét | 20: **18 `completed`**, 1 `partial`, 1 `failed` |
| Ứng viên (cả 20 lượt) | 184; danh sách rà chính 165, **đã gạn 19**, chỉ hạ ưu tiên 145 |
| Ở 18 lượt hoàn tất | 145 ứng viên, 19 bị gạn (13%), ở 2 trong 18 kho |
| Quy tắc gạn | G2 (lệnh là hằng): 19. G1: 0. G3: 0 |
| Phép kiểm độc lập | `constant_command`: **17**. `not_constant`: **2**. `unreadable`: 0 |

- Lượt `failed` (`donnemartin/dev-setup`): ứng dụng từ chối tệp nén vì có mục
  `bin/bash` không an toàn hoặc không được hỗ trợ. Đây là kiểm tra an toàn khi giải nén, hoạt
  động đúng thiết kế.
- Lượt `partial` (`donnemartin/gitsome`): 39 ứng viên, không ứng viên nào bị gạn, đúng nguyên tắc
  "chạy dở thì giữ".
- Mọi ứng viên bị gạn chỉ do Bandit báo và ở mức P4.

Theo diễn giải đã chốt trước, `not_constant` là thất bại của bước gạn, "bất kể lý do". **Kết quả
đã đăng ký vì vậy là: 17 ứng viên gạn đúng, 2 ứng viên bị phép kiểm đánh là gạn sai.**

## 2. Đọc lại hai ca `not_constant` (xem xét sau khi biết kết quả)

| Vị trí | Dòng mã | Lệnh thực sự được chạy |
|---|---|---|
| `auto_cpufreq/core.py:1313` | `total_cpu_count = int(getoutput("nproc"))` | `"nproc"` |
| `auto_cpufreq/globals.py:9` | `IS_INSTALLED_WITH_AUR = path.isfile("/etc/arch-release") and bool(getoutput("pacman -Qs auto-cpufreq"))` | `"pacman -Qs auto-cpufreq"` |

Ở cả hai dòng, lệnh truyền cho `getoutput` là chuỗi hằng. Phép kiểm đã đăng ký xét **mọi** lời
gọi bắt đầu trên dòng, kể cả lời gọi bọc ngoài `int(...)` và `bool(...)`; đối số của lời gọi bọc
ngoài là một lời gọi, nên nó trả về `not_constant`. Đây là thiếu sót của phép kiểm viết trước,
không phải của bước gạn: kiểm thử tổng hợp trước khi quét không có ca lời gọi lồng nhau.

Nhận định sau khi đọc lại: **cả 19 ứng viên bị gạn đều có lệnh là chuỗi hằng.** Nhận định này là
xem xét sau, do một người đọc không mù thực hiện; nó không thay con số đã đăng ký ở mục 1.

## 3. Điều đợt này cho thấy và không cho thấy

- **Cho thấy:** trên mã ứng dụng Python thật chưa từng xem, ở lượt quét hoàn tất, bước gạn có
  hành động, và các ứng viên nó gạn là lời gọi có lệnh hằng.
- **Không cho thấy:** bước gạn có làm mất lỗi thật hay không trên các kho này (không có nhãn
  dương tính); bước gạn có ích với loại cảnh báo sai nào khác ngoài "lệnh là hằng" (G1 và G3
  không gạn ứng viên nào); và chất lượng phát hiện.
- 145 ứng viên còn lại ở danh sách chính, hầu hết ở P3 và chỉ do Bandit báo (177 trong 184 ứng
  viên chỉ có Bandit báo). Bước gạn loại phần dễ nhất; phần lớn khối lượng rà soát vẫn còn.
