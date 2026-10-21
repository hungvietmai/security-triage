# Bản thử sửa normalization v0.2.1

Phát triển sau khi đã xem Wave C và
[tự rà nhãn](../wave-c/closeout/self-review/REVIEW.md). Giữ nguyên Wave C lịch sử,
mọi khóa cũ và báo cáo `failed_acceptance`; không nhận dữ liệu đã xem là kiểm
chứng độc lập cho bản sửa.

## Thay đổi

[normalization.patch](normalization.patch) chỉ sửa `SafetyEvidence::excludedSink`:
không loại sink `Path.resolve`/`os.path.realpath` dựa vào containment-check trên
kết quả ở phía sau. Giữ exclusion `abspath` và mọi barrier khác. Không thêm
source/sink, model hoặc hợp đồng.

| ID query thử | Vai trò |
|---|---|
| `v021` | Baseline v0.2 có đúng thay đổi predicate trên |
| `v031` | Strict dẫn xuất trên baseline sửa, IpgGuard giữ nguyên byte |
| `v031s` | Scoped dẫn xuất trên baseline sửa, IpgGuard giữ nguyên byte |

Các ID dẫn xuất không đổi tên hay ghi đè kết quả `v03`/`v03s` gốc. Pack có tên
riêng `security-triage/python-normalization-v021`; extension sink contract rỗng
chỉ trỏ tới tên pack mới. Đây chưa phải phiên bản phát hành hoặc cấu hình mặc
định của ứng dụng.

## Kỳ vọng và khóa

[PLAN.md](PLAN.md), [expectations.json](expectations.json) và
[INPUTS_LOCK.sha256](INPUTS_LOCK.sha256) được khóa tại máy trước query đầu.
Khóa 26 đầu vào, gồm pack, runner, fixture, hai tệp phản ví dụ tổng hợp cũ và
query/library baseline. Không nhận đây là bằng chứng công bố phương pháp độc
lập trước quét. [preflight.json](preflight.json) ghi kiểm tra thay đúng một
predicate và giữ nguyên IpgGuard.

Fixture có 16 marker ở từng thao tác. Mười ba marker bắt buộc phải có baseline;
ba marker còn lại quan sát baseline để ghi rõ ca không được thực thi phép lọc.
`os.path.realpath` có truy cập metadata trong Python nhưng không được mô hình
hóa như `Path.resolve` trong danh sách FileSystemAccess đang ghim. Không được
biến việc không có cảnh báo tại normalizer này thành kết quả giữ cảnh báo đúng.

Các ca giữ raw/giá trị trả về bị bỏ là đối chứng giữ cảnh báo khi thiếu chứng cứ
được công nhận, không tự khẳng định mỗi ca là TP khai thác được. Ngay cả dưới
giả định filesystem ổn định, hai biểu thức đường dẫn khác nhau đôi khi vẫn trỏ
cùng đích. Bộ này kiểm tra chính sách thận trọng đã khóa và hành vi scanner,
không thay thế oracle lỗ hổng độc lập.

## Thực thi

Dùng CodeQL 2.27.1/python-all 7.2.6 đã chuẩn bị cho Wave C; không cài dependency
ứng dụng. Từ repository root qua Ubuntu/WSL, chọn thư mục đầu ra mới:

```powershell
wsl -d Ubuntu --exec python3 /mnt/d/github/security-triage/experiments/v021-normalization/run.py --phase fixture --output artifacts/v021-normalization/replay-fixture-001
wsl -d Ubuntu --exec python3 /mnt/d/github/security-triage/experiments/v021-normalization/run.py --phase wave --fixture-result artifacts/v021-normalization/replay-fixture-001/fixture-report.json --output artifacts/v021-normalization/replay-wave-001
```

Runner kiểm tra lock trước mỗi phase và từ chối output đã tồn tại. Phase wave
chỉ chạy sau khi fixture đạt. Mọi analyze có `--rerun --threads=2 --ram=5000`,
timeout 20 phút; tạo fixture DB tối đa 30 phút. Cờ tài nguyên không chứng minh
giới hạn cứng cho toàn cây tiến trình. Không import/chạy source Flask hoặc
source repository, không quét các cặp nghiên cứu held-out lịch sử.

Phase wave dùng bản sao database của bảy repository đã quét, v0.2.1 trên cả bảy
và hai cấu hình dẫn xuất trên hai repository có cảnh báo. Năm repo zero-alert
không được mô tả là đã chạy lại cấu hình dẫn xuất. Hash file DB gốc trước/sau
được lưu riêng. Quan hệ tập cảnh báo và các sink được khôi phục được tính trực
tiếp từ SARIF, không lấy nhãn FP làm đầu vào scanner.

[Vòng phát triển đã hoàn tất](results/round-001/RESULTS.md): 13 marker bắt buộc
được baseline phát hiện và đạt kỳ vọng, không mất sink cũ. Trên cả bảy repository,
v0.2.1 giữ 6 sink thay vì 5, khôi phục một normalization unknown đề xuất ở pipecat.
Ba marker mới và hai ca `_bad` cũ không có baseline được ghi riêng, không tính
thành kiểm chứng retention đạt. 85 test tooling qua và database gốc không đổi.

[Quyết định](DECISION_2026-10-21.md) giữ bản thử cho phát triển, không đổi cấu
hình mặc định hoặc xóa trạng thái failed_acceptance lịch sử. Các nhãn, giả định
triển khai và trạng thái kiểm chứng độc lập được giữ riêng với hồi quy của bản sửa.
