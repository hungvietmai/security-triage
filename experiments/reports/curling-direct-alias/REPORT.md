# Development diagnostic: direct child_process aliases

Ngày 2026-09-29. Chỉ dùng dữ liệu phát triển; không chạy tập kiểm tra.

## Câu hỏi và thay đổi

Rule upstream ban đầu có sink dạng `$CP.exec(...)`, nhưng ca curling gán trực tiếp
`var exec = require('child_process').exec` rồi gọi `exec(...)`. Đợt này bổ sung đúng
hai mẫu alias trực tiếp cho `exec` và `execSync`; giữ nguyên phần source và toàn bộ
sink cũ. Đây là một vòng phát triển rule, chưa phải baseline S1 đã đóng băng.

Rule gốc được giữ nguyên byte từ semgrep/semgrep-rules commit
`a84ff9cc2453ca91d581380de4b8b3f272f6f4be`, đường dẫn
`javascript/lang/security/detect-child-process.yaml`. Bản gốc và bản thay đổi nằm
trong [rules](../../rules). SHA-256 được ghi trong hai cấu hình; thay đổi có thể
đối chiếu trực tiếp bằng `git diff --no-index` giữa hai file.

Commit chứa runner, cả hai rule, fixture và cấu hình **trước khi chạy lại curling**:
`d6ce12ece91dcb86427e542f7a7f858f6c98a193`. Fixture đã được chạy trong quá trình phát
triển trước commit này; không trình bày nó như tập kiểm tra độc lập.

## Kết quả quan sát

| Mẫu phát triển | Rule upstream | Rule bổ sung alias |
| --- | ---: | ---: |
| Fixture: `cp.exec` với tham số hàm | 1 | 1 |
| Fixture: alias `exec` với tham số hàm | 0 | 1 |
| Fixture: alias `execSync` với tham số hàm | 0 | 1 |
| Fixture: lệnh hằng | 0 | 0 |
| Fixture: nối chuỗi nhưng không thực thi | 0 | 0 |
| Package thật `curling@0.2.0` | 0 | 1 |

Đây là số cảnh báo thô. Cảnh báo mới ở `lib/curl-transport.js:56:8–56:25`, biểu thức
`"curl " + command`. Nó trùng biểu thức ở lời gọi được tham chiếu trong báo cáo
CodeQL trước đó; cần duyệt alias giữa hai định dạng vị trí trước khi cấp điểm TP.

Hai lượt curling đều dùng Semgrep 1.178.0, cùng archive/checksum, cùng các cờ và
phạm vi mặc định; chỉ khác file rule. Cả hai hoàn tất và quét hai file. Không sửa
mã nguồn package, cài dependency hoặc thực thi exploit. CodeQL không chạy lại
trong cặp thử này; kết quả 6 cảnh báo trước đó được giữ làm bằng chứng tham khảo,
không ghép thành một thí nghiệm thời gian mới.

Điểm rút ra: mở rộng một mẫu sink có thể khắc phục bỏ sót của rule được chọn trên
ca này. Chưa có bằng chứng giảm FP, tăng F1 tổng thể hoặc lợi ích kết hợp công cụ.
CodeQL đã báo vị trí này bằng model sẵn có, nên cảnh báo Semgrep mới không phải
phát hiện bổ sung vượt CodeQL. Muốn đánh giá FP phải có cảnh báo âm được rà nhãn
và tập dữ liệu rộng hơn; hai fixture âm chưa đủ.

## Tái lập

Cả hai phương án dùng cùng CLI, chạy từ thư mục gốc repo:

```bash
python3 experiments/run_pilot.py \
  --case experiments/cases/secbench-curling-0.2.0.json \
  --config experiments/configs/development-semgrep-upstream.json \
  --configuration-commit d6ce12ece91dcb86427e542f7a7f858f6c98a193 \
  --semgrep /path/to/semgrep \
  --output artifacts/curling-upstream-new
```

Chạy lần hai với cấu hình `development-semgrep-direct-alias.json` và output mới.
Có thể thêm `--source-archive /path/to/source.tgz`; CLI kiểm tra hash theo manifest
trước khi dùng lại. Nếu không truyền, CLI tải archive theo URL đã chốt. Hai cấu
hình chỉ bật Semgrep, không cần CodeQL. Trong Docker dùng cùng tham số cấu hình
cho image thực nghiệm đã build; image này vẫn chưa được kiểm chứng build.

## Bằng chứng và kiểm tra

- [comparison.json](comparison.json): các vị trí và số cảnh báo quan sát được.
- [execution-evidence.json](execution-evidence.json): bản gốc output, rule, source
  archive và log của hai lượt, kèm output fixture. Dùng cùng định dạng nén/checksum
  như báo cáo pilot đầu.
- [development-effort.json](development-effort.json): vòng chỉnh số 1, mốc thời gian
  đo, công việc chung và giới hạn phép đo. Tính cả thời gian chờ vào ngân sách theo
  cách bảo thủ; không coi thời gian agent là giờ lao động của con người.
- [review-packet-v1.json](review-packet-v1.json): cảnh báo Semgrep mới được giữ làm
  fallback vì adapter hiện tại chỉ đề xuất sink cho một rule CodeQL. Nhãn vẫn
  unresolved; việc thiếu adapter không làm cảnh báo biến mất.

14 kiểm thử offline đạt, gồm hai kiểm thử mới cho checksum và giới hạn đường dẫn
rule local. Hai lần quét fixture đạt các kỳ vọng trong bảng trên. Lint Python đạt.
Không thay đổi protocol; không công bố chỉ số đánh giá từ ca phát triển này.

## Bước kế tiếp

Hợp cảnh báo mới vào ledger rà nhãn chung với CodeQL; xác minh source/advisory để
chốt nhãn kỹ thuật và phạm vi. Bổ sung ca phát triển có cảnh báo sai thực sự để
kiểm tra policy, và thêm ca Python trước khi chốt baseline. Tránh tiếp tục chỉnh
rule chỉ để tối ưu riêng curling; các thay đổi tiếp theo phải có lý do và ghi ngân
sách, số vòng theo protocol.
