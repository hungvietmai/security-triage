# Rà soát vị trí và nhãn: pilot phát triển

Phiên bản triển khai: `sink-proposals-v1`, ngày 2026-09-29.
Áp dụng [EVALUATION_PROTOCOL.md](EVALUATION_PROTOCOL.md), không thay đổi policy.

## Chạy lại từ bằng chứng trong repo

Không cần cài hoặc chạy lại scanner:

```bash
python3 -m experiments.build_review \
  --evidence experiments/reports/curling-0.2.0/execution-evidence.json \
  --attempt 002 \
  --output artifacts/curling-review-new.json

python3 -m unittest experiments.test_runner experiments.test_review -v
```

Đường dẫn output phải chưa tồn tại để tránh ghi đè công việc rà nhãn.
Trong image thực nghiệm có thể thay entrypoint bằng `--entrypoint python`, rồi
truyền `-m experiments.build_review` cùng các tham số trên. Image chưa được kiểm
chứng build; kết quả hiện tại được tạo bằng Python chạy trực tiếp.

CLI kiểm tra checksum payload, từng artifact, archive nguồn và SARIF so với run
record. Công cụ này đọc gói bằng chứng tin cậy của repo, không phải endpoint nhận
gói dữ liệu tùy ý từ người dùng. Không chạy mã nguồn của package.

## Kết quả hiện tại

[review-packet-v1.json](reports/curling-0.2.0/review-packet-v1.json) giữ đủ 6 cảnh
báo gốc bằng tham chiếu SARIF/checksum. Mỗi cảnh báo có một đơn vị fallback riêng.
Cả 6 có đề xuất cùng một sink, dựa vào liên kết `[shell command](id)` trong message
và `relatedLocations` tương ứng. ID được đọc từ message, không cố định bằng 2.
Vùng nguồn ứng viên là `lib/curl-transport.js:56:3–58:5`, đối số `shell_command`.

Đây là adapter hẹp cho `js/shell-command-constructed-from-input`. Nó kiểm tra
đường dẫn, biên dòng/cột và lưu ngữ cảnh nguồn; chưa chứng minh callee hoặc span
bằng AST. Rule khác, tham chiếu mơ hồ, thiếu vị trí hoặc nguồn không đối chiếu được
sẽ giữ fallback và lý do. Không ghép chỉ vì cùng CWE hay gần dòng nhau.

Mọi đề xuất còn chờ duyệt. Vì chưa có sink assignment được chấp nhận, tỷ lệ chưa
ghép tự động theo protocol vẫn là 100%; tỷ lệ có **đề xuất** là 100%. Hai số này đo
hai việc khác nhau. Sáu fallback và một sink ứng viên là các phương án định danh,
không phải bảy đơn vị được cộng vào mẫu số đánh giá.

## Cách rà soát

1. Tạo bản sao packet với tên phiên bản mới. Giữ nguyên raw reference, checksum,
   vùng báo gốc và dữ liệu đề xuất. Packet hiện tại không làm mù tên công cụ;
   trường `blinded` ghi rõ điều đó.
2. Kiểm tra từng `source_context` với nguồn trong archive. Xác minh span bao đúng
   lời gọi thực thi lệnh và đúng vai trò đối số. Với ca curling, cần lần theo
   `exec` về import `child_process` và tham số `command` của API export.
3. Nếu xác nhận đề xuất, điền `mapping_review.decision = accept_candidate`, danh
   sách `accepted_unit_ids`, tên người rà và lý do/bằng chứng. Nếu giữ vị trí báo
   gốc, dùng `keep_fallback` với fallback ID. Khi chưa xác định được alias hoặc
   danh tính lỗ hổng, để `unresolved`; không tạo TP mới để cấp điểm cho công cụ.
4. Gán nhãn ở mục `labels` cho đơn vị đã chọn: `technical_verdict` và
   `scope_verdict` riêng biệt. Điền CWE đã thẩm định, giả định, nguồn bằng chứng,
   reviewer, thời điểm, phiên bản nhãn và threat model. Không lấy sự đồng thuận
   giữa hai công cụ làm nhãn đúng/sai.
5. `truth_set` chỉ là trường rà soát dự kiến: `K` cho vị trí thật có nguồn độc lập,
   `N` cho vị trí thật mới xác nhận, `F` cho khẳng định CWE-78 sai trong phạm vi;
   `outside_scope` hoặc `unresolved` cho các trường hợp còn lại. Chỉ chốt sau khi
   hai nhãn và bằng chứng nhất quán. Lưu mọi thay đổi bằng commit.
6. Rà soát thứ hai theo protocol; nếu chưa có người thứ hai, ghi nhận thiếu thay
   vì tự điền sự đồng thuận. Assistant không được ghi thành người rà độc lập.

Việc điền các trường trên hiện là quy trình rà thủ công. Chưa có validator cho
packet đã duyệt, bộ giải alias chung hoặc hàm tính chỉ số; `metrics` vẫn là null.
Các bộ phận đó phải kiểm tra tính nhất quán trước khi nhận nhãn để tính điểm.

## Giới hạn và đầu việc kế tiếp

Packet chỉ bao gồm cảnh báo từ hai lượt quét đã lưu. Nó chưa phải ledger đánh giá
hoàn chỉnh: cần bổ sung vị trí K không có cảnh báo, hợp kết quả S1/ST và các cấu
hình đã chốt, rồi giải alias nhất quán cho tất cả cấu hình. Thiếu kết quả quét
không được coi là dự đoán âm tính; trạng thái scanner được giữ trong packet.

Tiếp theo: duyệt ánh xạ/nhãn ca đầu, chốt tập file/rule chung trên tập phát triển,
thêm ca Python, rồi triển khai policy và bộ tính chỉ số với validator. Chưa chạy
tập kiểm tra. Protocol không cần sửa cho bước này vì đây là hiện thực hóa việc
giữ fallback và tách nhãn đã quy định.
