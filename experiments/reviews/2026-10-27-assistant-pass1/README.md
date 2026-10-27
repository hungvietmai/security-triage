# Rà kỹ thuật đợt C và phần nhãn chờ đợt B — 27/10/2026

Lượt rà do assistant thực hiện theo yêu cầu người dùng: **8 sink đợt C và 17
cảnh báo đợt B đã được đọc/đánh giá kỹ thuật**. Đây là đề xuất có biết kết quả
trước, không phải owner review, reviewer độc lập, lượt human thứ nhất hoặc thứ
hai. Các template owner review và nhãn lịch sử đã khóa được giữ nguyên.

## Kết quả và cách sử dụng

| Tập | TP đề xuất | FP đề xuất có điều kiện | Unknown | Nhãn human mới |
|---|---:|---:|---:|---:|
| C: 8 sink | 0 | 2 | 6 | 0 |
| B: 17 cảnh báo chờ | 4 | 9 | 4 | 0 |

Đây là các nhóm đề xuất, không phải tỷ lệ hiệu quả đã xác nhận. Giữ cảnh báo
khi điều kiện áp dụng chưa được xác nhận. FP có điều kiện dùng enum
`false_positive` cùng `label_is_conditional` và `conditions`; không tạo enum
mới hoặc coi điều kiện chưa biết là đúng. Với B, thiếu đường đi gốc nên
`all_reported_flows_reviewed=false` ở cả 17 ca.

- [Đợt C: từng sink](wave-c.md), [nhãn đề xuất](wave-c.labels.json).
- [Đợt B: từng cảnh báo](wave-b.md), [nhãn đề xuất](wave-b.labels.json).
- [Danh tính, thời gian và giới hạn](session.json).
- [Manifest tải source](sources.json), [audit artifact](audit.json).
- [Kết quả evaluator C](evaluation/report.json), [lệnh và mã thoát](evaluation-command.json).
- [Các lệnh kiểm chứng](checks.json).

Hai điểm thay đổi so với nhãn B đã khóa: RC-M5 từ FP sang unknown vì
normalization chạm filesystem trước guard; RC-M7 từ FP sang unknown vì
`response.json()` không bảo đảm đối tượng trả về là dict/list. Không sửa số
liệu lịch sử 1/33 hoặc nhãn khóa để chúng phù hợp với đề xuất mới. Trường hợp
FP duy nhất v0.2 loại ở B chính là RC-M5, nên chưa thể dùng đề xuất mới để
xác nhận phép loại đó đúng.

## Phạm vi bằng chứng

Source ứng dụng được tải từ raw GitHub theo SHA đủ 40 ký tự trong inventory
B và sources lock C. B đọc cả bản lỗi và bản vá: các file chứa 17 sink giống
nhau từng byte giữa hai bản. `mlflow/server/handlers.py` có thay đổi khác;
`_validate_gateway_path`, `gateway_proxy_handler` và decorator đã được đối chiếu
riêng. Ba file source chứa sink C khớp hash của source audit từ archive đã khóa.

Rà lại 18 đường đi mẫu, 39 node của đồ thị trừu tượng và ba summary C, gồm thân
hai helper ngoài các bước taint. Audit hữu hạn đối chiếu từng route trong graph
đã lưu với path exemplar đã khai triển; không nhận là mọi thực thi Python.
Không có source archive hoặc đường đi CodeQL gốc B trong workspace này. Nhãn
B dựa trên source/caller đã đọc, bảng cảnh báo khóa và bằng chứng lịch sử;
không tái tạo một lần quét hoặc nhận là đã khôi phục đủ đường đi B.

Đọc thêm source Werkzeug 3.0.6 đúng phiên bản trong requirements của
changedetection.io và Flask 2.3.3 làm bằng chứng hành vi trả về. Flask 2.3.3 là
phiên bản tham chiếu, **không** được nhận là phiên bản thực chạy của mlflow.
Các dependency dùng tag release được ghi riêng, không giả là commit 40 ký tự.
Ba URL đoán ban đầu trả 404 cũng được giữ trong manifest; không dùng chúng
làm bằng chứng. Không cài dependencies, import/chạy source đích hoặc exploit.

Source đầy đủ nằm trong `artifacts/review-20261027-001/sources/` bị Git bỏ qua.
Manifest giữ URL, hash byte và đường dẫn. Audit chỉ đọc source, SARIF và graph:

```powershell
$env:PYTHONUTF8 = "1"
python experiments/reviews/2026-10-27-assistant-pass1/audit_evidence.py --sources experiments/reviews/2026-10-27-assistant-pass1/sources.json --output artifacts/review-20261027-001/audit-rerun.json
```

## Khoảng cách bảy ngày

[START_HERE.md](../../wave-c/closeout/owner-review/START_HERE.md) yêu cầu hai
lượt human cách ít nhất bảy ngày, lượt hai đảo thứ tự và ẩn nhãn lượt đầu.
Lượt assistant này không bắt đầu hoặc hoàn tất đồng hồ human. Không lấy ngày
tự rà 21/10 làm ngày owner bắt đầu; đến 27/10 cũng chưa đủ bảy ngày và lượt
đó không phải human review.

`session.json` ghi thời điểm sớm nhất nếu muốn làm một lượt **assistant** tiếp
theo sau bảy ngày kể từ khi hoàn tất lượt này, theo UTC và Asia/Saigon. Đó là
mốc đủ điều kiện thời gian, không phải lịch hẹn tự động, không xác nhận lượt
sau mù và không thay mốc human. Nếu owner thực sự hoàn tất lượt đầu vào
27/10, lượt hai chỉ có thể bắt đầu từ cùng thời điểm ngày 03/11 trở đi; phải
ghi thời gian thực tế của owner mới xác định được mốc chính xác.

## Phần còn mở

- Owner duyệt nhãn và giả định; giữ hai lượt thực tế cùng hồ sơ hòa giải.
- B: tìm lại artifact đường đi đã lưu nếu cần xác nhận mọi luồng báo. Không
  quét lại chỉ để thử công cụ hoặc tạo vẻ như đã có đủ bằng chứng cũ.
- RC-M4: xác lập ranh giới localhost/proxy/browser. RC-M5: xác lập scope
  metadata tại normalization. RC-M7: xác lập schema/kiểu phản hồi upstream.
- C: xác nhận deployment/root policy, thay đổi filesystem và thời gian kiểm
  tra–sử dụng. Giữ kết quả `failed_acceptance`, mức loại thêm v0.3 bằng 0 và
  tỷ lệ FP human-confirmed N/A.

## Kiểm chứng lượt này

- 85 test thực nghiệm đạt; lệnh và thời gian thực tế ghi trong `checks.json`.
- Script audit mới qua ruff/format và chạy trên source + artifact đã lưu:
  8 sink C, 18 exemplar, 39 node, 3 summary; 17 sink B khớp tọa độ và file ở
  hai snapshot. Đây là kiểm chứng dữ liệu đầu vào, không tự suy nhãn đúng.
- Khóa C selection 17, execution 98, primary results 314, paths 64, source
  review 17 và self-review 36 file đều đạt. Khóa nhãn B 4 file đạt. 13 đầu vào
  lịch sử/owner được đối chiếu lại và không thay đổi.
- Kiểm tra đầy đủ v0.3 dual **không hoàn tất**: thiếu
  `artifacts/v03/v03_strict_baseline.tar.gz`; 61 file hiện có khớp hash.
  Không tạo archive thay thế hoặc sửa manifest để lệnh thành công.
- Evaluator cuối exit 2 đúng kết quả `failed_acceptance`; lần gọi đầu exit 1
  vì truyền đường dẫn Windows có dấu backslash. Đã dùng đường dẫn POSIX cho
  lần gọi sau, giữ cả log lần lỗi và không đổi evaluator đã khóa.
- Kiểm tra 102 liên kết cục bộ trong sáu tài liệu không thấy đích thiếu.
  Không chạy lại toàn stack Docker, frontend hoặc backend vì không đổi code
  ứng dụng. Không thực hiện lượt hai sớm hoặc tạo lịch hẹn tự động.
