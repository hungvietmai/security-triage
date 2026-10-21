# Đường đi bổ sung cho tám sink — 2026-10-21

Đã bổ sung đường đi cho **8/8 sink**, đối chiếu đúng từng cặp nguồn–sink với
SARIF `none` đã khóa, kể cả tọa độ kết thúc. Có **18 đường đi mẫu** và **114 dòng
cạnh có vị trí mã nguồn**. Đây là chẩn đoán **hậu kiểm**, sau khi đã xem kết quả;
không phải một phép đánh giá độc lập mới hoặc thay đổi phương pháp chính.

| Repository | Sink | Đường đi mẫu | Dòng cạnh có vị trí |
|---|---:|---:|---:|
| dep0we/atomic-agents-stack | 5 | 15 | 103 |
| pipecat-ai/pipecat | 3 | 3 | 11 |
| Tổng | 8 | 18 | 114 |

Số đường đi và số cạnh không phải số quan sát độc lập. Kết quả chính giữ nguyên:
`none=8`, `v0.2=5`, `strict=5`, `scoped=5`; mức loại thêm của v0.3 là **0**.
Không đổi nhãn: 4 FP đề xuất / 4 unknown, chưa có nhãn chủ đề án xác nhận.

## Cách đọc hồ sơ

Mỗi thẻ chứa các bước CodeQL và liên kết tới source tại đúng commit; không đưa
nhãn đề xuất hoặc quyết định lọc vào thẻ. Thứ tự vẫn theo hàng đợi đã công bố,
nên không tuyên bố đây là một lượt rà mù độc lập.

| Thẻ | Sink | Số đường đi mẫu |
|---|---|---:|
| [8dcaf01d](units/8dcaf01d7907a8adda39bd13.md) | pipecat `run.py:215:18` | 1 |
| [5859e664](units/5859e664e867d805eef70b8c.md) | pipecat `run.py:268:16` | 1 |
| [c295eacf](units/c295eacf017f952ad64f5391.md) | pipecat `run.py:273:34` | 1 |
| [b99a22cc](units/b99a22ccccd631527dd62004.md) | atomic `_io.py:110:17` | 3 |
| [29973e5c](units/29973e5cc3b0b49c809a4873.md) | atomic `serve.py:113:16` | 3 |
| [788be445](units/788be445943d8a953ce5a232.md) | atomic `serve.py:141:16` | 3 |
| [0f3b3e4c](units/0f3b3e4c8adbc208a0ca43bd.md) | atomic `serve.py:145:23` | 3 |
| [1d3c60e0](units/1d3c60e0364a3a006fa676d3.md) | atomic `serve.py:113:37` | 3 |

Đường đi của atomic hiển thị ba nhánh: `/agents/`, `/_dashboard/` và đường dẫn
trần. Nhánh `/agents/` chứa bước nối `dashboard.html` sau khi helper đã kiểm tra
thư mục cha; chủ đề án cần xét điều kiện symlink có sẵn theo A-SYM. Đường đi
pipecat tới `exists`/`FileResponse` đi qua giá trị trả về của
`_resolve_download_path`; vẫn cần rà source của guard và hợp đồng folder.

Các bước này hỗ trợ đọc mã; chúng không tự xác nhận giả định triển khai, quyền
truy cập hoặc tính khả thi của một đường thực thi. Chi tiết source và quan sát
tổng hợp nằm trong [hồ sơ trước](../review-001/REVIEW.md).

## Giới hạn biểu diễn

- SARIF chứa đường đi mẫu do CodeQL chọn, không liệt kê mọi đường thực thi.
  Một bước guard không xuất hiện trên đường taint không chứng minh guard vắng mặt.
- CSV là phép chiếu các cạnh `getASuccessor()` có vị trí và tên callable, giới
  hạn bởi khả năng đi từ nguồn tới sink trong đồ thị trừu tượng. Nó có thể chứa
  bước gọi hàm được tóm tắt, chu trình hoặc kết hợp không khả thi; không phải
  siêu tập mọi bước SARIF. Ví dụ pipecat `exists` có 8 bước SARIF nhưng 4 dòng
  cạnh được chiếu. JSON thô giữ cả bảng `edges`, `nodes`, `subpaths`, `#select`;
  ID thực thể chỉ có ý nghĩa trong kết quả truy vấn tương ứng.
- Khớp endpoint trên hai database này là kiểm tra nhất quán báo cáo, không phải
  chứng minh tương đương tổng quát giữa mọi truy vấn hoặc bằng chứng an toàn.
- `all_reported_flows_reviewed=false`, human review vẫn pending cho cả tám sink.
  SARIF và `trace_available=false` trong gói chính được giữ nguyên; chỉ gói bổ
  sung có trace. Không ghi người rà/ngày rà thay chủ đề án.

## Thực thi và bảo toàn

[Kế hoạch hậu kiểm](PLAN.json) được ghi trước lượt chẩn đoán này, nhưng sau kết
quả chính. Chỉ dùng hai repository có cảnh báo trong mẫu đã khóa, theo thứ tự
inventory; không chọn thêm mẫu hoặc quét cặp nghiên cứu lịch sử.

[ReviewPaths.ql](pack/ReviewPaths.ql) giữ các import, cấu hình PathInjectionFlow
và ExtraSanitizer rỗng của `cwe22_none.ql`, đổi phần biểu diễn sang `flowPath`.
[ReviewEdges.ql](pack/ReviewEdges.ql) chỉ xuất đồ thị của cùng cấu hình.
`SafetyEvidence.qll` và dependency lock là bản sao khớp byte với baseline;
CodeQL vẫn là 2.27.1, python-all 7.2.6. Không thêm source, sink, sanitizer,
model pack hoặc quy tắc lọc.

Hai database được sao chép và kiểm tra hash trước khi truy vấn. [run.json](run.json)
giữ hash từng file gốc trước/sau và xác nhận cả hai database gốc không đổi.
Không tạo lại database, import hay thực thi source ứng dụng. Bốn lệnh truy vấn
đều dùng `--rerun --threads=2 --ram=5000`, timeout 1.200 giây/lệnh, không retry.
Không tuyên bố các cờ này chứng minh trần tài nguyên cứng cho toàn cây tiến trình.

Chín lệnh CodeQL gồm kiểm tra version, bốn truy vấn, bốn decode đều exit 0;
tổng wall time từng lệnh **245,282 giây**, không gồm copy/hash/đóng gói.
Log có cảnh báo import local `SafetyEvidence`; log gốc được giữ trong [logs](logs).
Gói chính vẫn giữ nguyên 105 lệnh và runtime riêng của nó. Mã chạy/đóng gói ở
[tools/run_paths.py](tools/run_paths.py), [tools/package_paths.py](tools/package_paths.py);
dữ liệu thô ở [inputs](inputs), đối chiếu ở [summary.json](summary.json).

Lệnh thực tế, chạy từ repository root qua Ubuntu/WSL:

```powershell
wsl -d Ubuntu --exec python3 /mnt/d/github/security-triage/experiments/wave-c/results/paths-001/tools/run_paths.py --output artifacts/wave-c/review-paths-001
python experiments/wave-c/results/paths-001/tools/package_paths.py --run artifacts/wave-c/review-paths-001
```

Các thư mục đầu ra phải mới. Gói này đã đóng băng; không chạy lại bước đóng gói
vào đây. Khi tái hiện chẩn đoán, dùng tên mới dưới `artifacts/wave-c/` và giữ kết
quả tái hiện riêng để so sánh; không ghi đè các gói hiện có.

## Kiểm tra và bước tiếp

- [85 kiểm tra experiments](checks/experiments.json) qua bằng fixture tổng hợp;
  không dùng scanner trên cặp nghiên cứu cũ để thử tooling. Đây là regression
  suite; bằng chứng thực thi QL nằm riêng trong log chẩn đoán.
- [Kiểm tra bảo toàn](checks/preservation.json) đều exit 0: execution 98 đầu vào,
  v0.3 dual 62 đầu vào và archive, selection 17 đầu vào, gói chính 314 file,
  hồ sơ trước 17 file, toolchain 1.628 đầu vào, source cache 12 repository.
- [Khóa gói này](PATHS_LOCK.sha256) giữ byte của plan, QL, scripts, log, dữ liệu
  thô, đối chiếu và tám thẻ. Không thay khóa phương pháp hoặc khóa kết quả cũ.

Chủ đề án tiếp tục [hướng dẫn rà](../study-001/REVIEW_GUIDE.md) với các đường đi
bổ sung này, lưu lượt rà thực tế rồi chấm lại bằng evaluator đã khóa. Lượt hai
sau ít nhất 7 ngày tính từ lượt rà đầu thực tế. Chưa có lượt human review nào
trong gói này; không dùng thời điểm tạo gói làm thời điểm bắt đầu khoảng chờ.
