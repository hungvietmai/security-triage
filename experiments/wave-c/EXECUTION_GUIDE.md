# Đợt C — source, runner và evaluator

Tiếp nối [giao thức đã khóa](PROTOCOL.md); không sửa `LOCK.sha256`, inventory hoặc bản khóa v0.3.
Tài liệu này mô tả phần thực thi được chuẩn bị sau khóa mẫu, trước khi xem bất kỳ output quét
nào của mẫu nghiên cứu. `EXECUTION_LOCK.sha256` neo thêm source/toolchain/runner/evaluator.

CSV nhãn wave B đã khóa có CRLF. `.gitattributes` giữ riêng tệp đó ở `-text` để Git không
chuẩn hóa thành LF khi commit, làm khác byte với hash lịch sử. Không sửa CSV hay khóa cũ.

## Source đã chuẩn bị

`sources.lock.json` ghi cả 12 lượt tải theo đúng thứ tự mẫu, với byte gốc, hash và metadata
GitHub trong `artifacts/wave-c/sources/`. GitHub metadata xác minh SHA tồn tại, canonical repo,
alias/fork và nhóm liên quan. Không sửa inventory gốc hoặc chọn repository thay thế.

| Trạng thái | Số | Repository |
|---|---:|---|
| prepared | 7 | dulwich, gdown, atomic-agents-stack, Zope, pipecat, bbot, ironic |
| acquisition_failed | 3 | pytorch/serve, khoj, open-webui: vượt 50 MiB |
| rejected_archive | 2 | linuxfabrik/lib, scout: archive chứa symlink |

Các archive bị từ chối do symlink vẫn giữ nguyên byte và hash. Các lượt vượt giới hạn không
được ghi là download hoàn tất hoặc có checksum toàn archive. Không làm mềm giới hạn sau khi
biết dữ liệu. Không tạo symlink, không thực thi source và không cài dependency ứng dụng.
`prepare_sources.py --check` không tải lại; cache thiếu/hỏng là lỗi, không tự refetch TOFU.
Mọi near-duplicate review còn `pending`; metadata không chứng minh độc lập về họ mã nguồn.

## Toolchain

Ubuntu WSL có CodeQL CLI 2.27.1 tại
`artifacts/toolchains/codeql-2.27.1/codeql/codeql`. Archive Linux chính thức có SHA-256
`6ad2cead390cecf62dd59ae7ffd673d216902a9c00975ce107a362464a8b891e`, xác minh với
[release chính thức](https://github.com/github/codeql-cli-binaries/releases/tag/v2.27.1).
Phiên bản CLI đã chạy kiểm tra thực tế; đây không còn chỉ là thông tin từ báo cáo cũ.

`prepare_toolchain.py` cài `codeql/python-all@7.2.6`, `codeql/python-queries@1.8.11` và phụ
thuộc đã resolve trong cache workspace. V0.2/v0.3 được copy rồi install/generate trong artifacts;
không ghi vào pack gốc đã khóa. `toolchain.lock.json` giữ 1.628 hash, output version, download,
resolution và lệnh. Không tự đổi phiên bản khi thiếu cache.

Diagnostics dùng `database run-queries --rerun`, rồi tìm duy nhất BQRS của đúng query dưới
`database/results/` và decode CSV. Cách này giữ yêu cầu chạy lại trong protocol; vị trí BQRS,
CSV và tùy chọn `--rerun` của lệnh này đã được xác minh bằng lượt chạy tổng hợp thật.
Help của `query run` không liệt kê `--rerun`; runner không dựa vào cú pháp đó.
Tham chiếu: [database run-queries](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/database-run-queries),
[query run](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/query-run).
Các tùy chọn thực dùng đã được kiểm tra với `--help` của CLI 2.27.1, không chỉ dựa vào docs mới.

## Lệnh (Ubuntu WSL, từ Windows)

```powershell
wsl -d Ubuntu --exec python3 /mnt/d/github/security-triage/experiments/wave-c/prepare_sources.py --check
wsl -d Ubuntu --exec python3 /mnt/d/github/security-triage/experiments/wave-c/prepare_toolchain.py --check
wsl -d Ubuntu --exec python3 /mnt/d/github/security-triage/experiments/wave-c/run.py --plan --output artifacts/wave-c/plan-001
```

Plan không giải nén source hay tạo database. Các output directory phải mới; không xóa/ghi đè
một lượt có sẵn để chạy lại cho số đẹp. Runner thực thi tuần tự, tối đa 2 thread/5.000 MiB,
30 phút tạo database, 20 phút mỗi analyze/diagnostic/decode, ngân sách tổng 24 giờ.
Timeout giết cả process group trên Linux và giữ stdout/stderr/lệnh/mã thoát/thời gian.
Runner không retry scanner tự động; giới hạn một retry của protocol là trần, không bắt buộc retry.

Sau khi người dùng yêu cầu commit/push, bản khóa và mọi đầu vào cần có trên commit được công bố.
Điền `publication.json` theo template bằng SHA commit và ID workflow **thực sự có trên GitHub**.
Runner đọc workflow qua API, kiểm tra `head_sha`, thời điểm `created_at` do dịch vụ ghi, rồi so
`git show <commit>:<path>` với từng hash khóa. Không dùng ngày tự ghi hoặc tag chưa push làm chứng cứ.

```powershell
wsl -d Ubuntu --exec python3 /mnt/d/github/security-triage/experiments/wave-c/run.py --execute --output artifacts/wave-c/study-001
wsl -d Ubuntu --exec python3 /mnt/d/github/security-triage/experiments/wave-c/evaluate.py --run artifacts/wave-c/study-001/run.json --output artifacts/wave-c/review-001
```

Thiếu chứng cứ công bố thì `--execute` dừng trước tạo thư mục chạy/source/database. Không có
flag bỏ qua cổng này. Script `smoke_runner.py` tách riêng chỉ dùng hai fixture tổng hợp tự tạo;
nó không nhận inventory/source nghiên cứu làm đầu vào và không phải cổng bypass cho held-out.

## Kiểm chứng và review

- Runner giữ SARIF riêng từng cấu hình, bốn bảng v0.3 và bảng module Python đã trích xuất.
  So với danh sách `.py` trong archive để báo phần thiếu; không dùng số lượng tổng làm chứng minh
  coverage. Có file không được trích xuất thì `incomplete_extraction`, giữ output để rà nhưng
  không gộp vào tổng của các repository hoàn tất.
- Evaluator đọc mọi SARIF run, gộp sink trùng vị trí, từ chối vị trí thiếu cột/URI tuyệt đối,
  kiểm hash output và chuỗi tập con. Lượt thiếu/lỗi khác hoàn toàn lượt thành công 0 cảnh báo.
- `review_packet.json` không chứa nhãn cũ, tên rule hay quyết định lọc. Mọi sink bị loại được
  xếp trước, sau đó theo hash đã định trong protocol. Thông tin nguồn/source context có thể
  làm lộ công cụ; không gọi đây là review hoàn toàn mù.
- `labels.template.json` để nhãn, reviewer, ngày rà, root cause và scope trống. Chỉ điền từ
  review thực tế; không nhận reviewer thứ hai hoặc chủ đề án duyệt thay người dùng.
- Đối với mỗi phép loại: cần nhãn FP đã duyệt, mọi luồng đã rà, bằng chứng gốc/containment
  khớp và căn cứ cho mọi giả định áp dụng. `supported` không kèm bằng chứng vẫn là scope unknown.
  Giữ số `raw_suppressed` dù quyết định vận hành là giữ cảnh báo.
- TP/TP_conditional/unknown bị loại, bằng chứng thiếu/mâu thuẫn hoặc tập con sai làm đánh giá
  `failed_acceptance`. Thiếu nhãn không tự thành FP hay true negative.
- Giữ review lượt 1/lượt 2/hòa giải riêng, không ghi đè. Evaluator nhận mảng label JSON đã chọn
  qua `--labels`; record reviewer/date/status phải có thật. Gói đề xuất chưa phải human review.

Thực hiện kiểm tra theo [nhật ký mới](EXECUTION_LOG.md). Chưa có kết quả quét hay nhãn đợt C.
