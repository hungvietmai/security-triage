# Kết quả bản thử normalization v0.2.1 — 2026-10-21

**Đạt kỳ vọng hồi quy đã khóa trong phạm vi đã chạy.** Trên bảy database Wave C
đã xem, v0.2.1 giữ **6 sink thay vì 5**, khôi phục đúng cảnh báo pipecat
`src/pipecat/runner/run.py:215:18`. Không mất sink nào của v0.2. Các cấu hình
dẫn xuất strict/scoped trên hai repository có cảnh báo cũng khôi phục sink đó.

Đây là phát triển sau phơi nhiễm, không phải một lần kiểm chứng độc lập mới.
Giữ nguyên báo cáo `failed_acceptance` và các khóa Wave C cũ. Không dùng kết quả
bản sửa để đổi trạng thái của đợt lịch sử hoặc nhận đã xác nhận an toàn chung.

## Sửa đúng một điểm

[Patch](../../normalization.patch) bỏ exclusion cho metadata sink `resolve`/
`realpath` chỉ dựa vào guard trên kết quả phía sau. Giữ nguyên barrier và
exclusion `abspath`; [IpgGuard](../../pack/IpgGuard.qll) khớp byte với thư viện
v0.3 đã khóa. Không mở rộng source/sink, validator hoặc hợp đồng. Tên pack/query
thử riêng, không ghi đè phiên bản lịch sử.

26 đầu vào của [INPUTS_LOCK.sha256](../../INPUTS_LOCK.sha256) đã được khóa tại
máy trước query đầu. Fixture và kỳ vọng là dữ liệu phát triển có chủ đích, không
nhận chúng là phản ví dụ độc lập được tạo sau khi không biết phương pháp.

## Fixture mới và hồi quy tổng hợp

| Kiểm tra | Kết quả |
|---|---|
| Marker bắt buộc có baseline | 13/13 có cảnh báo baseline |
| Kỳ vọng keep/drop của các cấu hình thử | 0 thất bại |
| Hai ca dùng đúng giá trị sau guard | Vẫn được lọc ở `checked_content`, `returned_content` |
| Cảnh báo cũ bị mất | 0, kiểm tra theo sink chính xác |
| Marker không được baseline phát hiện | 3, ghi riêng bên dưới |
| Phản ví dụ cũ được đối chiếu | 30 ca ở `paths.py`/`values.py` |
| Ca `_bad` cũ baseline thực sự phát hiện | 18/20; cả 18 tiếp tục có cảnh báo |
| Ca `_bad` cũ thiếu baseline | `collection_5_bad`, `collection_6_bad` |

Ba marker baseline không báo là `realpath_metadata`, `realpath_content`,
`lexical_control_content`. Chỉ marker đầu là câu hỏi metadata sink của
`os.path.realpath`; pinned model không cung cấp cùng sink coverage như
`Path.resolve`. Hai marker đọc nội dung đã không có cảnh báo baseline nên
không đo thêm tác dụng lọc tại đó. Không tính bất kỳ ca vắng baseline nào là
kiểm tra retention không vacuous đạt. `collection_7_good` cũ cũng không có
cảnh báo baseline; tên `_good` không thay cho bằng chứng mới về metadata.

Tổng sink trên ba tệp synthetic: `none=46`, v0.2/strict/scoped cũ đều 30,
ba cấu hình thử đều 38. [Đối chiếu thao tác](operation-audit.json) dùng AST
Python độc lập để xác nhận cả tám sink khôi phục đều tại receiver của
`Path.resolve`, không phải cảnh báo đọc nội dung sau guard. Các tên ca
`_good` cũ phản ánh kỳ vọng nội dung ban đầu; không dùng chúng để mặc nhiên gọi
metadata mới được báo là FP.

[Báo cáo fixture](fixture/fixture-report.json) giữ từng marker, từng ca cũ và
trạng thái baseline. [SARIF](fixture/fixture.sarif) giữ cả bảy cấu hình trên cùng
database. Đây là phép kiểm tra scanner bằng source synthetic chỉ được extract,
không import/chạy ứng dụng Flask.

## Đối chiếu Wave C dưới vai trò phát triển

| Repository | none cũ | v0.2 cũ | v0.2.1 | strict dẫn xuất | scoped dẫn xuất |
|---|---:|---:|---:|---:|---:|
| jelmer/dulwich | 0 | 0 | 0 | — | — |
| wkentaro/gdown | 0 | 0 | 0 | — | — |
| dep0we/atomic-agents-stack | 5 | 5 | 5 | 5 | 5 |
| zopefoundation/zope | 0 | 0 | 0 | — | — |
| pipecat-ai/pipecat | 3 | 0 | 1 | 1 | 1 |
| blacklanternsecurity/bbot | 0 | 0 | 0 | — | — |
| openstack/ironic | 0 | 0 | 0 | — | — |

V0.2.1 chạy cả bảy repository, tổng 6 sink. Hai cấu hình dẫn xuất chỉ chạy trên
hai repository có cảnh báo, mỗi cấu hình tổng 6 sink trên phần đã đo; dấu — là
không chạy, không ghi thành 0 đã đo. Các quan hệ tập con đã đặt trước đều đạt.

Cảnh báo được khôi phục là receiver tại dòng:

```python
file_path = (allowed_base / filename).resolve()
```

Nó xảy ra trước guard ở helper pipecat. Hai cảnh báo `exists`/`FileResponse` sau
guard vẫn bị lọc; atomic giữ nguyên năm cảnh báo. [CSV đối chiếu repository](repository_comparison.csv)
và [đối chiếu từng sink](sink_comparison.json) tách cấu hình cũ/mới rõ ràng.

Theo nhãn **tự rà, chưa xác nhận độc lập** đã có trước vòng sửa:

- V0.2 cũ loại một unknown; v0.2.1 giữ ca đó, tức cả sáu unknown đều được giữ.
- Hai cảnh báo còn bị lọc là FP đề xuất có điều kiện, không phải FP đã xác nhận.
  Giả định folder/triển khai chưa được phê duyệt; không tự chấp nhận vận hành.
- Số TP mới được chứng minh khôi phục không được suy từ unknown. Tỷ lệ giảm FP
  đã xác nhận vẫn **N/A**. Chưa có adjudication độc lập cho bản thử.

Không gọi đây là "Wave C nay đã đạt". Nó cho thấy bản sửa phục hồi đúng triệu
chứng đã quan sát trên dữ liệu dùng để phát triển; đánh giá lịch sử vẫn giữ lỗi.

## Thực thi, bảo toàn và phạm vi kiểm tra

Chín lệnh CodeQL đều exit 0: một create, một analyze fixture gồm bảy query,
bảy analyze database repository, tổng 18 lượt query. Mọi analyze dùng `--rerun`;
cache compile được tái sử dụng, không được hiểu là bỏ qua query evaluation.
Tổng wall time từng lệnh 730,5 giây. Phase fixture khoảng 289,0 giây; phase Wave C
907,0 giây gồm copy/hash, không tính hai số này như runtime riêng của thuật toán
hay so tốc độ với cấu hình cũ. Các cờ tài nguyên không chứng minh trần cứng.

Cả bảy database gốc khớp hash trước/sau; bản sao được kiểm tra byte trước query.
Không tải repository mới, tạo lại database repository hoặc thực thi source.
[run fixture](fixture/run.json) và [run đối chiếu](wave/run.json) giữ lệnh, thời
gian, mã thoát, hash DB; [packaging.json](packaging.json) ghi copy/hash và việc
chỉ ghép nhãn sau scan. [summary.json](summary.json) giữ số liệu máy đọc được.

85 test experiments bằng fixture tổng hợp qua. [Kiểm tra bảo toàn](preservation-checks.json)
qua với execution/selection/result/review/self-review locks, v0.3 dual và
archive, 1.628 đầu vào toolchain. Không chạy frontend/backend app suites,
BenchmarkPython hoặc toàn bộ kịch bản hợp đồng v0.3 trong vòng hẹp này; không
nhận những bộ chưa chạy là đã pass. [Khóa kết quả](RESULTS_LOCK.sha256) giữ riêng
vòng phát triển này, không thay khóa lịch sử.
