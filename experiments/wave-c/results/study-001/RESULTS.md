# Wave C — kết quả scanner đã khóa

Ngày tổng hợp: 2026-10-21. Đây là kết quả scanner và gói rà nhãn, chưa phải xác nhận hiệu quả/an toàn độc lập.

| Thứ tự | Repository | Trạng thái | none | v0.2 | strict | scoped |
|---|---|---|---:|---:|---:|---:|
| 1 | jelmer/dulwich | completed | 0 | 0 | 0 | 0 |
| 2 | wkentaro/gdown | completed | 0 | 0 | 0 | 0 |
| 3 | dep0we/atomic-agents-stack | completed | 5 | 5 | 5 | 5 |
| 4 | zopefoundation/zope | completed | 0 | 0 | 0 | 0 |
| 5 | pytorch/serve | acquisition_failed | — | — | — | — |
| 6 | linuxfabrik/lib | rejected_archive | — | — | — | — |
| 7 | clinical-genomics/scout | rejected_archive | — | — | — | — |
| 8 | pipecat-ai/pipecat | completed | 3 | 0 | 0 | 0 |
| 9 | khoj-ai/khoj | acquisition_failed | — | — | — | — |
| 10 | open-webui/open-webui | acquisition_failed | — | — | — | — |
| 11 | blacklanternsecurity/bbot | completed | 0 | 0 | 0 | 0 |
| 12 | openstack/ironic | completed | 0 | 0 | 0 | 0 |

## Số liệu

- 12/12 lượt acquisition được giữ; 7 repository quét hoàn tất; không thay repository lỗi.
- Trên các repository hoàn tất: none=8, v0.2=5, strict=5, scoped=5 sink.
- v0.2 loại 3 sink so với none. Strict loại thêm 0; scoped loại thêm 0 so với v0.2; phần scoped tăng so với strict=0.
- Coverage AllowedRoot: strict 0/5, scoped 0/5 sink v0.2. Mẫu số 0 phải đọc là N/A.
- Số sink chờ rà: 8; 8 sink không có codeFlows trong SARIF. Nhãn chủ đề án đã xác nhận: 0.
- Tỷ lệ giảm FP: N/A khi chưa có FP được chủ đề án xác nhận. Số raw_suppressed không tự trở thành FP được loại đúng.
- 105 lệnh scanner/diagnostic/decode; tổng wall time từng lệnh 3358.2 giây. Đây không phải benchmark tốc độ giữa các cấu hình.

## Cách diễn giải và bước tiếp

Không sửa QL/policy hoặc chọn lại mẫu sau khi xem output. Giữ nguyên các manifest phương pháp đã công bố.
Record zero incremental suppression and stop rule expansion in this wave.
Giữ strict/scoped báo riêng; kết quả phát triển mlflow không trở thành bằng chứng độc lập của Wave C.

Nếu v0.3 không loại sink nào, việc không mất cảnh báo là hiển nhiên trên phần đã quan sát; không dùng nó làm phép thử an toàn không vacuous của quy tắc resource-derived.

Hoàn tất rà nhãn theo REVIEW_GUIDE.md và kiểm tra quan hệ/near-duplicate trước khi nhận là đánh giá xác nhận. Ghi chú đề xuất không phải human review hoặc một reviewer độc lập.

## Giới hạn và khả năng tái lập

- Ba archive vượt 50 MiB; hai archive có symlink bị từ chối theo giới hạn đã khóa. Chúng là kết quả thiếu, không phải repository 0 cảnh báo.
- So extractor với danh sách .py trong archive; giữ module bổ sung riêng. Xem original_run.json cho từng file thiếu/thêm, không suy coverage chỉ từ tổng số module.
- Kiểm tra exact-byte overlap chỉ xét các snapshot mới và file >=512 byte; không chứng minh độc lập ngữ nghĩa hoặc độc lập với dữ liệu phát triển. Near-duplicate review vẫn pending.
- Mọi lệnh CodeQL giữ --threads=2/--ram=5000. Đã thấy nhiều worker Python extractor cùng lúc; chưa xác minh trần CPU/RAM cứng cho toàn cây tiến trình. Không nhận là đã đo/chứng minh giới hạn hai worker.
- evaluation_run.json được tái tạo bằng cách đổi đường dẫn tới bản sao SARIF/CSV giống từng byte; original_run.json giữ bản gốc. Xem packaging.json và RESULTS_LOCK.sha256.
- Source, database và cache vẫn ở artifacts/; gói kết quả đủ để chạy lại evaluator mà không chạy scanner.

Bảng trạng thái và các giới hạn trên là bắt buộc khi trích số liệu; không gọi toàn bộ mẫu 12 repository là quét hoàn chỉnh.

## Kiểm tra cuối

- Check 1: exit 0; xem checks.json và check-1.*.log.
- Check 2: exit 0; xem checks.json và check-2.*.log.
- Check 3: exit 0; xem checks.json và check-3.*.log.
- Check 4: exit 0; xem checks.json và check-4.*.log.
- Check 5: exit 0; xem checks.json và check-5.*.log.

Kết quả đối chiếu báo cáo gốc/bản sao: giống nhau, ngoại trừ hash của run manifest đổi đường dẫn.
