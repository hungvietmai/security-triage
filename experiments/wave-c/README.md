# Đợt C — chuẩn bị đánh giá độc lập v0.3

Trạng thái ngày 2026-10-20: **đã khóa tại máy, chưa công bố, chưa tải source, chưa quét**.
Phương pháp và cách diễn giải: [PROTOCOL.md](PROTOCOL.md).
Quyết định giữ strict/scoped: [DECISION_2026-10-20.md](../v03-interprocedural-guard/DECISION_2026-10-20.md).

## Mẫu đã chọn

Chọn 12/157 repository còn lại theo hash từ metadata advisory đã ghim; không đọc source hoặc
output của mẫu mới. `exclusions.json` có 117 định danh loại trừ, gồm alias và mọi split cũ;
20 định danh trùng quần thể hợp lệ bị loại. Sáu URL commit thiếu SHA đầy đủ/không đúng dạng
được ghi trong `inventory.json`. Không thay mẫu vì số cảnh báo hay khả năng lọc FP.

| Thứ tự | Repository | Commit snapshot |
|---|---|---|
| 1 | jelmer/dulwich | `57efc4aa1581e038915a0fd79365be53b150f4a9` |
| 2 | wkentaro/gdown | `af569fc6ed300b7974dee66dc51e9f01b57b4dff` |
| 3 | dep0we/atomic-agents-stack | `ec474f458122c5c0ca718d0df3078c8080338b2c` |
| 4 | zopefoundation/zope | `1f8456bf1f908ea46012537d52bd7e752a532c91` |
| 5 | pytorch/serve | `cdba0fd449c2fd23dcf37c54c0784035541d5114` |
| 6 | linuxfabrik/lib | `d665042c55fae83a295ebc0023e8b77f6c473a28` |
| 7 | clinical-genomics/scout | `952a2e2319af2d95d22b017a561730feac086ff1` |
| 8 | pipecat-ai/pipecat | `7519c26ac5508573c35fa3a9c4717b013993d129` |
| 9 | khoj-ai/khoj | `9801ffd2de642772f072ca496032b7c352013b6a` |
| 10 | open-webui/open-webui | `05098d25a58d03738e01c4e85e8852c3b4ad849c` |
| 11 | blacklanternsecurity/bbot | `3bc8d3a96f34f312853c9fcf8decee2a4e905f26` |
| 12 | openstack/ironic | `10590b36f541130f6a5d7a49da0f095ff8390cce` |

Đây là snapshot **tham chiếu trong metadata**, chưa xác minh khả dụng, alias/fork hoặc độc lập
ở mức họ mã nguồn. Chưa coi advisory là nhãn cả repository an toàn. Các ứng viên không chọn
được giữ trong ledger để kiểm toán, không phải danh sách thay thế sau quét.

## Kiểm tra khóa (từ gốc repository)

```powershell
python experiments/wave-c/select_repositories.py --check
python experiments/v03-interprocedural-guard/scripts/verify_freeze.py --metadata experiments/v03-interprocedural-guard/FREEZE_v0.3_dual.json
python experiments/v03-interprocedural-guard/scripts/verify_freeze.py --manifest experiments/wave-c/LOCK.sha256
```

`select_repositories.py` không ghi đè inventory tồn tại; `--check` chỉ đọc.
`LOCK.sha256` dùng đường dẫn từ gốc repository, neo protocol/config/inventory, metadata nguồn,
danh sách loại, tests và manifest/metadata v0.3. Khóa dual neo 62 đầu vào và archive strict cũ;
archive dual có hash trong metadata và nằm tại `artifacts/v03/v03_dual_2026-10-20.tar.gz` (gitignore).
Không sửa các khóa này để làm kiểm tra qua; thay đổi cần bản khóa mới và ghi lý do.

## Còn phải hoàn tất trước quét

1. Chuẩn bị tải archive đúng SHA với giới hạn ở protocol, xác minh repository/alias/fork và
   khóa byte source trong manifest riêng. Không thực thi source hay cài dependency ứng dụng.
2. Chuẩn bị runner/chấm điểm đợt C và gói rà nhãn; kiểm thử bằng fixture tổng hợp.
   Các script phát triển `run_dev.sh`/`contract_report.py` không tự trở thành evaluator độc lập.
3. Có môi trường CodeQL với đúng CLI/pack, resolution lock và lệnh đã kiểm tra. Máy Windows
   hiện tại chưa có `codeql` trên PATH; version trong metadata release là từ báo cáo cũ.
4. Khi được người dùng yêu cầu, commit/publish đầy đủ các đầu vào và bản khóa cần thiết,
   ghi URL/thời điểm dịch vụ. Chưa có commit hay push nào ở bước chuẩn bị này.

Đây là một gói phương pháp/mẫu để duyệt, **chưa đạt cổng sẵn sàng quét**.
Xem [PREPARATION_LOG.md](PREPARATION_LOG.md) cho lệnh và kết quả kiểm tra đã thực sự chạy.
