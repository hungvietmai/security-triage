# Chủ đề án xác minh nhãn đợt C và đợt B — 28–29/10/2026

Chủ đề án kiểm từng dữ kiện mà [lượt rà assistant 27/10](../2026-10-27-assistant-pass1/README.md)
nêu ra, ở đúng commit được quét, rồi đồng ý hoặc sửa nhãn đề xuất. Kết quả và cách diễn
giải: [docs/research.md §3.10](../../../docs/research.md#310-chủ-đề-án-xác-minh-nhãn-282910).

## Phạm vi và giới hạn

- Một người rà (Hùng), một lượt, **không mù**: đã thấy đề xuất của assistant trước khi quyết
  định. Bắt đầu 28/10 lúc 21:00, kết thúc 29/10 lúc 00:40 (giờ Việt Nam); 180 phút làm thực.
- Ba quyết định chính sách được chốt sau khi đã biết ảnh hưởng của chúng tới kết quả:
  - P1: `resolve()` trước bước kiểm tra không tính là lỗ hổng CWE-22;
  - P2: chấp nhận giả định A-SYM;
  - RC-M4 là FP vì sai loại CWE.
- `all_reported_flows_reviewed = false` cho mọi nhãn.
- Không sửa nhãn hay khóa lịch sử nào. `wave_b_labels.csv` và template
  `wave-c/closeout/owner-review/` giữ nguyên.

## Tệp

| Tệp | Nội dung |
|---|---|
| `wave-c.labels.json` | 8 nhãn đợt C theo định dạng của evaluator đã khóa |
| `wave-b.labels.json` | 17 nhãn đợt B đã xác minh, kèm nhãn khóa cũ và quyết định v0.2 để đối chiếu |
| `session.json` | Người rà, thời gian, cách rà, các quyết định chính sách |
| `evaluation/` | Output của evaluator đợt C với `wave-c.labels.json` (exit 0) |
| `build_labels.py` | Script đã sinh ba file JSON trên từ phiếu xác minh |

Phiếu xác minh gốc (`PHIEU_XAC_MINH.md`) và hướng dẫn điền phiếu được chủ đề án giữ ngoài Git.
Ghi chú của từng nhóm trong phiếu được chép nguyên văn vào trường `label_evidence`, nên mọi
căn cứ quyết định đều nằm trong hai file nhãn. Chạy lại `build_labels.py` cần có bản phiếu đó.

## Chấm lại

Từ gốc repository, dùng một thư mục output mới. Evaluator là file bị khóa, nên trên Windows
cần đặt `PYTHONUTF8=1` và dùng dấu `/` trong đường dẫn:

```powershell
$env:PYTHONUTF8 = "1"
python experiments/wave-c/evaluate.py --run experiments/wave-c/results/study-001/evaluation_run.json --labels experiments/reviews/owner-verification/wave-c.labels.json --output artifacts/wave-c/owner-verification-rerun
```
