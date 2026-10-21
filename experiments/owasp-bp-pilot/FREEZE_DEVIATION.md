# Sai lệch giữa bản khóa v0.1/v0.2 và tệp đã commit

Ngày lập: 2026-10-16. `FREEZE_v0.1.sha256` và `FREEZE_v0.2.sha256` giữ nguyên làm bằng chứng lịch sử; báo cáo này
không sửa chúng. Kiểm chứng: `scripts/verify_post_format.sh WORK_DIR` (CodeQL 2.27.1 theo `tools/pins.env`).

## 1. Sai lệch

| Tệp | Hash trong bản khóa | Hash đã commit (`a2bb650`, không đổi tới nay) |
|---|---|---|
| `ql_v02/gen.py` | `51f2ca4e…` (v0.2) | `4e8eb475…` |
| `scripts/evaluate_cex.py` | `45657424…` (v0.2) | `3d824a61…` |
| `ql/gen.py` | `f71fbe0f…` (v0.1) | `f0525371…` |
| `scripts/evaluate.py` | `899d0d66…` (v0.1) | `f3791bdb…` |
| `scripts/evaluate_evidence.py` | `f0433d01…` (v0.1) | `d44bf24b…` |

`SafetyEvidence.qll` và `qlpack.yml` của cả hai phiên bản khớp bản khóa; `split.json` và
`artifacts/owasp-bp-pilot/evidence.sarif` khớp `FREEZE_v0.1.sha256`.

Bản trước định dạng không còn: hai bản khóa được tạo ở môi trường làm việc từ xa trước khi commit, và không blob nào trong
kho git (kể cả blob mồ côi) có hash đã khóa; các biến thể CRLF, dòng cuối, khoảng trắng cuối dòng cũng không khớp. Ghi
chú "Ghi chú định dạng sau đóng băng" trong `README.md` cho biết các script được định dạng bằng ruff 0.16.9 sau khi khóa
và liệt kê đúng hash đã commit.

Ghi chú đó có một điểm **không đúng**: "các truy vấn sinh ra giống hệt từng byte". `gen.py` đã commit sinh
`table/Evidence.ql` có hash `2c34e96b…`, khác `ql_v02/table/Evidence.ql` đã commit và đã dùng ở đợt A (`994616f9…`).
Khác biệt chỉ là cách xuống dòng trong chuỗi QL của mẫu (không đổi ngữ nghĩa QL); `ruff format` không đổi nội dung chuỗi,
nên thay đổi này không do ruff mà do một chỉnh sửa khác lúc định dạng. Tám truy vấn cảnh báo sinh ra giống hệt từng byte.

## 2. Phiên bản đã dùng ở từng lượt đánh giá

| Lượt | Thời điểm | Phiên bản | Căn cứ |
|---|---|---|---|
| BenchmarkPython v0.1 (Phần 2) | 2026-10-15 16:54 | script trước định dạng (bản khóa v0.1) | `evidence.sarif` khớp `FREEZE_v0.1.sha256` |
| BenchmarkPython v0.2 (Phần 3) | 2026-10-15 17:49 | nhiều khả năng là script trước định dạng (SARIF tạo 13 phút sau bản khóa v0.2); hash truy vấn không được ghi | suy luận từ thời điểm tệp |
| Bộ phản ví dụ v0.1/v0.2 | chạy lại sau định dạng | script đã commit | ghi chú trong `README.md` |
| Đợt A | 2026-10-16, trước commit `a2bb650` | 8 truy vấn cảnh báo, `.qll`, `qlpack.yml` giống bản do `gen.py` đã commit sinh ra; `Evidence.ql` = bản đã commit (`994616f9…`) | `../wave-a/query_hashes.txt` |
| Đợt B | 2026-10-16 11:24, sau commit `a2bb650` | hash truy vấn **không được ghi**; `gen.py` không đổi sau commit, và mọi bản `gen.py` quan sát được đều sinh cùng 8 truy vấn cảnh báo | suy luận; xác minh trực tiếp **một phần** (mục 3) |
| v0.3 (so với v0.2) | từ 2026-10-16 | tệp đã commit, khóa ở `FREEZE_v0.2_postformat.sha256` | — |

## 3. Chạy lại và kết quả

| Phép kiểm | Kết quả |
|---|---|
| Hash truy vấn v0.2 sinh ra (cùng `Evidence.ql` đã commit) so với `../wave-a/query_hashes.txt` | 11/11 tệp giống |
| Chấm lại SARIF đã lưu bằng script đã commit: `pilot_development.json`, `evidence_{development,test}.json`, `evidence_v02_{development,test}.json` | 5/5 giống |
| Bộ phản ví dụ, dựng lại database, v0.1 và v0.2, so với `cex_results.json` theo từng ca | giống (v0.1: 10 UNSOUND, 31 ok, 4 MISSED, 2 VACUOUS; v0.2: 41 ok, 4 MISSED, 2 VACUOUS) |
| BenchmarkPython `f1291485`, chạy lại 28 truy vấn v0.1 và 28 truy vấn v0.2, so với SARIF đã lưu (ruleId, tệp, dòng, cột, thông điệp) | giống: 1136 và 1184 kết quả |
| Bảng bằng chứng v0.2 trên BenchmarkPython bằng `Evidence.ql` sinh ra và bằng bản đã commit, so với `evidence_table_v02.csv` | giống: 4883 dòng |
| Đợt B, chạy lại CWE-22 (mặc định + v0.2) trên mlflow@`6e801f42` và Django@`05413afa` (phía fixed của hai cặp tập phát triển; `../v03-interprocedural-guard/scripts/run_dev.sh`), so với `v02.sarif` lưu trong `artifacts/wave-b/wave-b-raw.tar.gz` | giống (2026-10-20) |

Kết luận: các thay đổi sau khóa không làm đổi phép đo nào của thí điểm (v0.1, v0.2, bộ phản ví dụ). Không cần sửa số liệu.
Đợt A được hash truy vấn bảo đảm trực tiếp. Đợt B **chưa** được xác minh trực tiếp toàn bộ: chỉ CWE-22 của 2/22 phiên bản
đã chạy lại và trùng khớp; 20 phiên bản còn lại và CWE-78/79/643 vẫn dựa vào suy luận ở mục 2. Trước khi dùng kết quả đợt B
để đối chiếu cuối cùng, phải chạy lại các phần đó. Từ nay mỗi lượt quét ghi hash của mọi truy vấn đã dùng.

## 4. Bản khóa mới

`FREEZE_v0.2_postformat.sha256` khóa cấu hình v0.2 **như đã commit** (`SafetyEvidence.qll`, `gen.py`, `qlpack.yml`,
`table/Evidence.ql`, `scripts/evaluate_cex.py`). Bản này không thay `FREEZE_v0.2.sha256`: logic giống nhau (mục 3), chỉ
khác định dạng script và cách xuống dòng của `Evidence.ql`. Mọi so sánh hồi quy của v0.3 với v0.2 dùng bản khóa mới.
