# Đặc tả profile sql-injection-v0.1

- Ngày: 2026-11-15. Trạng thái: **chỉ phát hiện và giữ; chưa có số liệu đánh giá nào**. Thiết kế:
  [docs/plans/multi-cwe.md](../../docs/plans/multi-cwe.md), mục 19 và 20.
- Kiểu profile: `detection`. Profile này chỉ chạy như một thành viên của profile ghép, trên database
  CodeQL do thành viên đứng đầu của profile ghép tạo ra.
- Nhóm phân tích: `sql-injection` (CWE-89), cho Python và JavaScript/TypeScript.

## 1. Truy vấn

Truy vấn thuộc gói truy vấn chuẩn của CodeQL đã cài trong worker, không nằm trong kho mã. Mỗi truy
vấn được ghim bằng SHA-256 trong file cấu hình của ngôn ngữ và được kiểm lại lúc chạy; phiên bản
gói và phiên bản CodeQL phải khớp `tools/pins.env`.

| Ngôn ngữ | Gói truy vấn | Truy vấn | Rule | CWE ánh xạ |
|---|---|---|---|---|
| Python | `codeql/python-queries` 1.8.11 | `Security/CWE-089/SqlInjection.ql` | `py/sql-injection` | CWE-89 |
| JavaScript/TypeScript | `codeql/javascript-queries` 2.4.6 | `Security/CWE-089/SqlInjection.ql` | `js/sql-injection` | CWE-89, CWE-90, CWE-943 |

Truy vấn JavaScript báo cả truy vấn SQL lẫn truy vấn NoSQL và LDAP dựng từ dữ liệu người dùng, nên
rule của nó ánh xạ tới ba CWE. Cả ba được ghi ở `mapped_cwes`; nhãn do CodeQL gắn được giữ nguyên ở
`reported_cwes`. Cảnh báo của rule này thuộc nhóm `sql-injection` vì lượt chạy sinh ra nó chỉ phục
vụ nhóm đó.

Không có luật Semgrep, không có Bandit, không có ESLint ở phiên bản này.

## 2. Đơn vị và mức

- Mỗi vị trí CodeQL báo là một đơn vị. Không có bộ định vị sink và không gộp theo lời gọi.
- Mọi đơn vị nhận mức `U`: nhóm này **chưa có chính sách xếp hạng** nào được đo. Mức `U` ở đây
  nghĩa là "chưa xếp hạng", không phải đánh giá về mức nghiêm trọng của cảnh báo.
- Quyết định: `K10_DETECTED_KEPT`.

## 3. Gạn

**Không có điều kiện gạn.** Mọi đơn vị ở danh sách rà chính; không quy tắc nào của nhóm khác (G1–G4,
điều kiện của gói path-traversal v0.2) được áp dụng cho nhóm này. Lý do giữ được ghi là
`no_filter_condition_for_family`; trạng thái bằng chứng là "chưa đủ".

Một điều kiện gạn cho CWE-89 chỉ được thêm bằng một phiên bản profile mới, sau khi có gói bằng chứng
ghim hash, bộ phản ví dụ và một lượt đo theo giao thức ghi trước khi quét.

## 4. Lượt chạy lỗi hoặc dở

- Lượt chạy dở: các cảnh báo đã báo vẫn thành đơn vị ở danh sách rà, lý do giữ có thêm
  `run_incomplete`, trạng thái bằng chứng là "không lấy được".
- Lượt chạy thất bại, hoặc có cảnh báo của một rule không được ghim ở đây: profile không xếp hạng gì;
  profile ghép giữ các cảnh báo đã thu được thành đơn vị `F10_FAMILY_NOT_RANKED` ở mức `U`.
- Trong cả hai trường hợp, kết quả của các nhóm khác trong cùng lượt quét không đổi.
