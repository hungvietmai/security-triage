# Đặc tả profile sql-injection-v0.2

- Ngày: 2026-11-16. Trạng thái: **chỉ phát hiện và giữ; nhiều công cụ; chưa có số liệu đánh giá
  độc lập**. Thiết kế, giao thức đo và kết quả: [docs/plans/multi-cwe.md](../../docs/plans/multi-cwe.md),
  mục 21.
- Kiểu profile: `detection`, schema 2. Chỉ chạy như một thành viên của profile ghép (`multi-cwe-v0.3`).
- Nhóm phân tích: `sql-injection` (CWE-89), Python và JavaScript/TypeScript.
- `sql-injection-v0.1` (chỉ CodeQL) vẫn là một profile riêng, không thay đổi.

## 1. Công cụ và luật

| Ngôn ngữ | Lượt | Công cụ | Luật |
|---|---|---|---|
| Python | `semgrep-sql-injection` | Semgrep CE 1.178.0 | 25 file luật thượng nguồn, nguyên văn (`rules/semgrep/sql-injection-v0.1/`) |
| Python | `bandit-sql-injection` | Bandit 1.9.4 | `B608`, `B610`, `B611` (mọi test Bandit gán CWE-89); cấu hình `tools/bandit/bandit.ini` |
| Python | `codeql-sql-injection` | CodeQL 2.27.1 | `Security/CWE-089/SqlInjection.ql` của `codeql/python-queries` 1.8.11 |
| JS/TS | `semgrep-sql-injection` | Semgrep CE 1.178.0 | 12 file luật thượng nguồn, nguyên văn |
| JS/TS | `codeql-sql-injection` | CodeQL 2.27.1 | `Security/CWE-089/SqlInjection.ql` của `codeql/javascript-queries` 2.4.6 |

Cách chọn luật và giấy phép: [rules/semgrep/sql-injection-v0.1/README.md](../../rules/semgrep/sql-injection-v0.1/README.md).
Mỗi file luật, cấu hình và truy vấn được ghim bằng SHA-256. CodeQL chạy trên database do thành viên
đứng đầu của profile ghép tạo; Semgrep và Bandit chạy trên cùng snapshot, mỗi công cụ một lượt có
tên riêng, SARIF và log riêng.

Mọi luật được ánh xạ tới CWE-89, trừ `js/sql-injection` (CWE-89, CWE-90, CWE-943 như CodeQL khai).
Nhãn CWE mà công cụ tự ghi được giữ nguyên ở `reported_cwes`.

Một luật Semgrep được nhận diện qua thư mục mà file của nó được đặt vào khi chạy (`r<số thứ tự>`), vì
nhiều file thượng nguồn dùng chung một ID (`tainted-sql-string`). ID lưu và xuất là ID đầy đủ theo
đường dẫn thượng nguồn, ví dụ `python.flask.security.injection.tainted-sql-string.tainted-sql-string`;
ID thô công cụ ghi được giữ ở `raw_rule_id`.

## 2. Đơn vị và gộp

- **Python:** các lời gọi thực thi truy vấn SQL được định vị bằng trình phân tích cú pháp Python
  (`app/workflows/scans/sql_sites.py`, phiên bản `sql-call-site-v1`): lời gọi phương thức `execute`,
  `executemany`, `executescript`, `raw`, `extra`, và lời gọi `RawSQL`. Các cảnh báo có vùng báo nằm
  trọn trong cùng một lời gọi (lời gọi trong cùng nhất khi lồng nhau) được gộp thành **một** đơn vị
  của lời gọi đó. Dòng không phải ASCII không được định vị, vì các công cụ đếm cột khác nhau ở đó.
- **Mọi cảnh báo khác** — vùng báo nằm ngoài mọi lời gọi được định vị (ví dụ chuỗi SQL được dựng ở
  một dòng riêng), file không phân tích được, và toàn bộ JavaScript/TypeScript (chưa có bộ định vị ở
  phiên bản này) — là một đơn vị theo vị trí được báo **và theo công cụ**: không có lời gọi được định
  vị thì không có căn cứ để nói hai công cụ cùng chỉ một điểm thực thi, nên cảnh báo của hai công cụ
  không được gộp, kể cả khi trùng vùng báo. Cảnh báo cùng một công cụ trùng đúng vùng báo là một đơn
  vị, như ở `sql-injection-v0.1`.
- Mọi đơn vị nhận mức `U` ("chưa xếp hạng"), quyết định `K10_DETECTED_KEPT`, phiên bản đơn vị
  `detection-units-v2`.

## 3. Gạn

**Không có điều kiện gạn.** Mọi đơn vị ở danh sách rà chính; lý do giữ `no_filter_condition_for_family`.
Không quy tắc nào của nhóm khác (G1–G4, điều kiện của gói path-traversal v0.2) được áp dụng.

## 4. Lượt chạy lỗi hoặc dở

- Nhóm hoàn tất khi **mọi** lượt của nó hoàn tất. Một lượt lỗi hoặc dở làm nhóm chạy dở: cảnh báo
  của các lượt còn lại vẫn thành đơn vị ở danh sách rà, lý do giữ có thêm `run_incomplete`.
- Mọi lượt đều lỗi, hoặc có cảnh báo của một luật không được ghim: profile không xếp hạng gì; profile
  ghép giữ các cảnh báo đã thu được thành đơn vị `F10_FAMILY_NOT_RANKED` ở mức `U`.
- Kết quả của các nhóm khác trong cùng lượt quét không đổi.
