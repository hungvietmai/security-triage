# Đặc tả profile cross-site-scripting-v0.1

- **Ngày:** 2026-11-16.
- **Trạng thái:** **thử nghiệm**. Chỉ phát hiện và giữ, chưa có chính sách xếp hạng và chưa có điều
  kiện gạn. Thiết kế và kết quả nằm ở [docs/plans/multi-cwe.md](../../docs/plans/multi-cwe.md),
  mục 24.
- **Kiểu profile:** `detection`, schema 1. Profile chỉ chạy như một thành viên của profile ghép
  `multi-cwe-v0.5`, trên database CodeQL JavaScript do thành viên đứng đầu tạo ra.
- **Nhóm phân tích:** `cross-site-scripting` (CWE-79). Chỉ JavaScript/TypeScript; profile không có
  cấu hình Python.

## 1. Truy vấn

**Cách chọn:** lấy mọi truy vấn mà gói truy vấn chuẩn `codeql/javascript-queries` 2.4.6 xếp trong
thư mục `Security/CWE-079/`. Cách chọn chỉ dựa vào vị trí truy vấn trong gói, không dựa vào kết quả
trên dữ liệu nào. Cả bảy truy vấn đều thuộc bộ `javascript-code-scanning.qls` của gói.

Mỗi truy vấn được ghim bằng SHA-256 trong `javascript.json` và được kiểm lại lúc chạy. Phiên bản
CodeQL (2.27.1) và phiên bản gói phải khớp `tools/pins.env`. Tệp `.ql` chỉ là điểm vào; thư viện mà
truy vấn dùng được ghim theo phiên bản gói.

| Truy vấn | Rule | Biến thể XSS | Nguồn dữ liệu, theo mô hình của CodeQL | CWE ánh xạ |
|---|---|---|---|---|
| `ReflectedXss.ql` | `js/reflected-xss` | Phản xạ, phía máy chủ | Dữ liệu yêu cầu HTTP đi thẳng vào phản hồi HTML | CWE-79, CWE-116 |
| `StoredXss.ql` | `js/stored-xss` | Lưu trữ, phía máy chủ | Dữ liệu đã lưu, chủ yếu tên tệp đọc từ hệ thống tệp, đi vào phản hồi | CWE-79, CWE-116 |
| `Xss.ql` | `js/xss` | Dựa trên DOM, phía trình duyệt | URL, `location`, `postMessage` và nguồn tương tự, ghi vào `innerHTML`, `document.write`, jQuery | CWE-79, CWE-116 |
| `XssThroughDom.ql` | `js/xss-through-dom` | Qua văn bản DOM | Văn bản đọc từ DOM (`value`, `textContent`) bị ghi lại dưới dạng HTML | CWE-79, CWE-116 |
| `ExceptionXss.ql` | `js/xss-through-exception` | Qua thông điệp ngoại lệ | Thông điệp lỗi chứa dữ liệu người dùng bị ghi dưới dạng HTML | CWE-79, CWE-116 |
| `UnsafeJQueryPlugin.ql` | `js/unsafe-jquery-plugin` | Plugin jQuery | Tham số tùy chọn của plugin được dùng như bộ chọn hay HTML | CWE-79, CWE-116 |
| `UnsafeHtmlConstruction.ql` | `js/html-constructed-from-input` | Thư viện dựng HTML | Đầu vào của hàm thư viện được ghép vào HTML | CWE-79, CWE-116 |

CWE ánh xạ là đúng các nhãn `external/cwe/*` của truy vấn. Cả hai được ghi ở `mapped_cwes`; nhãn do
CodeQL gắn được giữ nguyên ở `reported_cwes`. Một cảnh báo thuộc nhóm `cross-site-scripting` vì lượt
chạy sinh ra nó (`codeql-cross-site-scripting`) chỉ phục vụ nhóm này.

**Truy vấn có nhãn `cwe-079` nhưng nằm ngoài phạm vi:**

| Truy vấn | Rule | Vì sao không chọn |
|---|---|---|
| `Security/CWE-094/CodeInjection.ql` | `js/code-injection` | Gói xếp vào CWE-94: chèn mã, thuộc một nhóm phân tích khác |
| `Security/CWE-094/ImproperCodeSanitization.ql` | `js/bad-code-sanitization` | CWE-94 |
| `Security/CWE-094/UnsafeCodeConstruction.ql` | `js/unsafe-code-construction` | CWE-94 |
| `Security/CWE-116/IncompleteHtmlAttributeSanitization.ql` | `js/incomplete-html-attribute-sanitization` | Gói xếp vào CWE-116: kiểm tra chất lượng bộ làm sạch, không phải luồng tới điểm ghi HTML |
| `Security/CWE-116/UnsafeHtmlExpansion.ql` | `js/unsafe-html-expansion` | CWE-116, như trên |
| `Security/CWE-601/ClientSideUrlRedirect.ql` | `js/client-side-unvalidated-url-redirection` | CWE-601: chuyển hướng |
| `Security/CWE-915/*.ql` (ba truy vấn) | `js/prototype-pollution*` | CWE-915: ô nhiễm prototype |
| `Electron/DisablingWebSecurity.ql` | `js/disabling-electron-websecurity` | Kiểm tra cấu hình, không có luồng dữ liệu |
| `experimental/**` (bốn truy vấn) | `js/*-more-sources`, `js/code-injection-dynamic-import` | Thử nghiệm của gói, không thuộc bộ chuẩn |

Không có luật Semgrep, không có ESLint, không có Bandit ở phiên bản này. Semgrep cho XSS và đối
chứng SonarQube là các lượt đo sau.

## 2. Đơn vị và mức

- Mỗi vị trí CodeQL báo (tệp và vùng) là một đơn vị. Không có bộ định vị sink và không gộp theo lời
  gọi. Hai truy vấn báo đúng cùng một vùng thì vào cùng một đơn vị; mỗi cảnh báo vẫn giữ rule, thông
  điệp và nhãn CWE riêng.
- Mã đơn vị có tên nhóm, nên cảnh báo XSS ở đúng vị trí của một cảnh báo CWE-78 hay CWE-89 vẫn là
  đơn vị riêng của nhóm `cross-site-scripting`.
- Mọi đơn vị nhận mức `U`: nhóm này **chưa có chính sách xếp hạng** nào được đo. Mức `U` nghĩa là
  "chưa xếp hạng", không phải đánh giá mức nghiêm trọng.
- Quyết định: `K10_DETECTED_KEPT`.

## 3. Gạn

**Không có điều kiện gạn.** Mọi đơn vị ở danh sách rà chính. Không quy tắc nào của nhóm khác (G1–G4,
điều kiện của gói path-traversal v0.2) được áp cho nhóm này. Lý do giữ là
`no_filter_condition_for_family`; trạng thái bằng chứng là "chưa đủ".

Một điều kiện gạn cho CWE-79 chỉ được thêm bằng một phiên bản profile mới, sau khi có gói bằng chứng
ghim hash, bộ phản ví dụ và một lượt đo theo giao thức ghi trước khi quét.

## 4. Lượt chạy lỗi hoặc dở

- **Lượt chạy dở** (SARIF ghi lượt chạy chưa xong, `executionSuccessful: false`): các cảnh báo đã báo
  vẫn thành đơn vị `K10_DETECTED_KEPT` ở danh sách rà. Lý do giữ có thêm `run_incomplete`; trạng thái
  bằng chứng là "không lấy được".
- **Lượt chạy thất bại** (CodeQL thoát lỗi, dù đã ghi SARIF hay chưa), hoặc có cảnh báo của một rule
  không được ghim ở đây: profile không xếp hạng gì. Profile ghép giữ các cảnh báo đã thu được thành
  đơn vị `F10_FAMILY_NOT_RANKED` ở mức `U`, trong danh sách rà. Không có SARIF thì không có cảnh báo
  nào để giữ.
- Trong cả hai trường hợp, nhóm được ghi là "chạy dở" hoặc "thất bại", và kết quả của các nhóm khác
  trong cùng lượt quét không đổi.

## 5. Cấu hình chạy

- Một lượt `database analyze` cho cả bảy truy vấn, `--threads 1`, `--ram=2048` như mọi lượt CodeQL
  của worker, giới hạn 600 giây.
- Một luồng, không phải hai: thử với `--threads 2` trên dữ liệu phát triển, CodeQL hết bộ nhớ khi
  biên dịch hai truy vấn cùng lúc trong 2048 MB, và lượt chạy thất bại.
- 600 giây là mức lớn nhất mà giới hạn thời gian của tác vụ còn chứa được. Trên NodeGoat, chạy riêng
  với một luồng, bảy truy vấn mất 210 giây, phần lớn là biên dịch truy vấn.
