# Đặc tả profile ssrf-v0.1

- **Ngày:** 2026-11-17.
- **Trạng thái:** **thử nghiệm**. Chỉ phát hiện và giữ, chưa có chính sách xếp hạng và chưa có điều
  kiện gạn. Thiết kế và kết quả nằm ở [docs/plans/multi-cwe.md](../../docs/plans/multi-cwe.md),
  mục 26.
- **Kiểu profile:** `detection`, schema 1. Profile chỉ chạy như một thành viên của profile ghép
  `multi-cwe-v0.6`, trên database CodeQL Python và JavaScript do thành viên đứng đầu tạo ra.
- **Nhóm phân tích:** `ssrf` (CWE-918, server-side request forgery). Python và
  JavaScript/TypeScript. Tên nhóm ngắn vì tên lượt chạy (`codeql-ssrf`) được lưu ở cột
  `tool_runs.tool`, dài tối đa 32 ký tự; `codeql-server-side-request-forgery` dài 34.

## 1. Truy vấn

**Cách chọn:** theo nội dung kiểm tra của truy vấn, không theo nhãn CWE. Trong gói truy vấn chuẩn
`codeql/python-queries` 1.8.11 và `codeql/javascript-queries` 2.4.6 (CodeQL 2.27.1), lấy mọi truy vấn
không thử nghiệm mà điều kiện báo là: **một yêu cầu mạng do máy chủ gửi đi** (lớp
`Http::Client::Request` của Python, `RequestForgery::Sink` của JavaScript) có URL phụ thuộc vào
**dữ liệu từ xa mà máy chủ nhận** (nguồn phía máy chủ). Cách chọn này được ghi trước khi chạy trên
dữ liệu nào; nó dựa vào tệp `.ql` và thư viện `*RequestForgery*Query.qll` mà truy vấn nhập.

Mỗi truy vấn được ghim bằng SHA-256 trong `python.json` và `javascript.json` và được kiểm lại lúc
chạy. Phiên bản CodeQL và phiên bản gói phải khớp `tools/pins.env`. Tệp `.ql` chỉ là điểm vào; thư
viện mà truy vấn dùng được ghim theo phiên bản gói.

| Ngôn ngữ | Truy vấn | Rule | Điều truy vấn kiểm | Độ chính xác (gói) | Bộ chuẩn của gói | CWE ánh xạ |
|---|---|---|---|---|---|---|
| Python | `Security/CWE-918/FullServerSideRequestForgery.ql` | `py/full-ssrf` | Mọi phần URL của yêu cầu đều đến từ nguồn từ xa | cao | `code-scanning`, `security-extended` | CWE-918 |
| Python | `Security/CWE-918/PartialServerSideRequestForgery.ql` | `py/partial-ssrf` | Một phần URL đến từ nguồn từ xa, phần còn lại cố định; loại trừ đúng các yêu cầu mà `py/full-ssrf` báo | trung bình | `security-extended` | CWE-918 |
| JavaScript/TypeScript | `Security/CWE-918/RequestForgery.ql` | `js/request-forgery` | URL của yêu cầu phụ thuộc vào nguồn mà `isServerSide()` đúng; chỉ tiền tố hằng có `?` hay `#` (phần nối thêm chỉ còn là truy vấn hay mảnh URL) chặn luồng | cao | `code-scanning`, `security-extended` | CWE-918 |

- Hai truy vấn Python dùng chung nguồn, đích và bộ làm sạch (`ServerSideRequestForgeryCustomizations`)
  và tách nhau bằng `fullyControlledRequest`: một yêu cầu chỉ có thể bị một trong hai báo. Cả hai
  được chọn, vì cả hai báo SSRF phía máy chủ. `py/partial-ssrf` có độ chính xác "trung bình" theo gói
  và không thuộc bộ `code-scanning`: mục rà của nó có thể nhiều cảnh báo sai hơn.
- Cả hai ngôn ngữ báo trường hợp máy chủ đích cố định và chỉ đường dẫn bị điều khiển
  (`"https://host/" + x`): ở Python là `py/partial-ssrf`, ở JavaScript vẫn là `js/request-forgery`.
  Python tách được URL bị điều khiển toàn phần hay một phần qua rule; JavaScript thì không.

CWE ánh xạ là đúng nhãn `external/cwe/*` của ba truy vấn (chỉ `cwe-918`). Nhãn do CodeQL gắn được giữ
nguyên ở `reported_cwes`. Một cảnh báo thuộc nhóm `ssrf` vì lượt chạy sinh ra nó (`codeql-ssrf`) chỉ
phục vụ nhóm này.

**Truy vấn có nhãn `cwe-918` nhưng không chọn:**

| Truy vấn | Rule | Vì sao không chọn |
|---|---|---|
| `Security/CWE-918/ClientSideRequestForgery.ql` (JS) | `js/client-side-request-forgery` | Nhãn CWE giống, nội dung khác: nguồn là dữ liệu phía trình duyệt (`not isServerSide()`), yêu cầu do trình duyệt gửi. Đây không phải SSRF phía máy chủ |
| `experimental/Security/CWE-918/SSRF.ql` (JS) | `javascript/ssrf` | Thử nghiệm của gói, không thuộc bộ chuẩn nào; nguồn gồm cả nguồn phía trình duyệt (không lọc `isServerSide()`) |
| `experimental/Security/CWE-918/SsrfIpv6TransitionIncompleteGuard.ql` (JS) | `javascript/ssrf-ipv6-transition-incomplete-guard` | Thử nghiệm; kiểm chất lượng một hàm chặn địa chỉ nội bộ, không kiểm luồng dữ liệu tới yêu cầu |

Gói Python 1.8.11 không có truy vấn `cwe-918` nào khác. Không có luật Semgrep, ESLint hay Bandit ở
phiên bản này.

## 2. Đơn vị và mức

- Mỗi vị trí CodeQL báo (tệp và vùng) là một đơn vị. Không có bộ định vị sink và không gộp theo lời
  gọi. Hai truy vấn báo đúng cùng một vùng thì vào cùng một đơn vị; mỗi cảnh báo vẫn giữ rule, thông
  điệp và nhãn CWE riêng.
- Mã đơn vị có tên nhóm, nên cảnh báo SSRF ở đúng vị trí của một cảnh báo nhóm khác vẫn là đơn vị
  riêng của nhóm `ssrf`.
- Mọi đơn vị nhận mức `U`: nhóm này **chưa có chính sách xếp hạng** nào được đo. Mức `U` nghĩa là
  "chưa xếp hạng", không phải đánh giá mức nghiêm trọng.
- Quyết định: `K10_DETECTED_KEPT`.

## 3. Gạn

**Không có điều kiện gạn.** Mọi đơn vị ở danh sách rà chính. Không quy tắc nào của nhóm khác (G1–G4,
điều kiện của gói path-traversal v0.2) được áp cho nhóm này. Lý do giữ là
`no_filter_condition_for_family`; trạng thái bằng chứng là "chưa đủ".

Một điều kiện gạn cho CWE-918 chỉ được thêm bằng một phiên bản profile mới, sau khi có gói bằng chứng
ghim hash, bộ phản ví dụ và một lượt đo theo giao thức ghi trước khi quét.

## 4. Lượt chạy lỗi hoặc dở

Mỗi ngôn ngữ có lượt `codeql-ssrf` riêng; trạng thái được ghi theo từng ngôn ngữ.

- **Lượt chạy dở** (SARIF ghi lượt chạy chưa xong, `executionSuccessful: false`): các cảnh báo đã báo
  vẫn thành đơn vị `K10_DETECTED_KEPT` ở danh sách rà. Lý do giữ có thêm `run_incomplete`; trạng thái
  bằng chứng là "không lấy được".
- **Lượt chạy thất bại** (CodeQL thoát lỗi, dù đã ghi SARIF hay chưa), hoặc có cảnh báo của một rule
  không được ghim ở đây: profile không xếp hạng gì ở ngôn ngữ đó. Profile ghép giữ các cảnh báo đã thu
  được thành đơn vị `F10_FAMILY_NOT_RANKED` ở mức `U`, trong danh sách rà. Không có SARIF thì không có
  cảnh báo nào để giữ.
- Trong cả hai trường hợp, nhóm được ghi là "chạy dở" hoặc "thất bại" ở ngôn ngữ đó, và kết quả của
  các nhóm khác trong cùng lượt quét không đổi.

## 5. Cấu hình chạy

- Mỗi ngôn ngữ một lượt `database analyze` trên database dùng chung (`--rerun`), `--threads 1`,
  `--ram=2048` như mọi lượt CodeQL của worker, giới hạn 600 giây.
- Một luồng, như `cross-site-scripting-v0.1`: với hai luồng, CodeQL đã hết 2048 MB khi biên dịch hai
  truy vấn JavaScript cùng lúc.
- Hai lượt 600 giây làm trường hợp xấu nhất của `multi-cwe-v0.6` tăng 1 200 giây so với
  `multi-cwe-v0.5`; giới hạn thời gian của tác vụ và thời gian hiển thị lại của broker được nâng cùng
  lúc (docs/plans/multi-cwe.md, mục 26).
