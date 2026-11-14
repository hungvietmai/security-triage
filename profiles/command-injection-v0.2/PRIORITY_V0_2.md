# Đặc tả chính sách ưu tiên v0.2

- Ngày: 2026-11-14. Trạng thái: **profile sản phẩm, chưa được đánh giá**. Chưa có số liệu nào
  về hiệu quả của v0.2; mọi kết luận nghiên cứu hiện có thuộc về v0.1 và phần CWE-22.
- Chính sách: `command-injection-priority`, phiên bản `0.2`.
- Bản khai báo: [priority-v0.2.yaml](priority-v0.2.yaml). Ngữ nghĩa rule:
  [rule-claims-v3.json](rule-claims-v3.json). Bộ gộp và bộ định vị không đổi:
  `reconcile-v0.1`, `sink-locator-v0`.
- Kế thừa toàn bộ [đặc tả v0.1](../../experiments/policy/PRIORITY_V0_1.md). Tài liệu này chỉ ghi
  những gì thay đổi; mục nào không nhắc tới thì v0.1 vẫn áp dụng nguyên văn.

## 1. Vì sao có v0.2

Đề cương mô tả quy trình hai giai đoạn: **sàng lọc nhanh** bằng Semgrep cùng một công cụ bổ trợ
theo ngôn ngữ, rồi **thẩm định** bằng CodeQL. Profile v0.1 chỉ chạy Semgrep và CodeQL. Profile
`command-injection-v0.2` thêm công cụ bổ trợ vào giai đoạn sàng lọc:

| Ngôn ngữ | Sàng lọc | Thẩm định |
|---|---|---|
| Python | Semgrep 1.178.0 (4 rule như v0.1), **Bandit 1.9.4** | CodeQL 2.27.1 (2 truy vấn như v0.1), rồi 2 truy vấn bằng chứng an toàn trên cùng database |
| JavaScript/TypeScript | Semgrep 1.178.0 (4 rule như v0.1), **ESLint 10.15.0 + eslint-plugin-security 4.2.1** | CodeQL 2.27.1 (2 truy vấn như v0.1) |

Mức ưu tiên vẫn là thứ tự **rà soát**. Không mức nào xóa cảnh báo, và không mức nào là nhãn
đúng/sai.

## 2. Rule của công cụ bổ trợ

| Công cụ | Rule | Nội dung |
|---|---|---|
| Bandit | `B602`, `B604` | Lời gọi có `shell=True` (`subprocess` và hàm khác) |
| Bandit | `B603`, `B606` | Khởi chạy tiến trình không qua shell |
| Bandit | `B605` | Khởi chạy tiến trình qua shell (`os.system`, `os.popen`…) |
| Bandit | `B607` | Đường dẫn chương trình không đầy đủ |
| Bandit | `B609` | Ký tự đại diện trong lệnh |
| ESLint | `security/detect-child-process` | `child_process.exec()` có đối số đầu không phải literal |

- Đây là toàn bộ các test của Bandit gắn CWE-78 **tại vị trí lời gọi**. `B404` (dòng
  `import subprocess`) bị loại vì nó không chỉ vào một lời gọi thực thi lệnh nên không thể gộp
  theo sink.
- Các rule này bắt mẫu cú pháp, không phân tích luồng dữ liệu. `rule-claims-v3` xếp chúng vào
  `claim_family = audit`, `audit_oriented = true`, `source_type = unknown`.
- Rule nằm sẵn trong công cụ, nên `definition_sha256` của chúng là SHA-256 của file cấu hình công
  cụ đã ghim mà lượt quét dùng ([bandit.ini](../../tools/bandit/bandit.ini),
  [eslint.config.mjs](../../tools/eslint/eslint.config.mjs)). Phiên bản công cụ được kiểm lúc
  chạy; phiên bản plugin, parser và formatter của ESLint do
  [package-lock.json](../../tools/eslint/package-lock.json) quyết định và profile ghim hash của
  file đó.
- Danh sách rule được bật nằm trong cấu hình ngôn ngữ của profile
  ([python.json](python.json), [javascript.json](javascript.json)), không nằm trong file cấu
  hình công cụ.

## 3. Thay đổi về tín hiệu

Chỉ một tín hiệu đổi định nghĩa:

| Tín hiệu | v0.1 | v0.2 |
|---|---|---|
| `agreement` | Đơn vị có cảnh báo của cả `semgrep` và `codeql` | Đơn vị có cảnh báo `codeql` **và** ít nhất một công cụ sàng lọc (`semgrep`, `bandit`, `eslint`) |

Với lượt quét chỉ có Semgrep và CodeQL, hai định nghĩa cho cùng kết quả, nên profile v0.1 không
bị ảnh hưởng. Như ở v0.1, đây là đồng hiện trên cùng đơn vị, chưa chứng minh hai công cụ có mô
hình độc lập. Chín tín hiệu còn lại giữ nguyên.

## 4. Danh sách quyết định

Giữ nguyên từng dòng so với v0.1 (D00 → D99, quy tắc đầu tiên khớp thắng). Hệ quả đối với cảnh
báo của công cụ bổ trợ:

| Tình huống trên một đơn vị | Mức |
|---|---|
| Cảnh báo sàng lọc và CodeQL có vết luồng hợp lệ tới đối số lệnh | P1 (D20) |
| Cảnh báo sàng lọc và CodeQL, chưa có vết luồng hợp lệ | P2 (D30) |
| Chỉ có cảnh báo Bandit/ESLint, gộp được vào một sink | P3 (D40), hoặc P4 nếu toàn bộ lệnh là literal (D10) |
| Chỉ có cảnh báo Bandit/ESLint, **không** gộp được vào sink nào | U (D00) |
| Chỉ CodeQL báo | Như v0.1: P1 hoặc P2 tùy vết luồng và ngữ nghĩa shell |

## 5. Giới hạn đã biết

- **Khóa đơn vị có vai trò đối số.** Bandit và ESLint báo cả lời gọi, không báo một đối số. Với
  lời gọi không qua shell (`subprocess.run([...])`, `spawn`), cảnh báo đó tạo đơn vị
  `role_unresolved`, tách khỏi đơn vị mà CodeQL báo trên đối số chương trình. Hai cảnh báo cùng
  một lời gọi khi đó **không** được tính là `agreement` trong chính sách ưu tiên. Bước thẩm định
  `adjudicate-v0.1` gộp các đơn vị cùng một lời gọi thành một ứng viên rà soát, nên báo cáo
  trước–sau và quyết định gạn vẫn xét chúng cùng nhau (xem mục 7).
- **Hàng đợi U.** `B604` và các lời gọi mà bộ định vị sink không nhận ra sẽ vào U, đứng trên P3
  trong thứ tự vận hành. Cần số liệu thật trước khi quyết định có đổi quy tắc này hay không.
- **ESLint và file không phân tích được.** File mà parser không đọc được không được quét; lượt
  chạy ESLint khi đó ở trạng thái `partial`, không phải "không có cảnh báo". ESLint bỏ qua
  `node_modules/`.
- **Độ phủ của `detect-child-process`** chỉ gồm `exec()` với đối số không phải literal; `spawn`,
  `execFile`, `execSync` nằm ngoài rule này.
- CLI thực nghiệm `run_pilot.py` chưa chạy Bandit hay ESLint; hai công cụ này hiện chỉ chạy
  trong worker.

## 6. Bước thẩm định và gạn (`adjudicate-v0.1`)

Chính sách ưu tiên chỉ xếp thứ tự rà soát. Việc chuyển một ứng viên ra khỏi danh sách rà chính
là quyết định riêng, do `backend/app/triage/adjudicate.py` đưa ra sau khi đã xếp ưu tiên:

- **Ứng viên:** các đơn vị cùng một lời gọi (cùng tệp và vùng lời gọi). Đơn vị không gộp được
  vào lời gọi nào là một ứng viên riêng.
- **G1 — bằng chứng an toàn của CodeQL (Python).** Sau khi phân tích, CodeQL chạy thêm hai truy
  vấn của gói [command-injection-evidence-v0.2](../../rules/codeql/command-injection-evidence-v0.2/README.md)
  trên chính database đã tạo. Ứng viên được gạn khi: mọi cảnh báo `py/command-line-injection`
  của nó được truy vấn đối chứng `st/cwe-78/none` báo đúng vị trí, truy vấn có bằng chứng
  `st/cwe-78/all` không còn báo vị trí nào trong số đó, và không công cụ nào khác khẳng định
  luồng dữ liệu tại lời gọi.
- **G2 — lệnh là hằng.** Ứng viên được gạn khi chứng minh `whole_command_literal_v1` thành công,
  Bandit xếp lời gọi ở mức LOW của `B602`/`B605` (mức dành cho đối số lệnh là chuỗi hằng), và
  không công cụ nào khẳng định luồng dữ liệu.
- **Luôn giữ lại** khi lượt quét chạy dở, bước bằng chứng thất bại, truy vấn có bằng chứng vẫn
  báo luồng, luồng do truy vấn chưa có bản bằng chứng (`py/shell-command-constructed-from-input`)
  báo, có công cụ khác khẳng định luồng, hoặc không có bằng chứng nào. Một công cụ im lặng
  không phải là bằng chứng.
- Ứng viên đã gạn giữ nguyên đơn vị, mức ưu tiên, cảnh báo gốc, quy tắc và bằng chứng gạn.

JavaScript/TypeScript chưa có gói bằng chứng: bước này không gạn ứng viên JS/TS nào.

## 7. Phiên bản

Thay đổi ngữ nghĩa của tín hiệu, danh sách quyết định, danh sách rule hoặc file cấu hình công
cụ cần phiên bản chính sách và profile mới. Sau khi đổi một file được ghim, chạy
`python experiments/build_profile.py` để cập nhật hash của profile.
