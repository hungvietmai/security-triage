# Ghi chú cho Chương 2 — Thiết kế quy trình và điều chỉnh phương pháp

Tài liệu nguồn để viết Chương 2 ("Thiết kế và xây dựng quy trình phân tích nhiều bước và chuẩn
hóa kết quả"). Mỗi mục ghi rõ mã nguồn hoặc số liệu làm căn cứ. Số liệu đều lấy trên **dữ liệu
phát triển**; xem giới hạn ở [chapter-3-results.md](chapter-3-results.md).

## 2.1 Bài toán và mục tiêu thiết kế

- **Bài toán:** công cụ phân tích tĩnh sinh nhiều cảnh báo sai, trong khi mỗi công cụ lại bỏ sót
  một phần lỗi thật.
- **Hai mục tiêu, theo thứ tự ưu tiên:**
  1. phát hiện được nhiều lỗi đúng nhất trong phạm vi đánh giá;
  2. giảm số cảnh báo sai người rà phải đọc, **đồng thời đo được** số cảnh báo đúng bị mất.
- **Ba ràng buộc thiết kế:**
  - không xóa cảnh báo nào; cảnh báo bị gạn vẫn xem lại được cùng lý do;
  - chỉ gạn khi có bằng chứng cụ thể; thiếu bằng chứng, mâu thuẫn hoặc chạy dở thì giữ;
  - mọi công cụ, rule và cấu hình được ghim phiên bản và hash để tái lập.

## 2.2 Quy trình tổng thể

```
Mã nguồn (một phiên bản cố định, có SHA-256)
   │
   ▼
[1] Phát hiện rộng      Semgrep, CodeQL, Bandit (Python), ESLint + eslint-plugin-security (JS/TS)
   │                    → cảnh báo thô, mỗi công cụ một tệp SARIF
   ▼
[2] Chuẩn hóa và gộp    SARIF → cảnh báo chuẩn hóa → đơn vị (lời gọi + vai trò đối số)
   │                    → ứng viên rà soát (mỗi lời gọi một mục)
   ▼
[3] Thẩm định và gạn    xếp ưu tiên P1–P4/U; luật bằng chứng nhánh chết của Semgrep CE,
   │                    truy vấn bằng chứng an toàn của CodeQL, phân loại "lệnh là hằng"
   │                    của Bandit → danh sách rà chính / đã gạn
   ▼
[4] Báo cáo trước–sau   số liệu từng bước, đóng góp từng công cụ, thời gian, SARIF hợp nhất
```

Cài đặt: [backend/app/scanners/](../../backend/app/scanners/README.md) (bước 1),
[backend/app/triage/reconcile.py](../../backend/app/triage/reconcile.py) và
[adjudicate.py](../../backend/app/triage/adjudicate.py) (bước 2–3),
[backend/app/workflows/scans/report.py](../../backend/app/workflows/scans/report.py) (bước 4).

## 2.3 Điều chỉnh so với đề cương: từ nối tiếp sang hợp các nguồn

**Thiết kế trong đề cương.** Semgrep cùng một công cụ bổ trợ quét nhanh để tạo danh sách cảnh
báo ban đầu; CodeQL chỉ phân tích sâu "tại các vị trí đã được cảnh báo".

**Điều thí điểm cho thấy.** Trên 20 vị trí CWE-78 của OWASP BenchmarkPython (13 lỗi thật, 7 an
toàn), với bốn rule Semgrep cộng đồng và hai truy vấn CodeQL mặc định
([báo cáo thí điểm](../../experiments/reports/owasp-python-development/REPORT.md)):

| Nhóm vị trí | Lỗi thật | An toàn |
|---|---:|---:|
| Chỉ Semgrep báo | 0 | 5 |
| Chỉ CodeQL báo | **4** | 0 |
| Cả hai báo | 7 | 2 |
| Không công cụ nào báo | 2 | — |

- Bốn lỗi thật chỉ CodeQL báo sẽ **không bao giờ** tới bước thẩm định nếu CodeQL chỉ xem vị trí
  Semgrep đã báo. Luồng nối tiếp vì thế có độ bao phủ tối đa 7/13, kể cả khi bước thẩm định
  hoàn hảo; F1 tối đa 0,70, thấp hơn CodeQL chạy riêng (0,85).
- Hai lỗi thật còn lại (00899, 01191) cả Semgrep lẫn CodeQL đều bỏ sót vì nguồn dữ liệu đi qua
  một lớp bọc không được mô hình hóa.

**Điều chỉnh.** Tập ứng viên là **hợp** kết quả của mọi công cụ trên cùng phiên bản mã. CodeQL
giữ hai vai trò: một nguồn ứng viên, và công cụ thẩm định qua các truy vấn bằng chứng an toàn.
Công cụ bổ trợ của đề cương (Bandit, eslint-plugin-security) được giữ đúng vai trò quét nhanh.

**Căn cứ để mở rộng nguồn.** Đóng góp riêng của từng nguồn được đo trước khi quyết định
(báo cáo trước–sau, cột "chỉ công cụ này báo"). Trên cùng 20 vị trí, Bandit là nguồn duy nhất
báo hai lỗi thật 00899 và 01191, đưa độ bao phủ của tập hợp từ 11/13 lên 13/13.

**Tên đề tài vẫn đúng:** quy trình kết hợp Semgrep và CodeQL để sàng lọc và thẩm định; phần đổi
là thứ tự phối hợp, không phải công cụ hay mục tiêu.

## 2.4 Bước phát hiện rộng

| Công cụ | Phiên bản | Ngôn ngữ | Loại cảnh báo |
|---|---|---|---|
| Semgrep CE | 1.178.0 | Python, JS/TS | 4 rule cộng đồng mỗi ngôn ngữ (taint và bắt mẫu) |
| CodeQL | 2.27.1 | Python, JS/TS | 2 truy vấn luồng dữ liệu mặc định mỗi ngôn ngữ |
| Bandit | 1.9.4 | Python | 7 test bắt mẫu tại lời gọi (`B602`–`B607`, `B609`) |
| ESLint + eslint-plugin-security | 10.15.0 + 4.2.1 | JS/TS | `security/detect-child-process` |

- Phiên bản ghim ở [tools/pins.env](../../tools/pins.env); worker từ chối khởi động nếu lệch.
- **An toàn với mã bị quét:** không thực thi mã, không cài phụ thuộc. Bandit nhận `--ini` đã
  ghim và `--ignore-nosec`; ESLint nhận cấu hình và formatter bằng đường dẫn tuyệt đối, tắt
  chú thích `eslint-disable`. Đã kiểm chứng rằng nếu không làm vậy, Bandit đọc file `.bandit`
  trong mã bị quét.
- Rule, cấu hình và lý do loại `B404`:
  [PRIORITY_V0_2.md](../../profiles/command-injection-v0.2/PRIORITY_V0_2.md).

## 2.5 Chuẩn hóa và gộp cảnh báo trùng

1. **Chuẩn hóa.** Mỗi kết quả SARIF 2.1.0 thành một cảnh báo chuẩn hóa: công cụ, rule, tệp,
   vùng mã, thông điệp, kết quả gốc nguyên vẹn
   ([sarif.py](../../backend/app/scanners/sarif.py)). SARIF sai định dạng làm lượt chạy thất
   bại, không bị coi là "không có cảnh báo".
2. **Đơn vị** (`reconcile-v0.1`). Bộ định vị sink tìm mọi lời gọi thực thi lệnh bằng AST. Cảnh
   báo được ghép vào lời gọi theo ba căn cứ, lưu lại cho từng cảnh báo:
   - `explicit_link`: CodeQL chỉ thẳng tới vị trí lệnh shell;
   - `containment`: vùng cảnh báo nằm trong lời gọi;
   - `exact_span`: vùng cảnh báo trùng đúng lời gọi.

   Khóa đơn vị gồm phiên bản mã, tệp, vùng lời gọi và vai trò đối số (lệnh shell, chương trình,
   danh sách tham số).
3. **Ứng viên rà soát** (`adjudicate-v0.1`). Các đơn vị cùng một lời gọi thành một ứng viên, vì
   người rà xem một lời gọi một lần. Bước này cần thiết vì công cụ báo ở vị trí khác nhau:
   CodeQL chỉ vào đối số, Bandit và ESLint chỉ vào cả lời gọi.
4. **Ca chưa chắc chắn được giữ riêng**, không ép ghép: cảnh báo không khớp lời gọi nào
   (`unmatched_location`), vai trò đối số chưa xác định (`role_unresolved`), và tệp có ký tự
   ngoài ASCII trên dòng cần so cột (`column_encoding_requires_review`).

Kiểm thử ba tình huống ghép:
[test_adjudicate.py](../../backend/tests/triage/test_adjudicate.py) (hai công cụ báo một lời gọi
ở hai vị trí; hai cảnh báo ở hai dòng liền nhau về hai lời gọi khác nhau; cảnh báo không có căn
cứ ghép).

## 2.6 Thẩm định và gạn cảnh báo sai

**Hai việc tách biệt.**

- *Xếp ưu tiên* (chính sách v0.2): P1–P4 hoặc U theo danh sách quyết định có thứ tự. Đây là
  thứ tự rà soát, không phải nhãn đúng/sai. "Hạ ưu tiên" nghĩa là ở P3/P4 nhưng vẫn trong danh
  sách rà chính.
- *Gạn* (`adjudicate-v0.2`): chuyển ứng viên sang danh sách "Đã gạn" khi có bằng chứng cụ thể.
  Mọi quy tắc đều được kiểm; ứng viên được gạn khi ít nhất một quy tắc đủ bằng chứng, và báo
  cáo ghi lại mọi quy tắc đã thỏa.

**Quy tắc gạn.**

| Quy tắc | Công cụ cung cấp bằng chứng | Điều kiện (phải đủ tất cả) |
|---|---|---|
| G3 — nhánh không bao giờ chạy | **Semgrep CE** (mã nguồn mở, LGPL-2.1): cặp luật taint đối chứng `st-cmd-flow-none` và bằng chứng `st-cmd-flow-all`, cùng luật `st-dead-assignment` | Luật đối chứng báo lệnh của ứng viên, luật bằng chứng không báo; mọi luồng do công cụ khác báo tại lời gọi đều có đường đi, và mỗi đường đi có một bước nằm trên dòng của phép gán chết; truy vấn bằng chứng của CodeQL (nếu có) không còn báo luồng đó |
| G1 — bằng chứng an toàn của CodeQL | Truy vấn `st/cwe-78/all` (CWE-78) hoặc `st/cwe-22/all` (CWE-22), chạy trên chính database đã tạo | Ứng viên có luồng do truy vấn CodeQL gốc báo; truy vấn đối chứng của gói bằng chứng báo đúng vị trí đó; truy vấn có bằng chứng **không** còn báo; không công cụ nào khác khẳng định luồng |
| G2 — lệnh là hằng | Bandit (`B602`/`B605` mức LOW) cùng chứng minh `whole_command_literal_v1` của hệ thống | Cả hai nguồn cùng xác nhận lệnh là chuỗi hằng; không công cụ nào khẳng định luồng |

**Các trường hợp luôn giữ lại**, kèm mã lý do hiển thị cho người rà:

| Mã | Ý nghĩa |
|---|---|
| `run_incomplete` | Một công cụ chạy dở hoặc thất bại |
| `evidence_step_failed` | Bước chạy truy vấn bằng chứng không hoàn tất |
| `evidence_query_still_reports_flow` | Truy vấn có bằng chứng vẫn báo luồng |
| `flow_rule_without_evidence_query` | Luồng do truy vấn chưa có bản bằng chứng tương ứng báo |
| `evidence_baseline_does_not_report_this_alert` | Không đối chiếu được vị trí |
| `independent_flow_claim` | Công cụ khác vẫn khẳng định luồng (mâu thuẫn) |
| `literal_proof_without_second_source` | Chỉ một nguồn nói lệnh là hằng: chỉ hạ ưu tiên |
| `reported_flow_avoids_the_dead_branch` | Một đường đi do công cụ khác báo không qua nhánh chết |
| `flow_claim_without_a_trace_to_check` | Công cụ khác khẳng định luồng mà không kèm đường đi |
| `no_refuting_evidence` | Không có bằng chứng nào |

Việc một công cụ **im lặng** không bao giờ là bằng chứng: hai lỗi thật 00899 và 01191 chính là
trường hợp CodeQL im lặng.

**Lựa chọn công cụ cho bước gạn.** Bốn ứng viên đã được thử trên dữ liệu phát triển; bảng số
liệu ở [chapter-3-results.md, mục 3.4](chapter-3-results.md#34-lựa-chọn-công-cụ-cho-bước-gạn).
Kết luận thiết kế:

- **Công cụ mã nguồn mở được chọn cho bước gạn là Semgrep CE.** Nó chứng minh được một loại
  bằng chứng cụ thể (phép gán nằm trong nhánh có điều kiện số nguyên hằng không bao giờ chạy)
  bằng lan truyền hằng và `metavariable-comparison`, và đầu ra của nó (vị trí lệnh, vị trí
  phép gán chết) đủ để đối chiếu với đường đi mà công cụ khác báo. Gói luật và 13 ca kiểm tra:
  [rules/semgrep/command-injection-evidence-v0.1/](../../rules/semgrep/command-injection-evidence-v0.1/README.md).
- Bandit và ESLint chủ yếu **tạo thêm cảnh báo**, nên được dùng làm nguồn phát hiện và tín hiệu
  bổ sung. Riêng Bandit có một bằng chứng dùng được: nó xếp mức LOW khi đối số lệnh là hằng (G2).
- Truy vấn bằng chứng của CodeQL (G1) được giữ làm lớp thẩm định thứ hai, đúng vai trò đề
  cương giao cho CodeQL. Thư viện và truy vấn CodeQL là mã nguồn mở (giấy phép MIT); **bộ máy
  CodeQL CLI không phải mã nguồn mở**. Báo cáo vì vậy tách riêng kết quả "gạn chỉ bằng công cụ
  mã nguồn mở" khỏi kết quả dùng mọi quy tắc.
- **Giả định của G3**, cần nêu trong luận văn: Semgrep CE chỉ phân tích trong một hàm; đường đi
  của CodeQL là các đường đi mẫu được xuất ra, không phải mọi đường đi; biến cấp module được
  gán đúng một lần được coi là hằng; nguồn dữ liệu là một danh sách cố định.

## 2.7 Chuẩn hóa kết quả và báo cáo

- **Báo cáo trước–sau** (`GET /api/v1/scans/{id}/report`, hiển thị trên trang lượt quét): số
  cảnh báo thô, đơn vị, ứng viên, danh sách rà chính, đã gạn, chỉ hạ ưu tiên; đóng góp của từng
  công cụ; số ứng viên theo quy tắc gạn; trạng thái và thời gian từng bước.
- **SARIF hợp nhất** (`GET /api/v1/scans/{id}/report.sarif`): mọi cảnh báo gốc của mọi công cụ
  trong một tệp SARIF 2.1.0, mỗi cảnh báo mang khóa ứng viên, mức ưu tiên và kết quả gạn. Cảnh
  báo đã gạn mang trường `suppressions` kèm lý do, nên trình xem SARIF ẩn chúng mà không mất.
- Mọi lượt quét lưu SARIF thô, log, cấu hình và hash; xem
  [architecture.md](../architecture.md).

## 2.8 Giới hạn của thiết kế

- G1 và G3 chỉ áp dụng cho Python: chưa có gói bằng chứng cho JavaScript/TypeScript. Với JS/TS,
  bước gạn chỉ hạ ưu tiên khi lệnh là hằng.
- Các cơ chế bằng chứng áp dụng cho CWE-78 (nhánh điều kiện hằng, đọc phần tử hằng của
  collection, đoạn route cố định) được phát triển trên chính benchmark dùng để đo.
- Cảnh báo chỉ có công cụ bắt mẫu báo (Semgrep audit, Bandit, ESLint) không bị gạn dù phần lớn
  có thể là cảnh báo sai; chúng chỉ bị hạ ưu tiên.
- `detect-child-process` của eslint-plugin-security chỉ bắt `exec()` có đối số không phải hằng.
