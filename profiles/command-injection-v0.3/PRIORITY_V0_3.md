# Đặc tả profile command-injection-v0.3

- Ngày: 2026-11-15. Trạng thái: **profile sản phẩm; mới đo trên dữ liệu phát triển** (xem
  [docs/thesis/chuong-3-thuc-nghiem.md](../../docs/thesis/chuong-3-thuc-nghiem.md), mục 3.3.4).
- Kế thừa toàn bộ [đặc tả v0.2](../command-injection-v0.2/PRIORITY_V0_2.md): cùng công cụ, cùng
  luật phát hiện, cùng chính sách ưu tiên v0.2 (dùng lại nguyên các tệp
  `priority-v0.2.yaml`, `priority-v0.2.json`, `rule-claims-v3.json` của v0.2), cùng các quy tắc
  gạn G1, G2, G3 cho Python. Tài liệu này chỉ ghi ba điểm khác.
- Bộ quy tắc gạn: `adjudicate-v0.3`. Bộ gộp không đổi: `reconcile-v0.1`.

## 1. Phạm vi tệp của Semgrep do worker quyết định

Cấu hình ngôn ngữ có `semgrep_target_selection: worker-controlled-v1`. Trước khi chạy công cụ,
worker xóa mọi tệp `.semgrepignore` trong bản giải nén và ghi một tệp ở gốc chỉ gồm
`node_modules/`.

- **Vì sao:** khi không có tệp này, Semgrep tự bỏ qua `build/`, `dist/`, `test/`, `tests/`,
  `vendor/`, `*.min.js`… trong khi CodeQL, Bandit và ESLint vẫn quét các thư mục đó. Cảnh báo của
  ba công cụ kia ở đó vì thế không có lời gọi nào được định vị để gộp vào, và thành ứng viên
  `unmatched_location` (hàng U).
- **An toàn:** một tệp `.semgrepignore` nằm trong mã bị quét, kể cả ở thư mục con, làm Semgrep
  bỏ qua tệp tùy ý. Đã kiểm chứng với Semgrep 1.178.0. Từ v0.3 mã bị quét không còn quyết định
  được phạm vi này.
- Áp dụng cho mọi bước dùng Semgrep: phát hiện, định vị lời gọi và luật bằng chứng.

## 2. Bộ định vị lời gọi JavaScript v1

[sink-locator-v1-javascript.yaml](../../experiments/locators/sink-locator-v1-javascript.yaml)
thay cho v0. Ngoài các dạng v0 đã nhận, v1 nhận thêm:

| Dạng | Ví dụ |
|---|---|
| Bí danh hai bước | `var cp = require('child_process'); var exec = cp.exec; exec(cmd)` |
| Destructuring | `const { exec } = require('child_process'); exec(cmd)` |
| Hàm đã `promisify` | `const run = util.promisify(require('child_process').exec); run(cmd)` |
| `require` nội tuyến | `require('child_process').exec(cmd)` |
| Tiền tố `node:` | `require('node:child_process')` |

- Luật chỉ nhận lời gọi khi tên được buộc vào `child_process` trong cùng tệp; `db.exec(sql)`,
  `regex.exec(text)` hay hàm `exec` của module khác không được định vị. 18 ca kiểm tra:
  [check_sink_locator_v1.py](../../experiments/locators/check_sink_locator_v1.py).
- Cảnh báo vẫn chỉ được gộp vào lời gọi theo ba căn cứ của `reconcile-v0.1` (liên kết tường
  minh, chứa trong, trùng vùng). Cảnh báo không có căn cứ nào vẫn là ứng viên riêng ở hàng U.

## 3. Quy tắc gạn G4 cho JavaScript/TypeScript: lệnh là hằng

Ứng viên được chuyển sang "Đã gạn" khi **đủ cả bốn** điều kiện:

1. mọi lời gọi của ứng viên là `child_process.exec` hoặc `child_process.execSync`, tức lời gọi
   nhận toàn bộ lệnh trong một chuỗi;
2. luật `st-js-constant-command` của gói
   [command-injection-evidence-js-v0.1](../../rules/semgrep/command-injection-evidence-js-v0.1/README.md)
   (Semgrep CE, lan truyền hằng) báo **đúng vùng mã của lời gọi đó**;
3. không công cụ nào khẳng định luồng dữ liệu tới lệnh (cảnh báo CodeQL, hoặc luật Semgrep thuộc
   nhóm luồng dữ liệu);
4. lượt quét và bước bằng chứng hoàn tất.

- Với `spawn`, `execFile`, `fork`, chương trình là hằng không nói gì về các tham số, nên G4
  không áp dụng.
- Thiếu một điều kiện thì ứng viên ở lại danh sách rà chính: có công cụ khẳng định luồng →
  `independent_flow_claim`; bước bằng chứng lỗi → `evidence_step_failed`; lượt chạy dở →
  `run_incomplete`.
- Việc một công cụ im lặng, hay việc hai cảnh báo gộp được vào một lời gọi, không phải là căn
  cứ để gạn.
- Ứng viên đã gạn giữ nguyên cảnh báo gốc, đơn vị, mức ưu tiên; bản ghi thẩm định có quy tắc,
  luật bằng chứng, vùng mã của lời gọi và mã băm của tệp luật.

## 4. Giới hạn đã biết

- Bằng chứng của G4 là phép lan truyền hằng trong một hàm của Semgrep CE. Nó đúng trên 20 ca
  tổng hợp của gói bằng chứng, gồm các ca biến bị gán lại ở hàm khác; nó không phải chứng minh
  hình thức.
- Trên dữ liệu đã lưu chỉ có một ứng viên thỏa G4. Chưa có nhãn an toàn cho JavaScript, nên chưa
  kết luận được G4 giảm cảnh báo sai đến mức nào.
- Ứng viên do `git-parse`, `local-devices` và bản UMD của `thi.ng/egf` sinh ra vẫn ở hàng U: lời
  gọi ở đó đi qua lớp bọc hoặc mã đã đóng gói mà v1 không định vị.
