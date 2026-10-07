# Đặc tả chính sách ưu tiên v0.1

- Ngày: 2026-10-07. Trạng thái: đặc tả trước triển khai; chỉ đóng băng khi tag từ xa được xác minh.
- Mốc đối chiếu: `eb6e038d243aa6d9d7ffaccad909ad88326964b5`.
- Chính sách: `command-injection-priority`, phiên bản `0.1`.
- Bản khai báo: [priority-v0.1.yaml](priority-v0.1.yaml).
- Ngữ nghĩa rule: [rule-claims-v2.json](../mappings/rule-claims-v2.json).
- Bộ gộp: `reconcile-v0.1`; định vị: `sink-locator-v0`.
- Tag bắt buộc trước code: `evidence/priority-v0.1-spec`.

## 1. Phạm vi và ý nghĩa

Đặc tả này cụ thể hóa bảng ưu tiên v0 trong [Amendment 02](../amendments/AMENDMENT_02_APPLICATION_TRIAGE.md), thay bảng điều kiện chồng lấn bằng danh sách quyết định có thứ tự. Nó thay thế `priority-v0.yaml` cho lần triển khai mới, không sửa hay chấm lại kết quả cũ. Phạm vi chính là CWE-78 trên JavaScript/Python, Linux/POSIX; CWE-77/CWE-88 phải báo cáo riêng.

P1–P4 là mức ưu tiên **rà soát**, không phải nhãn đúng/sai, khả năng khai thác hay kết luận an toàn. U biểu thị chưa đủ cơ sở phân loại. Không mức nào xóa cảnh báo. Mỗi đơn vị nhận đúng một mức; các mức của cùng đơn vị được lưu riêng theo phiên bản chính sách khi triển khai lưu trữ sau này. Không dùng nhãn thủ công, CVE, bản vá, tên fixture hoặc tập đánh giá để tính ưu tiên.

Commit này chỉ thêm đặc tả, cấu hình và bảng ngữ nghĩa. Chưa bật cờ trong adapter, chưa viết bộ trích bằng chứng/bộ ưu tiên, chưa chạy thử chính sách, chưa ghi database. Những thay đổi schema sau 0003 phải là migration mới.

## 2. Quyết định về vết luồng và bảo toàn cảnh báo

**Chọn bật `--dataflow-traces` cho Semgrep 1.178.0 khi triển khai v0.1.** Đây là tùy chọn xuất giải thích luồng trong text/SARIF, không phải thay đổi rule hoặc chọn tập ứng viên. Vẫn phải kiểm chứng tính bất biến trên phiên bản đã khóa; không coi mô tả CLI là bằng chứng đã chạy kiểm tra. Tham khảo [CLI Semgrep](https://semgrep.dev/docs/cli-reference).

Phân biệt hai tiêu chí:

1. **Giữa lần chạy cũ và lần có cờ mới:** không bắt buộc `findings.json` giống từng byte, vì `raw_result.codeFlows` có thể được bổ sung. Phải giữ cùng snapshot, phiên bản scanner/rule, số lượng theo công cụ/rule, ID cảnh báo, rule ID và vị trí chính của từng ID; đồng thời so sánh đa tập định danh ngữ nghĩa, giữ số lần lặp.
2. **Trong một lần chạy:** file cảnh báo thô trước và sau gộp/trích bằng chứng/ưu tiên vẫn phải giống từng byte. Đầu ra bổ sung không được sửa cảnh báo đầu vào.

`raw_id` hiện có dạng `tool:run_index:result_index`, không phải dấu vân tay nội dung. Vì vậy chỉ so sánh tập `raw_id` là chưa đủ. Định danh ngữ nghĩa bổ sung gồm `(tool, snapshot_sha256, rule_id, reported_path, startLine, startColumn, endLine, endColumn)`; trường thiếu giữ `null`, không tự điền bằng tọa độ sink. Chuẩn hóa đường dẫn theo quy tắc bộ gộp hiện tại, không gộp các file khác nhau. Tọa độ được so sánh cùng quy ước; có thể so sánh thêm toàn bộ `reported_region` để phát hiện biến đổi ngoài dự kiến. Nếu ID bị hoán đổi do thứ tự SARIF, phép kiểm tra nghiêm ngặt phải thất bại, lưu hai đầu ra và ghi nguyên nhân trước khi đề xuất sửa tiêu chí; không âm thầm chấp nhận chỉ vì tổng số giống nhau.

Bật cờ không bảo đảm mọi cảnh báo đều có vết. Rule taint thiếu vết vẫn là `flow_claim_without_trace`, không được nâng thành `strong_flow`. Rule audit không trở thành rule luồng chỉ vì có cờ. Smoke curling hiện không có cảnh báo Semgrep nên file của cấu hình này **có thể vẫn giống từng byte**; không yêu cầu nó phải thay đổi. Cấu hình alias có cảnh báo Semgrep mới là đối chứng bổ sung cần thiết cho vết của công cụ này.

Khi triển khai phải tạo thư mục đầu ra mới, ghi tham số CLI, hash cấu hình, bảng rule-claims, chính sách, đặc tả và các file runner; giữ các bản ghi lịch sử nguyên trạng. Chỉ nhận kiểm tra thành công khi cả scanner hoàn tất; timeout/partial không được đổi thành số cảnh báo 0.

## 3. Rule-claims v2 và loại nguồn

### 3.1. Đối chiếu định nghĩa đã khóa

**Không phân loại chỉ từ tên rule hoặc metadata `subcategory`.** Các file hiện có cho thấy Python có ba rule taint và một rule audit. Bộ JS upstream có hai rule taint và hai rule tìm mẫu; `detect-child-process` là taint dù metadata ghi audit. V2 giữ `claim_kind` mô tả chi tiết, thêm `claim_family` dùng trong quyết định và `audit_oriented` độc lập. Một rule có thể vừa khẳng định luồng có điều kiện vừa mang định hướng audit.

| Ngôn ngữ/công cụ | Rule/query | Cơ chế | `claim_family` | `audit_oriented` | `source_type` |
| --- | --- | --- | --- | --- | --- |
| Python/Semgrep | `dangerous-subprocess-use` | taint | flow | false | remote |
| Python/Semgrep | `dangerous-system-call` | taint | flow | false | remote |
| Python/Semgrep | `subprocess-injection` | taint | flow | false | remote |
| Python/Semgrep | `subprocess-shell-true` | search, tập trung `shell=True` | audit | true | unknown |
| Python/CodeQL | `py/command-line-injection` | path-problem | flow | false | remote |
| Python/CodeQL | `py/shell-command-constructed-from-input` | path-problem | flow | false | library_input |
| JS/Semgrep | `detect-child-process`, upstream | taint | flow | true | unknown |
| JS/Semgrep | `detect-child-process`, direct-alias | taint | flow | true | unknown |
| JS/Semgrep | `dangerous-spawn-shell` | taint | flow | false | unknown |
| JS/Semgrep | `spawn-shell-true` | search | audit | true | unknown |
| JS/Semgrep | `shelljs-exec-injection` | search | audit | true | unknown |
| JS/CodeQL | `js/command-line-injection` | path-problem | flow | false | remote |
| JS/CodeQL | `js/shell-command-constructed-from-input` | path-problem | flow | false | library_input |

JSON chứa đủ 13 bản ghi, gồm sáu bản cũ, sáu bản Python và một biến thể alias phát triển. Mỗi bản ghi có SHA-256 của **toàn bộ byte file định nghĩa**, phiên bản công cụ, loại khẳng định, nguồn và mã rule; CodeQL có thêm đường dẫn/phiên bản query pack. Bốn file query được đối chiếu với source CodeQL tại `6e9f9e38390175c41b99070a423c875f450759ca`, commit được tag `codeql-cli/v2.27.1` trỏ tới. Hash khớp cấu hình đã khóa: JS pack 2.4.6, Python pack 1.8.11. Các thư viện được import không nằm trong hash file query; provenance vẫn phải giữ bundle/query pack đã khóa, không tuyên bố hash này bao phủ toàn bộ engine.

Khóa tra cứu gồm `(tool, language, canonical_rule_id, tool_version, definition_sha256)`, thêm query pack/path cho CodeQL. Semgrep cho phép ID chính xác hoặc hậu tố sau dấu chấm do đường dẫn staging; phải có đúng một bản ghi khớp toàn bộ khóa. Alias và upstream dùng cùng ID nhưng **khác hash**, không được tra cứu chỉ bằng ID. Hash cần xác minh từ định nghĩa thực tế và cấu hình của run, không tin riêng metadata đầu vào. Thiếu, sai hoặc đa nghĩa → `candidate_status=classification_unresolved`, `claim_family=classification_unresolved`, `source_type=unknown`. Adapter annotation v1 chưa được coi là hỗ trợ v2; thay đổi đó thuộc commit code sau tag.

### 3.2. Ranh giới tin cậy

`source_type` là loại nguồn **mà rule mô hình hóa**, lấy từ bản ghi rule/hash đã xác minh:

- `remote`: mô hình đầu vào bên ngoài của query/rule; không đủ để kết luận endpoint thực tế mở ra Internet hoặc không cần xác thực.
- `library_input`: đầu vào API/thư viện do caller cung cấp; chưa chứng minh caller là đối tượng không tin cậy. Query CodeQL `*/shell-command-constructed-from-input` thuộc nhóm này.
- `unknown`: chưa phân loại chắc nguồn, gồm rule chỉ lấy tham số hàm thông thường. Không tự suy ra hàm đó được export.

Lưu loại nguồn trên từng cảnh báo, kèm `source_type_basis=pinned_rule_definition`; ở cấp đơn vị lưu tập giá trị phân biệt, không ghi đè `library_input` bằng `remote`. Vết SARIF có vị trí nguồn được lưu riêng. Không suy diễn loại nguồn từ nội dung message tự do.

Curling được kỳ vọng P1 dù có `library_input`: ưu tiên cao phản ánh đường đi tới lệnh shell, trong khi ranh giới tin cậy vẫn là bất định cần người rà soát. P1 không yêu cầu nguồn remote và không xóa cờ bất định. Nếu sau này muốn giới hạn P1 chỉ cho nguồn remote, phải phiên bản hóa chính sách và thay kỳ vọng trước đợt đánh giá mới.

## 4. Định nghĩa tín hiệu có thể triển khai

Đầu vào là `units.json`, các finding gốc với `raw_result`, bản ghi sink với `args`, cấu hình scanner và source snapshot xác minh được. `args` chưa nằm trong bản ghi đơn vị hiện tại: nối lại sink bằng snapshot, path, `sink_span`, `sink_kind`; chỉ nhận đúng một sink. Không dùng vị trí highlight của query thay cho vị trí thực thi. Không thay `unit_id` để thêm thông tin ưu tiên.

| Tín hiệu | Định nghĩa chính xác |
| --- | --- |
| `execution_candidate` | `mapping_status` thuộc `mapped`, `role_unresolved`. |
| `unresolved_unit` | `mapping_status` thuộc `unmapped`, `column_encoding_requires_review`, hoặc mọi finding đều `classification_unresolved`. |
| `flow_claim` | Ít nhất một finding có định nghĩa đã xác minh và `claim_family=flow`; không bắt buộc có vết. |
| `strong_flow` | Cùng **một finding** có `flow_claim`, có threadFlow hợp lệ từ nguồn tới điểm cuối, điểm cuối nằm trong đối số `shell_command` hoặc `executable` của chính sink/đơn vị đó, với tọa độ được xác minh. Không ghép khẳng định của finding A với vết finding B. |
| `shell_semantics` | `argument_role=shell_command`. Không mở rộng ngầm sang trình thông dịch có vai trò `argument_list`. |
| `agreement` | Tập `tools` của các finding thuộc chính đơn vị chứa cả `semgrep` và `codeql`; số lượng rule/cảnh báo cùng công cụ không tạo đồng thuận. Đây là đồng hiện tại cùng đơn vị, chưa chứng minh hai công cụ có mô hình độc lập. |
| `verified_blocker` | Có chứng minh `whole_command_literal_v1` theo mục 5; không chỉ kiểm tra tên executable. |
| `important_unknown` | Role null, shell chưa xác định, options là biến/spread, loại nguồn library_input/unknown, khẳng định luồng thiếu vết hợp lệ tới đối số, một phần rule chưa phân loại, hoặc thiếu source/không phân tích được đối số. Lưu tất cả nguyên nhân, không chỉ cờ tổng hợp. |
| `audit_claim` | Ít nhất một finding đã xác minh có `audit_oriented=true` trong v2. |
| `evidence_conflict` | Đồng thời có chứng minh literal đầy đủ và luồng mạnh vào cùng lệnh; chuyển U để kiểm tra mâu thuẫn thay vì hạ P4 hoặc nâng P1. |

Các predicate dùng trong danh sách quyết định là boolean. Thiếu bằng chứng để chứng minh điều kiện dương → false, đồng thời ghi bất định phù hợp; **false không có nghĩa an toàn**. Ví dụ `verified_blocker=false` chỉ là chưa có chặn đã xác minh, không phải đã chứng minh không có sanitizer. Đơn vị không có finding, thiếu liên kết finding, ID trùng hoặc vi phạm conservation là lỗi cấu trúc khiến run thất bại; không tạo đơn vị rỗng để vượt điều kiện U. Unknown enum là lỗi hợp đồng, không rơi về P4.

### Vết luồng hợp lệ

Đọc `raw_result.codeFlows[*].threadFlows[*].locations[*].location.physicalLocation`. Danh sách `codeFlows` không rỗng nhưng không có threadFlow đầy đủ **chưa đủ**. Cần ít nhất hai vị trí nguồn/đích hợp lệ, URI giải được trong snapshot, span rõ ràng và thứ tự có thể xác định. Khi mọi vị trí có `executionOrder` nguyên, duy nhất, dùng thứ tự đó; nếu không vị trí nào có thì dùng thứ tự mảng; trộn lẫn, trùng hoặc sai kiểu → vết bất định. `endLine` vắng có thể dùng `startLine` theo SARIF; thiếu start/end column cần thiết để chứng minh bao chứa thì không xác nhận luồng mạnh.

Điểm cuối phải được bao chứa hoàn toàn trong span đối số liên quan của **cùng đơn vị**, đồng nhất path/snapshot/role; Python list/tuple phải xét đúng phần tử theo `reconcile-v0.1`. Role của endpoint được kiểm tra độc lập với highlight gốc; endpoint ở `argument_list`, option shell, mode của `os.spawn*`, cả lời gọi hoặc sink khác không đủ để khẳng định mạnh. Không lấy vị trí cuối cùng có vẻ thuận lợi trong đường đi; không dùng `relatedLocations` hoặc message `[shell command]` thay thế vết luồng. Chúng chỉ có thể hỗ trợ việc gộp đã được đặc tả trước.

V0.1 tiếp tục hạn chế so cột khi thiếu source hoặc có ký tự ngoài ASCII trên vùng cần so sánh. Không lặng lẽ coi byte column và Unicode column là một. Từng finding lưu `trace_status` trong `valid_endpoint`, `missing`, `malformed`, `endpoint_unresolved`, `endpoint_mismatch`, `coordinate_unverified`, cùng chỉ số codeFlow/threadFlow và vị trí nguồn/đích. `strong_flow` đúng nếu tồn tại ít nhất một vết hợp lệ như trên; vẫn giữ các vết và bất định khác.

## 5. Điều kiện chặn duy nhất: toàn bộ lệnh literal

Không có bộ trích guard/sanitizer trong v0.1 của chính sách này. Query guard thử nghiệm đã có ở thư mục khác không tự động trở thành bằng chứng ưu tiên. Không đọc tên hàm như `quote`, `sanitize` để khẳng định chặn; không lấy việc công cụ im lặng làm chặn.

`whole_command_literal_v1` chỉ chấp nhận biểu thức chuỗi literal, ngoặc bao quanh hoặc toán tử cộng của chính những biểu thức đó, đọc từ `args.text` của sink đã ghép và phân tích hết biểu thức bằng cú pháp đúng ngôn ngữ. Không `eval`, không chạy source; `value_kind=string` không đủ vì locator JS hiện nhận diện theo ký tự đầu. Các toán hạng phải đều là chuỗi, không ép kiểu ngầm. Không lan truyền biến, kể cả `const` trỏ tới literal; không chấp nhận call, template interpolation, spread, nhánh hoặc phần cú pháp chưa hiểu.

Miền hẹp sau giải mã chuỗi: toàn bộ lệnh không rỗng, khớp `^[A-Za-z0-9_./ -]+$`, không xuống dòng, không `$`, backtick, dấu điều khiển shell, redirect hay wildcard. Không chấp nhận trình thông dịch tường minh; executable được lấy từ token đầu sau tách khoảng trắng và so basename với `sh`, `bash`, `dash`, `ksh`, `csh`, `tcsh`, `zsh`, `python`, `python2`, `python3`, `node`, `perl`, `ruby`, `env`, `eval`, `exec` (các tên có hậu tố phiên bản thuộc cùng nhóm cũng bị loại). Tập hỗ trợ chỉ là lệnh shell trực tiếp của `child_process.exec/execSync`, `shelljs.exec`, `os.system/os.popen`, `asyncio.create_subprocess_shell`, `subprocess.getoutput/getstatusoutput`, `subprocess.run/Popen/call/check_call/check_output` với đối số chuỗi và `shell=True`, và JS `spawn/spawnSync` với `shell: true` literal. Call/overload khác chưa được chứng minh thì false.

Với JS spawn qua shell, phải kiểm tra **cả executable lẫn mọi phần tử argv**; argv vắng được hiểu là rỗng chỉ khi overload đã xác định. Options phải hiểu đầy đủ, chỉ chấp nhận object không spread/computed key, không trùng key, chỉ có `shell: true`; thuộc tính bổ sung chưa mô hình hóa thì không xác minh chặn. Với các API còn lại, phải loại mọi options hoặc keyword có thể thay lệnh/executable/env/shell mà chưa được mô hình hóa; callback tĩnh nhận diện được không phải dữ liệu lệnh. `exec` có options là biến cũng không đủ chứng minh. Python sequence cùng `shell=True` là giới hạn đã biết, không xác minh chặn. Gọi trực tiếp executable không qua shell chưa thuộc miền chứng minh này.

Ví dụ: `spawn('printf', ['fixed'], {shell:true})` có thể có chặn; `spawn('printf', [input], {shell:true})` tuyệt đối không. `exec('printf ' + 'fixed')` có thể có chặn; `exec('printf ' + input)` không. Literal không đồng nghĩa command vô hại: P4 chỉ giảm ưu tiên khẳng định injection trong mô hình runtime/executable/import/môi trường tin cậy, không chứng minh không có hành vi nguy hiểm hoặc không có lỗ hổng khác. Lưu span và hash đoạn source, biểu thức, các giá trị hằng đã giải, loại sink, quy tắc chứng minh và giả định vào `blocker_proof`.

## 6. Danh sách quyết định có thứ tự

Duyệt từ trên xuống; **quy tắc đầu tiên khớp thắng**, sau đó dừng. Thứ tự xét khác thứ tự hàng đợi vận hành `P1, P2, U, P3, P4`.

| Thứ tự / mã | Điều kiện | Mức |
| --- | --- | --- |
| D00_UNRESOLVED | `unresolved_unit` hoặc `evidence_conflict` | U |
| D10_LITERAL | `execution_candidate` và `verified_blocker` | P4 |
| D20_STRONG | Ứng viên, luồng mạnh, chưa có chặn đã xác minh, và (`shell_semantics` hoặc `agreement`) | P1 |
| D30_HIGH | Ứng viên, chưa có chặn đã xác minh, và ít nhất một: luồng mạnh; hoặc có khẳng định luồng cùng bất định quan trọng; hoặc đồng thuận cùng khẳng định audit nhưng chưa có luồng mạnh | P2 |
| D40_REVIEW | Ứng viên, chưa có chặn đã xác minh, và ít nhất một: khẳng định luồng, bất định quan trọng, ngữ nghĩa shell | P3 |
| D99_DEFAULT | Luôn đúng nếu chưa quy tắc nào khớp | P4 |

U xét trước giúp cảnh báo chưa ghép được hoặc toàn bộ chưa phân loại không được nâng nhờ sự đồng hiện của công cụ. D10 xét trước P1/P2 ngăn literal đã xác minh được nâng chỉ vì đồng thuận. D00 xử lý trường hợp literal và luồng mạnh mâu thuẫn trước D10. Luồng mạnh đơn công cụ vào executable nhưng không có shell/đồng thuận đi P2. Thiếu vết không đồng nghĩa P4: khẳng định luồng thiếu vết đi P2 theo D30; audit shell còn thiếu dữ kiện ít nhất P3, có đồng thuận có thể P2.

`library_input` làm `important_unknown=true` nhưng không phủ quyết P1 khi D20 đã đủ điều kiện. Đây là lựa chọn ưu tiên rà soát được chốt trước code, không phải ngoại lệ cài riêng cho tên curling.

Mỗi kết quả phải có `decision_id`, một câu lý do và **toàn bộ điều kiện đã thỏa** trong `matched_conditions`, kể cả nhánh hỗ trợ đồng thuận/shell và các nguyên nhân U; lưu riêng cả giá trị false để kiểm toán. Không chỉ ghi “P1 vì nguy cơ cao”. Mẫu câu nằm trong YAML; các trường bất định rỗng ghi `[]`, không bỏ trường. Ví dụ hợp lệ cho curling: “P1: ứng viên đã ghép; có vết tới đối số shell; chưa có chặn được xác minh; nguồn library_input, ranh giới tin cậy cần rà soát.” Không diễn đạt “không có sanitizer” hay “đã xác nhận khai thác”.

Đầu ra giữ `unit_id`, version/hash chính sách/đặc tả/bảng rule, phiên bản bộ gộp, mức, lý do, toàn bộ predicate, source types, bằng chứng theo raw ID và chứng minh chặn nếu có. Hash chính sách/đặc tả là SHA-256 file thực tế trong commit tag; không nhúng hash tự tham chiếu vào chính file. Tên trường chi tiết nằm trong YAML. Không sửa verdict nghiên cứu hoặc `findings.json` để lưu ưu tiên.

## 7. Kỳ vọng phát triển, viết trước chạy chính sách

Các scanner output và fixture dưới đây **đã được quan sát trước đặc tả**. Đây là kiểm thử hồi quy trên dữ liệu phát triển, không phải đăng ký trước dữ liệu chưa thấy; không báo cáo lợi ích nghiên cứu từ việc đạt các kỳ vọng này.

| Dữ liệu | Kỳ vọng khi triển khai |
| --- | --- |
| Curling, `development-smoke-javascript` | 0 Semgrep + 6 CodeQL → 1 đơn vị P1, agreement=false, nguồn library_input. |
| Curling, `development-paired-direct-alias` | 1 Semgrep + 6 CodeQL → 1 đơn vị P1, agreement=true; nguồn từng cảnh báo giữ riêng. |
| R1 01 literal, 04 fixed spawn shell, 09 shelljs literal | Mọi đơn vị thực tế không được P1. Nếu chứng minh literal thành công → P4. |
| R1 03 dynamic exec, 05 dynamic spawn shell | Mỗi fixture phải có ít nhất một đơn vị thực tế; tất cả đơn vị tương ứng phải P1/P2/P3, không P4 hoặc U. |

R1 chạy với bộ upstream đã khóa trong [cấu hình batch 01](../configs/development-batch-01-upstream.json) và snapshot fixture xác định trong [manifest](../fixtures/r1-feasibility/manifest.json). Không thêm rule chỉ để tạo cảnh báo literal. Các fixture 01/09 có thể không có cảnh báo upstream: ghi 0 finding/0 unit và “không áp dụng mức”, không tạo unit P4 giả; vẫn cần kiểm thử hợp đồng riêng bằng sink/đối số literal khi triển khai extractor. Đối với 03/05, zero candidate là thất bại kiểm tra độ bao phủ, không phải thành công rỗng. Với từng finding thực tế phải kiểm tra conservation.

Cả hai curling phải giữ `unit_id`:

`58114fb901d995f4d95d948c211ef89b82117648db9a34447f2d5fc7e48dfdcb`

Cờ trace chỉ tác động bằng chứng, không thay khóa đơn vị. Không dùng tên fixture/case để ép mức; nếu kết quả trái kỳ vọng thì báo thất bại và phân tích, không sửa bảng sau khi đã thấy kết quả mà vẫn giữ version 0.1.

Các kiểm thử hợp đồng cần có trước khi chấp nhận code: hash sai/ID alias trùng; cả hai ngôn ngữ; taint không vết; codeFlows rỗng/malformed; endpoint ở sai sink, sai role hoặc thiếu source; source library_input; literal executable với argv động; biến options/spread; chặn và luồng mâu thuẫn; mọi nhánh quyết định và mặc định; đúng một mức cho mọi tổ hợp predicate hợp lệ. U không được coi là “thấp hơn P3” để lách kỳ vọng.

## 8. Lưu bằng chứng và điều kiện chuyển sang code

1. Kiểm tra Markdown/YAML/JSON nhất quán, hash 13 định nghĩa và cấu trúc bảng quyết định; chưa chạy chính sách.
2. Commit ba file đặc tả/cấu hình/bảng rule-claims cùng nhau, theo Conventional Commits. Commit không chứa code thực thi chính sách, scanner hay migration.
3. Tạo tag `evidence/priority-v0.1-spec` trỏ **đúng commit này**, push và đọc lại `refs/tags/evidence/priority-v0.1-spec` để xác minh. Tag nhẹ hoặc annotated đều được; nếu annotated phải kiểm tra peeled commit. Không dùng nhánh cùng tên thay thế tag; không ghi trạng thái đóng băng khi push tag chưa thành công.
4. Chỉ sau gate tag mới viết code. Không di chuyển/xóa tag. Giữ lịch sử bằng merge commit; nếu squash thì tag đặc tả vẫn phải tồn tại và có liên kết trong log. Thay đổi ngữ nghĩa sau mốc này cần version/tag mới.
5. Sau triển khai, chạy Docker trên curling và R1, ghi CI đúng commit cuối, hash hai cấu hình, phép so ID/vị trí, conservation, unit ID và kết quả kỳ vọng vào `RESEARCH_LOG.md`. Không ghi các kỳ vọng ở trên thành kết quả đã đạt.

Mọi nhãn thủ công, cặp lỗi/vá hoặc tập giữ lại độc lập vẫn đi theo giao thức nghiên cứu; không dùng kết quả đã quan sát để chấm lại một đánh giá giữ lại như thể chính sách đã được chốt trước. Thứ tự hiển thị có thể theo unit ID, nhưng đánh giá xếp hạng dùng kỳ vọng dưới thứ tự ngẫu nhiên đều trong từng mức như Amendment 02.
