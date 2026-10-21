# Đợt C — đánh giá độc lập v0.3 CWE-22

Ngày thiết kế: 2026-10-20. Trạng thái: chuẩn bị trước quét, chưa phải kết quả độc lập.
Phạm vi: Python, Linux/POSIX, CWE-22; tiếp nối
[quyết định v0.3](../v03-interprocedural-guard/DECISION_2026-10-20.md).
Giao thức này quy định thí nghiệm giảm FP; không thay các giao thức command-injection/split cũ.
Không quét hay sử dụng lại các cặp held-out lịch sử.

## 1. Câu hỏi và cấu hình

Đo số cảnh báo sai đã sinh được loại, số TP/TP có điều kiện/unknown bị loại và độ phủ hợp đồng.
Không đo recall tổng thể bằng tập chỉ gồm cảnh báo; không coi CVE không được phát hiện là FP.

| Cấu hình | Vai trò |
|---|---|
| `none` | Truy vấn mặc định CWE-22, với phiên bản thư viện đã ghim |
| `all` | Đường cơ sở v0.2 |
| `v03` | v0.3 strict, mặc định |
| `v03s` | v0.3 scoped; báo riêng phần tăng thêm so với strict |

Chạy cùng snapshot và database; không model pack khai báo gốc riêng cho repository.
Kiểm tra `R_v03s ⊆ R_v03 ⊆ R_all ⊆ R_none` theo (CWE, tệp, dòng, cột sink).
Giữ toàn bộ SARIF, đường tới sink, diagnostics, stderr, lệnh, thời gian và mã thoát.
QL/policy không đổi sau khóa. Hai truy vấn là phép thử trực tiếp trong CodeQL; không tuyên bố
hậu kiểm tốt hơn truy vấn tương đương nếu chưa có cấu hình riêng được thực thi và so sánh.
Semgrep không thuộc phép thử chính này; không nhận là đã đo bổ sung TP hay hiệu quả kết hợp.

## 2. Quần thể, chọn mẫu và phơi nhiễm

Dùng duy nhất `../wave-b/advisories_filtered.json`, metadata đã chụp từ
`github/advisory-database@52e6592044d15d3db09bba0087668c99b52984ab`.
Việc đã thấy metadata advisory không tương đương đã thấy output/source của repository mới.
Đây là mẫu **repository có advisory PyPI CWE-22 có tham chiếu commit vá**, không đại diện mọi
dự án Python. Chọn snapshot tại tham chiếu vá không làm cả repository thành mẫu an toàn.

Quy tắc, cố định trước khi sinh inventory:

1. Giữ hàng `decision=candidate` có `CWE-22`. Chỉ nhận URL commit GitHub đúng dạng với SHA đủ
   40 ký tự hex; chuẩn hóa owner/repo về chữ thường. URL không hợp lệ được ghi vào ledger.
2. Loại mọi repository trong `exclusions.json`: toàn bộ repository của inventory cặp cũ
   (gồm development, held-out, reserve, excluded), repository đã xét ở đợt A/B và các dự án
   đã nghiên cứu ghi trong danh sách loại. Giữ nguồn và lý do loại; không đọc output held-out.
3. Gộp mọi advisory/commit cùng repository. Chọn anchor có hash nhỏ nhất của
   `security-triage/wave-c-v1/anchor/<ghsa_id>/<owner/repo>/<sha>`; đối chiếu bằng tuple từ điển
   nếu hash bằng nhau. Không xét nội dung bản vá để chọn anchor.
4. Sắp repository theo `sha256("security-triage/wave-c-v1/repository/" + owner/repo)`,
   rồi owner/repo khi hòa. Lấy **12 repository đầu tiên**, không chia lại và không thêm mẫu
   sau khi xem kết quả. `selection.json` cố định seed, số lượng, nguồn và các hash đầu vào.
5. `inventory.json` giữ SHA, advisory nguồn, thứ tự, mọi ứng viên còn lại và lý do loại.
   Tạo `LOCK.sha256` trước khi tải source. `--check` phải tái tạo đúng từng byte inventory.

Không chọn theo số cảnh báo, validator, tài nguyên, framework, sao GitHub hay FP đã biết.
Mẫu không đủ 12 thì giữ mẫu nhỏ hơn, không đổi seed. Repository alias/fork/near-duplicate
phát hiện khi xác minh trước quét được ghi quan hệ nhóm; repository liên quan dữ liệu phát
triển bị loại khỏi độc lập, **không thay thế**. Phát hiện sau quét cũng giữ lịch sử, báo
contamination và không dùng nhóm đó để khẳng định độc lập.

## 3. Chuẩn bị source và các cổng trước quét

- Sau khóa inventory, tải archive của đúng SHA, giữ byte gốc và SHA-256 (TOFU được ghi rõ).
  Xác minh commit tồn tại và repository/alias/fork; không chuyển sang HEAD hoặc bản vá khác.
- Giới hạn mỗi archive 50 MiB, tổng giải nén 500 MiB và 50.000 entry; từ chối path traversal,
  liên kết, tệp đặc biệt và archive lỗi. Không thực thi source, không cài dependency ứng dụng.
  Giữ tất cả file Python có thể trích xuất; không bỏ tests khỏi database để làm gốc ổn định.
- Ghi archive hash, commit, acquisition status, quan hệ nhóm, extractor coverage và lỗi trong
  manifest chuẩn bị riêng; không ghi đè inventory đã khóa.
- Trước quét đầu: khóa và **commit/publish** phương pháp, inventory, script chạy/chấm điểm,
  archive hashes, tool/pack lock và lệnh. Ghi commit URL và thời điểm công bố do dịch vụ ghi nhận.
  Bản khóa tại máy chưa phải bằng chứng công bố trước quét. Chỉ commit/push khi người dùng yêu cầu.
- Phiên bản mục tiêu theo vòng phát triển: CodeQL 2.27.1, python-queries 1.8.11,
  python-all 7.2.6. Kiểm tra CLI thực tế, lưu version và resolution lock trước khi chạy;
  không tự nâng cấp khi thiếu công cụ. Mọi analyze và query diagnostic dùng `--rerun`.
- Chuẩn bị script chạy/chấm điểm bằng fixture tổng hợp, không chạy scanner trên cặp nghiên cứu
  để thử công cụ. Script phát triển `run_dev.sh` không phải runner của đợt C.

## 4. Ngân sách và dừng

Không sửa quy tắc (0 vòng phát triển), không thêm nguồn/sink/model hay hợp đồng theo repository.
Mỗi repository: tạo database tối đa 30 phút; mỗi cấu hình/diagnostic tối đa 20 phút;
RAM tối đa 5.000 MiB, 2 thread. Ngân sách scanner chung tối đa 24 giờ wall time.
Chạy theo thứ tự inventory. Một lần retry cùng đầu vào chỉ cho lỗi hạ tầng tạm thời;
timeout/lỗi trích xuất vẫn là kết quả thiếu, không thay repository hoặc tăng giới hạn hậu nghiệm.

Dừng vì đủ 12 lượt attempted, hết mẫu hoặc chạm ngân sách. Không dừng sớm vì số FP đẹp/xấu.
Nếu phát hiện loại nhầm TP/TP có điều kiện, giả định sai có tác động an toàn, hoặc vi phạm
chuỗi tập con: lưu output và dừng đợt xác nhận, ghi `failed_acceptance`. Không vá rồi tiếp tục
gọi cùng đợt là held-out. Phần đã xem trở thành dữ liệu phát triển khi dùng để sửa phương pháp.

Ngân sách rà nhãn: tối đa 24 active reviewer-hours, thời gian thực đo riêng với runtime.
Ưu tiên rà **mọi** sink bị bất kỳ cấu hình nào loại, rồi sink còn lại theo hash
`security-triage/wave-c-v1/review/<repo>@<sha>/<file>:<line>:<column>`.
Hết ngân sách thì giữ nhãn chưa rà là `unreviewed`, không coi là FP/TP/unknown đã rà.
Không tuyên bố FP reduction rate toàn mẫu khi mẫu số FP chưa được rà hết.

## 5. Nhãn và kiểm tra giả định

Đơn vị nhãn là một sink cùng mọi luồng được CodeQL báo đến sink, không phải từng path row.
Tách production/test/example; mã có tên test nhưng được runtime gọi phải được ghi rõ.
Nhãn kỹ thuật: TP, TP_conditional, FP, unknown; thêm scope, root_cause_id, bằng chứng và trạng
thái reviewer. Không tự ghi owner_reviewed hoặc giả danh người dùng xác nhận nhãn.

Chuẩn bị gói rà lần đầu ẩn cấu hình lọc, quyết định loại, nhãn cũ và tên quy tắc khi có thể;
giữ mã/luồng cần để đánh giá. Chủ đề án rà hoặc nhãn chỉ là proposed/exploratory.
Nếu một reviewer, giữ giới hạn đó; lần hai sau ít nhất 7 ngày, đổi thứ tự và ẩn nhãn lần đầu
theo giao thức hiện hành. Giữ hai lượt và hòa giải; không gọi là hai reviewer độc lập.

Oracle nhãn không đọc quyết định của bộ lọc hay suy nhãn từ model pack. Đối với mọi sink bị loại,
rà độc lập S-TEST, S-TMP/A-SYM, S-PURPOSE, S-ENV và mọi đường tới sink. Mỗi giả định nhận
`supported`, `contradicted`, hoặc `unknown` kèm bằng chứng/phạm vi mô hình đe dọa.
S-TEST cần xét import/call vào mã mang tên test; regex của QL không phải bằng chứng triển khai.
S-PURPOSE phải nêu giới hạn phân quyền; không đồng nhất containment với quyền giữa tenant.

Giữ hai kết quả: `raw_suppressed` của QL và `accepted_suppression` sau rà phạm vi.
Giả định contradicted/unknown không được âm thầm sửa số liệu nguyên bản; quyết định vận hành
giữ cảnh báo, ghi `scope_rejected`/`scope_unknown`. Báo cả số TP/unknown bị bộ lọc nguyên bản loại.
Một ca dangerous chỉ được gọi là kiểm tra không vacuous khi baseline thực sự phát hiện nó.

## 6. Báo cáo và diễn giải đã định trước

Mỗi repository và toàn mẫu báo attempted/completed/failed/zero-alert, số sink production/test,
nhóm nguyên nhân gốc và các số sau cho strict/scoped riêng:

- Số cảnh báo bị loại so với v0.2; phần scoped tăng thêm so với strict.
- FP được loại, TP/TP_conditional/unknown/unreviewed bị loại; số giữ theo từng nhãn.
- Độ phủ hợp đồng = số sink v0.2 có AllowedRoot / tổng sink v0.2, trên cùng scope và snapshot.
  Báo riêng proved/scoped, thiếu hợp đồng, thiếu containment và giả định không chấp nhận được.
- Tỷ lệ loại FP = FP được loại / toàn bộ FP đã xác nhận trên cùng tập ứng viên; chỉ là tỷ lệ
  của phần đã rà nếu chưa đầy đủ. Mẫu số 0 ghi N/A; không loại repository 0 cảnh báo khỏi bảng.
- Số root cause có ít nhất một sink bị loại và số root cause được loại toàn bộ; báo theo repo.
  Không coi nhiều sink cùng gốc là quan sát độc lập, không suy khoảng tin cậy theo số SARIF row.
- Runtime, retry, giới hạn trích xuất, phạm vi kiểm thử, số nhãn proposed/chưa rà và contamination.

Điều kiện chấp nhận: không loại TP/TP_conditional/unknown đã rà, không vi phạm tập con,
mọi ca loại có hồ sơ bằng chứng và giả định. Chưa rà hết phần bị loại thì kết quả chưa hoàn chỉnh.
Nếu không có FP được loại: báo 0 và dừng mở rộng quy tắc trong đợt này. Nếu hiệu quả chỉ ở một
nhóm độc lập: báo tính khả thi; tối thiểu hai root cause ở hai repository độc lập mới hỗ trợ
nhận xét hiệu quả ngoài một dự án (vẫn không phải chứng minh thống kê/an toàn tuyệt đối).

## 7. Hiện trạng

Đợt C chưa tải source, chưa chạy scanner và chưa có nhãn. Inventory/khóa tại máy có thể được
chuẩn bị ngay; công bố và các cổng ở mục 3 phải hoàn tất trước quét độc lập.
