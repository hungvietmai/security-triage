# Tiến độ hoàn thiện đề án

Ghi lại để tiếp tục khi phiên làm việc bị gián đoạn. Cập nhật lần cuối: 2026-11-14.
Mọi thay đổi sau commit `1d581a6` đang nằm ở working tree của nhánh `feat/cwe22-triage`,
đã commit cục bộ (chưa push), kể cả phần phiên bản 0.3.

## Mục tiêu

Luồng **phát hiện rộng → chuẩn hóa và gộp cảnh báo trùng → thẩm định và gạn cảnh báo sai →
báo cáo trước–sau**, theo đề cương "Xây dựng quy trình sàng lọc và thẩm định cảnh báo lỗ hổng
kết hợp Semgrep và CodeQL". CWE-78 là kịch bản chính; CWE-22 trên Python là minh họa bổ sung.

## Đã làm (theo thứ tự)

1. Profile `path-traversal-v0.2` (đã commit `2344e5b`, `1d581a6`).
2. Bandit và ESLint trong bước phát hiện; profile `command-injection-v0.2`, chính sách ưu tiên
   v0.2, `rule-claims-v3`. Sửa lỗi CodeQL không trích xuất được TypeScript (thiếu Node.js).
3. Bước gạn `adjudicate-v0.2` ([backend/app/triage/adjudicate.py](../../backend/app/triage/adjudicate.py)):
   gộp đơn vị theo lời gọi thành ứng viên; quy tắc G3 (luật nhánh chết của Semgrep CE, công cụ
   mã nguồn mở được chọn cho bước gạn), G1 (bằng chứng an toàn của CodeQL) và G2 (lệnh là hằng,
   có Bandit xác nhận).
4. CodeQL chạy truy vấn bằng chứng CWE-78 trên chính database đã tạo
   ([rules/codeql/command-injection-evidence-v0.2/](../../rules/codeql/command-injection-evidence-v0.2/README.md)).
5. Migration `0007`, API `disposition`, `GET /scans/{id}/report` và `/report.sarif`.
6. Giao diện: danh sách rà chính / đã gạn, khối "Thẩm định" trong chi tiết, báo cáo trước–sau.
7. Đánh giá từ báo cáo đã lưu: [experiments/evaluation/](../../experiments/evaluation/README.md).
8. Trình diễn trên stack thật bằng trình duyệt: [docs/demo/README.md](../demo/README.md).
9. Kiểm tra độc lập quy mô nhỏ trên ba ứng dụng chưa từng quét, giao thức băm trước khi quét:
   [experiments/evaluation/independent/](../../experiments/evaluation/independent/PROTOCOL.md).
   **Không quét lại các nguồn này và không sửa ba tệp đã băm.**
10. Hồ sơ đề án: [commitments.md](commitments.md), [chapter-2-notes.md](chapter-2-notes.md),
   [chapter-3-results.md](chapter-3-results.md); bảng tiêu chí ở [README.md](README.md).
11. Kiểm tra độc lập đợt 2: 52 package npm có CVE chèn lệnh của SecBench.js nằm ngoài
   inventory đã khóa ([independent-secbench/](../../experiments/evaluation/independent-secbench/PROTOCOL.md)).
   Đợt 3: ba ứng dụng Python, sáu vị trí
   ([independent-python/](../../experiments/evaluation/independent-python/PROTOCOL.md)).
   **Không quét lại các nguồn này và không sửa các tệp đã băm**; sai lệch duy nhất được ghi ở
   [DEVIATIONS.md](../../experiments/evaluation/independent-secbench/DEVIATIONS.md).
12. Sửa lỗi tìm thấy nhờ đợt 2: worker đọc tệp nguồn có `\r\n` làm lệch vị trí byte của
   Semgrep và hỏng cả lượt quét ([acquisition.py](../../backend/app/scanners/acquisition.py)).
13. Bộ chấm cho `pairs-v1`, kiểm thử mà không quét cặp nào:
   [pairs-v1/](../../experiments/evaluation/pairs-v1/README.md).
14. Kiểm tra độc lập đợt 4, có cả nhãn an toàn: 210 dòng mã minh họa của kho semgrep-rules
   ([independent-labeled/](../../experiments/evaluation/independent-labeled/PROTOCOL.md)). Lượt
   quét đã đăng ký thất bại vì lỗi của nguyên mẫu; kết quả có P/R/F1 là của lượt quét lại sau
   khi sửa, ghi ở [DEVIATIONS.md](../../experiments/evaluation/independent-labeled/DEVIATIONS.md).
   **Không quét lại nguồn này.**
15. Sửa lỗi thứ hai do dữ liệu độc lập làm lộ: một tệp Python sai cú pháp làm hỏng cả lượt quét
   ([analysis.py](../../backend/app/workflows/scans/analysis.py)); nay lượt quét thành `partial`
   và không gạn gì.
16. Đối chiếu tài liệu tham khảo của đề cương với nguồn (bảng ở cuối Chương 1).
17. Kiểm tra độc lập đợt 5: 20 công cụ dòng lệnh Python thật, không có nhãn, để xem bước gạn có
   hành động ở lượt quét hoàn tất không ([independent-filter/](../../experiments/evaluation/independent-filter/PROTOCOL.md)).
   Kết quả và phần đọc lại: [READING.md](../../experiments/evaluation/independent-filter/READING.md). **Không quét lại.**
18. Danh mục tài liệu tham khảo đã sửa: [tai-lieu-tham-khao.md](tai-lieu-tham-khao.md).
19. `pairs-v1`: Amendment 06 (tập phát triển, v0.2), Amendment 07 (hoãn tập giữ lại) và Amendment
   08 (mở tập giữ lại cho v0.3). **Tập giữ lại đã được quét một lần ngày 2026-11-15**: hợp mọi
   nguồn báo 9/9 vị trí lỗi đã biết, 0 bị gạn. Không quét lại:
   [pairs-v1/](../../experiments/evaluation/pairs-v1/README.md).
20. Profile `command-injection-v0.3`: phạm vi tệp của Semgrep do worker quyết định, bộ định vị
   lời gọi JavaScript v1, quy tắc gạn G4 (lệnh hằng). So sánh v0.2 → v0.3 trên 84 nguồn:
   [js-matching-v0.3/](../../experiments/evaluation/js-matching-v0.3/READING.md).
21. Văn bản ba chương và Kết luận: [chuong-1-tong-quan.md](chuong-1-tong-quan.md),
   [chuong-2-thiet-ke.md](chuong-2-thiet-ke.md), [chuong-3-thuc-nghiem.md](chuong-3-thuc-nghiem.md),
   [ket-luan.md](ket-luan.md).

## Lệnh kiểm tra đã chạy và kết quả

Ghi trong [docs/validation.md](../validation.md), mục 2, các dòng ngày 2026-11-14.

## Trạng thái máy cục bộ khi dừng

- Stack Docker đã dừng (`docker compose start` để mở lại; dữ liệu còn trong volume).
- Cơ sở dữ liệu cục bộ có dự án "Danh gia truoc-sau (du lieu phat trien)" chứa các lượt quét
  dùng cho đánh giá, và dự án "Kiem chung profile path-traversal-v0.2" từ lần kiểm trước.
- Chromium của Playwright đã cài trên máy (dùng cho `npm run test:e2e` và kịch bản trình diễn).
- `artifacts/demo-adjudication/` (không theo dõi bởi Git) chứa ảnh và tệp xuất của lần trình
  diễn cuối.
- Cơ sở dữ liệu cục bộ có thêm 79 lượt quét của năm đợt kiểm tra độc lập và ba lượt quét lại
  sau khi sửa lỗi, trong cùng dự án "Danh gia truoc-sau (du lieu phat trien)".
- `artifacts/pair-sources/` **không có** trên máy này (bộ lưu trữ nguồn đã khóa của `pairs-v1`).

## Việc tiếp theo

1. Push khi chủ đề án quyết định (nhánh trên remote đang ở `3feb328`; các commit sau đó chỉ ở local). Không commit file PDF đề cương.
2. Tập giữ lại của `pairs-v1` đã dùng xong; phiên bản sau v0.3 cần một tập giữ lại mới.
3. Nhãn cho mọi ứng viên JavaScript của 84 nguồn: trợ lý AI đề xuất, chủ đề án rà từng ca cả 84
   nhãn (15/11; sửa 12, tách một ca thành bảy). Kết quả: 60 có lỗi, 11 an toàn, 13 chưa xác
   định; hợp mọi nguồn TP 122, FP 11; bước gạn chuyển đi 1 cảnh báo sai, gạn nhầm 0. Xem
   [js-labels-v0.3/](../../experiments/evaluation/js-labels-v0.3/README.md). Mã ứng dụng thật ngoài các package này
   vẫn chưa có nhãn. Người rà thứ hai: gói rà mù cho 38 đơn vị đã chuẩn bị (15/11), chưa có
   phiếu trả lời.
4. Bằng chứng gạn cho các loại cảnh báo sai JavaScript còn lại (giá trị đã kiểm tra hoặc trích
   dẫn, giá trị nội bộ, lời gọi không qua shell); bộ định vị chưa thấy lời gọi qua
   `_child_process.default.exec` của mã Babel (`git-parse`); cách biểu diễn một cảnh báo liên quan
   tới nhiều lời gọi (14 cảnh báo còn ở hàng U, xem `js-matching-v0.3/READING.md`).
5. Duyệt văn bản ba chương, chuyển sang mẫu trình bày của Học viện; sửa danh mục tài liệu tham
   khảo theo bảng đối chiếu ở cuối Chương 1 ([1], [6], [8] sai tác giả; không tìm thấy [9]).
6. Quyết định có thu hẹp nguyên tắc "chạy dở thì giữ" xuống mức tệp hay không: hiện một tệp
   không phân tích được tắt bước gạn của cả lượt quét.
7. Phiếu rà soát (kết luận đúng/sai của người rà) nếu cần đo với người dùng.
