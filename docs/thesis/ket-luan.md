# KẾT LUẬN

> **Ghi chú cho người viết (không thuộc nội dung đề án).** Văn bản ngày 2026-11-14. Số liệu lấy
> từ [chuong-3-thuc-nghiem.md](chuong-3-thuc-nghiem.md).

**Kết quả đạt được.** Đề án đã xây dựng và đánh giá một quy trình bốn bước để sàng lọc và thẩm
định cảnh báo lỗ hổng, kết hợp Semgrep, công cụ bổ trợ theo ngôn ngữ (Bandit, ESLint với
eslint-plugin-security) và CodeQL: phát hiện rộng, chuẩn hóa và gộp cảnh báo trùng, thẩm định và
gạn cảnh báo sai, báo cáo trước–sau. Quy trình được cài đặt thành một nguyên mẫu chạy được trên
mã Python và JavaScript/TypeScript, với kết quả trao đổi theo SARIF và mọi công cụ, luật, truy
vấn được cố định phiên bản.

So với đề cương, đề án điều chỉnh một điểm: tập ứng viên là hợp kết quả của mọi công cụ, thay vì
chỉ là kết quả quét nhanh. Số đo cho thấy luồng nối tiếp làm mất các lỗi thật mà công cụ quét
nhanh bỏ sót.

Các kết quả chính:

1. Lấy hợp các nguồn phát hiện được nhiều lỗi thật hơn từng công cụ. Trên 43 lỗ hổng chèn lệnh
   thật của package npm mà dự án chưa từng xem, quy trình báo 32, so với 27 của CodeQL và 12 của
   Semgrep chạy riêng. Trên bộ OWASP BenchmarkPython, quy trình báo 13/13 lỗi thật, so với 11
   của CodeQL.
2. Gộp theo lời gọi biến cảnh báo của bốn công cụ thành một danh sách ứng viên, giữ nguyên nguồn
   gốc; trên bộ OWASP, 51 cảnh báo thô thành 20 mục rà soát.
3. Bước gạn chỉ hành động khi có bằng chứng cụ thể và chưa làm mất lỗi thật nào trong mọi phép
   đo, kể cả trên bảy vị trí lỗi Python chưa từng xem. Trên dữ liệu phát triển, nó loại 2 trong 7
   cảnh báo sai; 1 trong 7 nếu chỉ dùng công cụ mã nguồn mở. Trên 20 công cụ dòng lệnh Python
   thật chưa từng xem, nó gạn 19 trong 145 ứng viên của các lượt quét hoàn tất, đều là lời gọi
   có lệnh hằng.
4. Nhóm rà trước (P1 và P2) chứa phần lớn lỗi thật: 11/13 trên bộ OWASP và không kèm cảnh báo
   sai nào; 29/32 trên các package npm.

**Hạn chế.**

- Phần bước gạn loại được còn hẹp. Trên mã chưa từng xem, chỉ quy tắc "lệnh là hằng" hoạt
  động; các quy tắc dựa trên bằng chứng luồng dữ liệu của Semgrep và CodeQL mới chỉ hoạt động
  trên dữ liệu phát triển. Một lượt quét chạy dở, kể cả chỉ vì một tệp không phân tích được,
  tắt bước gạn của cả lượt.
- Lấy hợp các nguồn đổi độ chính xác lấy độ bao phủ. Trên 210 dòng mã minh họa có cả nhãn an
  toàn mà dự án chưa từng xem, quy trình đạt F1 0,69, cao hơn mọi công cụ chạy riêng, nhưng độ
  chính xác 0,66 thấp hơn Semgrep (0,88) và CodeQL (1,00). Trên bộ OWASP, F1 của quy trình
  (0,84) không vượt CodeQL chạy riêng (0,85). Trên mã ứng dụng thật chưa có số đo độ chính xác.
- Bước gạn chưa có gói bằng chứng cho JavaScript/TypeScript.
- Tập giữ lại gồm các cặp phiên bản lỗi/vá của CVE thật chưa được dùng.
- Nguyên mẫu chạy cục bộ cho một người dùng; chưa có cấu hình mẫu để gắn vào hệ thống tích hợp
  liên tục và chưa được đánh giá với người rà soát.

**Hướng phát triển.**

- Viết gói bằng chứng cho JavaScript/TypeScript và mở rộng các tình huống an toàn cho Python dựa
  trên mã thực tế thay vì benchmark.
- Hoàn thiện bộ định vị lời gọi JavaScript, nơi dữ liệu độc lập đã chỉ ra các ca chưa gộp được.
- Đánh giá trên tập giữ lại và trên một mẫu ứng viên có người gán nhãn, để đo độ chính xác.
- Mở rộng sang nhóm lỗi khác theo cách đã làm với duyệt đường dẫn (CWE-22).
- Cung cấp giao diện dòng lệnh để tích hợp vào quy trình tích hợp liên tục.
- Nghiên cứu dùng mô hình ngôn ngữ lớn để giải thích cảnh báo hoặc gợi ý sửa lỗi trong báo cáo,
  với điều kiện giữ nguyên tắc chỉ gạn khi có bằng chứng kiểm tra lại được.
