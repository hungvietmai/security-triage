# Đặc tả profile multi-cwe-v0.5

- **Ngày:** 2026-11-16.
- **Trạng thái:** **profile ghép thử nghiệm**. Thiết kế và kết quả nằm ở
  [docs/plans/multi-cwe.md](../../docs/plans/multi-cwe.md), mục 24.
- **Nội dung:**
  - Profile này không có luật, truy vấn, chính sách hay quy tắc gạn của riêng nó.
  - Nó ghim manifest của bốn profile thành viên và quét chúng trong cùng một lượt, cách ghép
    `family-composition-v0.1`.
- **Mốc đối chứng:** `multi-cwe-v0.4`, vẫn là một profile riêng và không thay đổi.

## 1. Thành viên

| Nhóm phân tích | CWE | Profile thành viên | Kiểu | Ngôn ngữ |
|---|---|---|---|---|
| `command-injection` | CWE-78 | `command-injection-v0.3` | xếp hạng và gạn (G1–G4) | Python, JavaScript/TypeScript |
| `path-traversal` | CWE-22 | `path-traversal-v0.2` | bằng chứng an toàn | Python |
| `sql-injection` | CWE-89 | `sql-injection-v0.3` | chỉ phát hiện và giữ, Semgrep + Bandit + CodeQL | Python, JavaScript/TypeScript |
| `cross-site-scripting` | CWE-79 | `cross-site-scripting-v0.1` | chỉ phát hiện và giữ, CodeQL | JavaScript/TypeScript |

- Ba thành viên đầu giống hệt `multi-cwe-v0.4`: cùng manifest, cùng hash.
- Thành viên CWE-79 chạy bảy truy vấn chuẩn của CodeQL trong `Security/CWE-079/`, theo
  `profiles/cross-site-scripting-v0.1/DETECTION.md`.

## 2. Cách chạy, phân loại, lỗi

Như `multi-cwe-v0.4`:

- Thành viên đứng đầu (`command-injection-v0.3`) chạy công cụ sàng lọc và tạo một database CodeQL cho
  mỗi ngôn ngữ. Mỗi thành viên khác chạy truy vấn của mình trên database đó, trong lượt riêng có tên:
  CWE-79 là `codeql-cross-site-scripting`, chỉ ở JavaScript/TypeScript.
- Trong một lượt quét, các thành viên phải ghim cùng phiên bản CodeQL, Semgrep và Bandit.
- Nhóm của mỗi cảnh báo được gán theo lượt chạy, trước mọi phép gộp. Cảnh báo của hai nhóm không bao
  giờ chung một đơn vị, kể cả khi trùng vị trí.
- Mức hoàn tất tính theo nhóm. Lượt CWE-79 lỗi hay dở chỉ làm nhóm CWE-79 "thất bại" hoặc "chạy dở";
  các nhóm khác giữ nguyên kết quả. Mọi cảnh báo của lượt quét nằm trong đúng một đơn vị.
