import { ShieldAlertIcon } from "lucide-react";
import { NotImplemented } from "@/components/common/not-implemented";
import { PageHeader } from "@/components/common/page-header";

export function FindingsRoute() {
  return (
    <>
      <PageHeader
        title="Cảnh báo"
        description="Cảnh báo Semgrep và CodeQL đã gộp theo vị trí sink, kèm mức ưu tiên và bằng chứng."
      />
      <NotImplemented
        icon={ShieldAlertIcon}
        title="Danh sách cảnh báo toàn hệ thống"
        description="Cảnh báo hiện được xem theo từng lượt quét: mở một dự án, tạo hoặc mở lượt quét để xem hàng đợi P1–P4 và bằng chứng của từng đơn vị."
        planned={[
          "API liệt kê cảnh báo của mọi lượt quét, lọc theo dự án, công cụ, mức ưu tiên và CWE.",
          "Mức ưu tiên là thứ tự rà soát, không phải nhãn đúng/sai; không mức nào xóa cảnh báo.",
          "Không có cảnh báo không có nghĩa là mã an toàn.",
        ]}
      />
    </>
  );
}
