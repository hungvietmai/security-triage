import { ShieldAlertIcon } from "lucide-react";
import { NotImplemented } from "@/components/common/not-implemented";
import { PageHeader } from "@/components/common/page-header";

export function FindingsRoute() {
  return (
    <>
      <PageHeader
        title="Cảnh báo"
        description="Rà soát cảnh báo Semgrep kèm bằng chứng và quyết định thẩm định."
      />
      <NotImplemented
        icon={ShieldAlertIcon}
        title="Chưa có cảnh báo"
        description="Chưa có công cụ nào được chạy nên chưa có cảnh báo để thẩm định."
        planned={[
          "Phạm vi đầu tiên: CWE-78 (command injection) cho JavaScript và Python.",
          "Kết quả thẩm định: supported, inconclusive hoặc proposed_reject, kèm bằng chứng.",
          "Cảnh báo chỉ có ở CodeQL được giữ làm baseline độc lập, không đưa vào kết quả chính.",
          "Không có cảnh báo CodeQL không có nghĩa là mã an toàn.",
        ]}
      />
    </>
  );
}
