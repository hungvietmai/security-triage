import { ScanSearchIcon } from "lucide-react";
import { NotImplemented } from "@/components/common/not-implemented";
import { PageHeader } from "@/components/common/page-header";

export function ScansRoute() {
  return (
    <>
      <PageHeader
        title="Lượt quét"
        description="Theo dõi các lượt chạy Semgrep và CodeQL trên từng bản mã nguồn."
      />
      <NotImplemented
        icon={ScanSearchIcon}
        title="Chưa có lượt quét"
        description="Backend chưa có API chạy công cụ. Trang này sẽ liệt kê lượt quét của mọi dự án khi tính năng sẵn sàng."
        planned={[
          "Hàng đợi Celery chạy Semgrep/CodeQL trong workspace cô lập, có giới hạn thời gian và tài nguyên.",
          "Trạng thái: queued, running, completed, partial, failed, cancelled.",
          "Đo riêng thời gian tạo CodeQL database và chạy query.",
          "Không cài dependency hay thực thi mã nguồn được tải lên.",
        ]}
      />
    </>
  );
}
