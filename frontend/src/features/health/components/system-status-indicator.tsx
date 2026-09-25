import { Link } from "@tanstack/react-router";
import { SidebarMenuButton } from "@/components/ui/sidebar";
import { paths } from "@/config/paths";
import { useReadiness } from "@/features/health/api/get-readiness";
import { StatusDot } from "@/features/health/components/status-label";
import { overallState } from "@/features/health/utils/service-state";

const LABELS = {
  checking: "Đang kiểm tra dịch vụ",
  ok: "Tất cả dịch vụ sẵn sàng",
  unavailable: "Dịch vụ gặp sự cố",
  unknown: "Dịch vụ gặp sự cố",
};

/** Sidebar footer entry summarizing readiness; links to the system page. */
export function SystemStatusIndicator() {
  const readiness = useReadiness();
  const state = overallState(readiness.data, {
    pending: readiness.isPending,
    failed: readiness.isError,
  });

  return (
    <SidebarMenuButton asChild size="sm" tooltip="Trạng thái hệ thống">
      <Link to={paths.system.path}>
        <StatusDot state={state} />
        <span className="truncate text-muted-foreground">{LABELS[state]}</span>
      </Link>
    </SidebarMenuButton>
  );
}
