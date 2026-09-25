import { Outlet } from "@tanstack/react-router";
import { DashboardLayout } from "@/components/layouts/dashboard-layout";
import { SystemStatusIndicator } from "@/features/health/components/system-status-indicator";

export function RootRoute() {
  return (
    <DashboardLayout sidebarFooter={<SystemStatusIndicator />}>
      <Outlet />
    </DashboardLayout>
  );
}
