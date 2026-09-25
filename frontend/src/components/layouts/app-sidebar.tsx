import { Link, useRouterState } from "@tanstack/react-router";
import {
  ActivityIcon,
  FolderKanbanIcon,
  LayoutDashboardIcon,
  ScanSearchIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  type LucideIcon,
} from "lucide-react";
import type { ReactNode } from "react";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
} from "@/components/ui/sidebar";
import { paths } from "@/config/paths";

type NavPath =
  | typeof paths.dashboard
  | typeof paths.projects
  | typeof paths.scans
  | typeof paths.findings
  | typeof paths.system;

interface NavItem {
  route: NavPath;
  icon: LucideIcon;
  /** The backend has no API for this area yet. */
  pending?: boolean;
}

const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: "Không gian làm việc",
    items: [
      { route: paths.dashboard, icon: LayoutDashboardIcon },
      { route: paths.projects, icon: FolderKanbanIcon },
    ],
  },
  {
    label: "Phân tích",
    items: [
      { route: paths.scans, icon: ScanSearchIcon, pending: true },
      { route: paths.findings, icon: ShieldAlertIcon, pending: true },
    ],
  },
  {
    label: "Vận hành",
    items: [{ route: paths.system, icon: ActivityIcon }],
  },
];

function isActive(pathname: string, to: string) {
  return to === "/"
    ? pathname === "/"
    : pathname === to || pathname.startsWith(`${to}/`);
}

export function AppSidebar({ footer }: { footer?: ReactNode }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" asChild>
              <Link to={paths.dashboard.path}>
                <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                  <ShieldCheckIcon className="size-4" />
                </div>
                <div className="grid flex-1 text-left text-sm leading-tight">
                  <span className="truncate font-semibold">
                    Security Triage
                  </span>
                  <span className="truncate text-xs text-muted-foreground">
                    Semgrep + CodeQL
                  </span>
                </div>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        {NAV_GROUPS.map((group) => (
          <SidebarGroup key={group.label}>
            <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {group.items.map(({ route, icon: Icon, pending }) => (
                  <SidebarMenuItem key={route.path}>
                    <SidebarMenuButton
                      asChild
                      isActive={isActive(pathname, route.path)}
                      tooltip={route.label}
                    >
                      <Link to={route.path}>
                        <Icon />
                        <span>{route.label}</span>
                      </Link>
                    </SidebarMenuButton>
                    {pending && (
                      <SidebarMenuBadge className="text-[10px] font-normal text-muted-foreground">
                        Sắp có
                      </SidebarMenuBadge>
                    )}
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        ))}
      </SidebarContent>
      {footer && (
        <SidebarFooter>
          <SidebarMenu>
            <SidebarMenuItem>{footer}</SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
      )}
      <SidebarRail />
    </Sidebar>
  );
}
