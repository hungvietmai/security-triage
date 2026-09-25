import { Link } from "@tanstack/react-router";
import {
  ArrowRightIcon,
  CheckCircle2Icon,
  CircleDashedIcon,
  FileArchiveIcon,
  FolderKanbanIcon,
  ScanSearchIcon,
  ShieldAlertIcon,
  type LucideIcon,
} from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { paths } from "@/config/paths";
import { ServiceStatusList } from "@/features/health/components/service-status-list";
import { useProjects } from "@/features/projects/api/get-projects";
import { CreateProjectDialog } from "@/features/projects/components/create-project-dialog";
import { RecentProjects } from "@/features/projects/components/recent-projects";

// Mirrors docs/architecture.md; update as milestones land.
const PIPELINE: { title: string; detail: string; done: boolean }[] = [
  { title: "Quản lý dự án", detail: "Tạo, liệt kê và xem dự án", done: true },
  {
    title: "Nạp mã nguồn",
    detail: "Manifest có phiên bản cố định, upload ZIP có giới hạn",
    done: false,
  },
  {
    title: "Quét Semgrep",
    detail: "Lưu SARIF thô, cấu hình, thời gian và lỗi",
    done: false,
  },
  {
    title: "Quét CodeQL",
    detail: "Baseline độc lập, đo riêng tạo DB và chạy query",
    done: false,
  },
  {
    title: "Thẩm định CWE-78",
    detail: "Chính sách bằng chứng: supported / inconclusive / proposed_reject",
    done: false,
  },
];

function StatCard({
  title,
  icon: Icon,
  value,
  hint,
  loading = false,
}: {
  title: string;
  icon: LucideIcon;
  value: string | number;
  hint: string;
  loading?: boolean;
}) {
  return (
    <Card size="sm">
      <CardHeader>
        <CardDescription>{title}</CardDescription>
        <CardAction>
          <Icon className="size-4 text-muted-foreground" />
        </CardAction>
        <CardTitle className="text-2xl tabular-nums">
          {loading ? <Skeleton className="h-8 w-12" /> : value}
        </CardTitle>
      </CardHeader>
      <CardContent className="text-xs text-muted-foreground">
        {hint}
      </CardContent>
    </Card>
  );
}

function PipelineProgress() {
  return (
    <ol className="grid gap-4 md:grid-cols-5">
      {PIPELINE.map((step, index) => (
        <li key={step.title} className="flex gap-3 md:flex-col md:gap-2">
          <div className="flex items-center gap-2">
            {step.done ? (
              <CheckCircle2Icon className="size-5 shrink-0 text-emerald-600 dark:text-emerald-400" />
            ) : (
              <CircleDashedIcon className="size-5 shrink-0 text-muted-foreground" />
            )}
            <span className="text-xs text-muted-foreground tabular-nums">
              Bước {index + 1}
            </span>
          </div>
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2 text-sm font-medium">
              {step.title}
              {!step.done && (
                <Badge variant="outline" className="font-normal">
                  Chưa có
                </Badge>
              )}
            </div>
            <p className="text-xs text-muted-foreground">{step.detail}</p>
          </div>
        </li>
      ))}
    </ol>
  );
}

export function DashboardRoute() {
  const projects = useProjects({ page: 1 });

  return (
    <>
      <PageHeader
        title="Tổng quan"
        description="Sàng lọc và thẩm định cảnh báo lỗ hổng từ Semgrep và CodeQL cho JavaScript/TypeScript và Python."
        actions={<CreateProjectDialog />}
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          title="Dự án"
          icon={FolderKanbanIcon}
          value={projects.data?.total ?? "—"}
          hint={projects.isError ? "Không tải được" : "Tổng số dự án"}
          loading={projects.isPending}
        />
        <StatCard
          title="Bản mã nguồn"
          icon={FileArchiveIcon}
          value="—"
          hint="Chưa triển khai nạp mã nguồn"
        />
        <StatCard
          title="Lượt quét"
          icon={ScanSearchIcon}
          value="—"
          hint="Chưa triển khai chạy công cụ"
        />
        <StatCard
          title="Cảnh báo cần thẩm định"
          icon={ShieldAlertIcon}
          value="—"
          hint="Chưa triển khai thẩm định"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Dự án gần đây</CardTitle>
            <CardDescription>5 dự án được tạo gần nhất</CardDescription>
            <CardAction>
              <Button variant="ghost" size="sm" asChild>
                <Link to={paths.projects.path}>
                  Xem tất cả
                  <ArrowRightIcon data-icon="inline-end" />
                </Link>
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            <RecentProjects />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Dịch vụ</CardTitle>
            <CardDescription>Tự kiểm tra lại mỗi 15 giây</CardDescription>
            <CardAction>
              <Button variant="ghost" size="sm" asChild>
                <Link to={paths.system.path}>Chi tiết</Link>
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            <ServiceStatusList />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Tiến độ quy trình</CardTitle>
          <CardDescription>
            Các bước của pipeline và trạng thái triển khai hiện tại
          </CardDescription>
        </CardHeader>
        <CardContent>
          <PipelineProgress />
        </CardContent>
      </Card>
    </>
  );
}
