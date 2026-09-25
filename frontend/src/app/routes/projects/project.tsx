import { getRouteApi, Link, useNavigate } from "@tanstack/react-router";
import {
  ArrowLeftIcon,
  FileArchiveIcon,
  FolderXIcon,
  ScanSearchIcon,
  ShieldAlertIcon,
} from "lucide-react";
import { NotImplemented } from "@/components/common/not-implemented";
import { PageHeader } from "@/components/common/page-header";
import { QueryError } from "@/components/common/query-error";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { paths } from "@/config/paths";
import { PROJECT_TABS, type ProjectTab } from "@/app/routes/projects/search";
import { useProject } from "@/features/projects/api/get-project";
import { ProjectDetails } from "@/features/projects/components/project-details";
import { isApiError } from "@/lib/api-client";

const route = getRouteApi("/projects/$projectId");

const TAB_LABELS: Record<ProjectTab, string> = {
  overview: "Tổng quan",
  sources: "Mã nguồn",
  scans: "Lượt quét",
  findings: "Cảnh báo",
};

function ProjectSkeleton() {
  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-4 w-96 max-w-full" />
      </div>
      <Skeleton className="h-9 w-80" />
      <Skeleton className="h-64 w-full" />
    </div>
  );
}

function ProjectNotFound() {
  return (
    <Empty className="flex-none border border-dashed py-12">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <FolderXIcon />
        </EmptyMedia>
        <EmptyTitle>Không tìm thấy dự án</EmptyTitle>
        <EmptyDescription>
          Dự án này không tồn tại hoặc đường dẫn không đúng.
        </EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <Button variant="outline" asChild>
          <Link to={paths.projects.path} search={{ page: 1 }}>
            <ArrowLeftIcon data-icon="inline-start" />
            Danh sách dự án
          </Link>
        </Button>
      </EmptyContent>
    </Empty>
  );
}

function NextSteps() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Bước tiếp theo</CardTitle>
        <CardDescription>Các bước sẽ mở khi backend hỗ trợ.</CardDescription>
      </CardHeader>
      <CardContent>
        <ol className="list-decimal space-y-2 pl-5 text-sm text-muted-foreground">
          <li>Nạp một bản mã nguồn bất biến (manifest hoặc ZIP).</li>
          <li>Chạy Semgrep, sau đó CodeQL trên cùng bản mã nguồn.</li>
          <li>Thẩm định từng cảnh báo Semgrep theo chính sách bằng chứng.</li>
        </ol>
      </CardContent>
    </Card>
  );
}

export function ProjectRoute() {
  const { projectId } = route.useParams();
  const { tab } = route.useSearch();
  const navigate = useNavigate();
  const project = useProject({ projectId });

  if (project.isPending) return <ProjectSkeleton />;
  if (project.isError) {
    if (isApiError(project.error, 404)) return <ProjectNotFound />;
    return (
      <QueryError
        error={project.error}
        onRetry={() => void project.refetch()}
        retrying={project.isFetching}
      />
    );
  }

  const data = project.data;

  return (
    <>
      <PageHeader
        title={data.name}
        description={data.description || undefined}
      />
      <Tabs
        value={tab}
        onValueChange={(value) =>
          void navigate({
            to: paths.project.path,
            params: { projectId },
            search: { tab: value as ProjectTab },
            replace: true,
          })
        }
      >
        <TabsList variant="line">
          {PROJECT_TABS.map((value) => (
            <TabsTrigger key={value} value={value}>
              {TAB_LABELS[value]}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="overview" className="pt-4">
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <ProjectDetails project={data} />
            </div>
            <NextSteps />
          </div>
        </TabsContent>
        <TabsContent value="sources" className="pt-4">
          <NotImplemented
            icon={FileArchiveIcon}
            title="Bản mã nguồn"
            description="Chưa thể nạp mã nguồn cho dự án. Mỗi bản sẽ là một snapshot bất biến, có hash và nguồn gốc rõ ràng."
            planned={[
              "Nạp từ manifest có phiên bản/commit cố định (đầu vào chính cho thực nghiệm).",
              "Chọn thư mục, xem và lọc file, tự đóng gói ZIP rồi upload (bản demo).",
              "Kiểm tra kích thước, số file, path traversal và symlink trước khi giải nén.",
            ]}
          />
        </TabsContent>
        <TabsContent value="scans" className="pt-4">
          <NotImplemented
            icon={ScanSearchIcon}
            title="Lượt quét"
            description="Chưa có API tạo lượt quét. Lượt quét sẽ chạy trong worker, không chạy trực tiếp trong API."
            planned={[
              "Semgrep trước, CodeQL sau, trên cùng một bản mã nguồn.",
              "Lưu SARIF thô, log, phiên bản công cụ/rule và các lỗi từng phần.",
            ]}
          />
        </TabsContent>
        <TabsContent value="findings" className="pt-4">
          <NotImplemented
            icon={ShieldAlertIcon}
            title="Cảnh báo"
            description="Chưa có cảnh báo vì chưa chạy công cụ nào. Không có dữ liệu mẫu hay kết quả giả."
            planned={[
              "Chuẩn hóa vị trí theo đúng bản mã nguồn đã quét.",
              "Tách riêng: sự đồng thuận giữa công cụ, quyết định thẩm định và nhãn đánh giá độc lập.",
            ]}
          />
        </TabsContent>
      </Tabs>
    </>
  );
}
