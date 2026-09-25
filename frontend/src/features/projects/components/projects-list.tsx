import { Link } from "@tanstack/react-router";
import { FolderKanbanIcon } from "lucide-react";
import { PaginationBar } from "@/components/common/pagination-bar";
import { QueryError } from "@/components/common/query-error";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import { paths } from "@/config/paths";
import { useProjects } from "@/features/projects/api/get-projects";
import { CreateProjectDialog } from "@/features/projects/components/create-project-dialog";
import { ProjectsTable } from "@/features/projects/components/projects-table";
import { PROJECTS_PAGE_SIZE } from "@/features/projects/types";

/** Paginated project table with its empty, out-of-range and error states. */
export function ProjectsList({
  page,
  onPageChange,
}: {
  page: number;
  onPageChange: (page: number) => void;
}) {
  const projects = useProjects({ page });
  const data = projects.data;

  if (projects.isError) {
    return (
      <QueryError
        error={projects.error}
        onRetry={() => void projects.refetch()}
        retrying={projects.isFetching}
      />
    );
  }

  if (data?.total === 0) {
    return (
      <Empty className="flex-none border border-dashed py-12">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <FolderKanbanIcon />
          </EmptyMedia>
          <EmptyTitle>Chưa có dự án</EmptyTitle>
          <EmptyDescription>
            Đặt tên và mô tả phạm vi mã nguồn cần đánh giá để bắt đầu.
          </EmptyDescription>
        </EmptyHeader>
        <EmptyContent>
          <CreateProjectDialog />
        </EmptyContent>
      </Empty>
    );
  }

  if (data && data.items.length === 0) {
    return (
      <Empty className="flex-none border border-dashed py-12">
        <EmptyHeader>
          <EmptyTitle>Trang {page} không có dự án</EmptyTitle>
          <EmptyDescription>
            Danh sách chỉ có {data.total} dự án.
          </EmptyDescription>
        </EmptyHeader>
        <EmptyContent>
          <Button variant="outline" asChild>
            <Link to={paths.projects.path} search={{ page: 1 }}>
              Về trang đầu
            </Link>
          </Button>
        </EmptyContent>
      </Empty>
    );
  }

  return (
    <Card className="py-0">
      <CardContent className="px-0" aria-busy={projects.isFetching}>
        <ProjectsTable
          projects={data?.items ?? []}
          loading={projects.isPending}
        />
      </CardContent>
      {data && (
        <CardFooter className="border-t py-3">
          <PaginationBar
            page={page}
            pageSize={PROJECTS_PAGE_SIZE}
            total={data.total}
            disabled={projects.isFetching}
            onPageChange={onPageChange}
          />
        </CardFooter>
      )}
    </Card>
  );
}
