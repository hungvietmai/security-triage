import { Link } from "@tanstack/react-router";
import { QueryError } from "@/components/common/query-error";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyTitle,
} from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { paths } from "@/config/paths";
import { useProjects } from "@/features/projects/api/get-projects";
import { CreateProjectDialog } from "@/features/projects/components/create-project-dialog";
import { formatRelative } from "@/utils/format";

const RECENT_PROJECTS_COUNT = 5;

/** The newest projects; shares the first page's cache with the projects list. */
export function RecentProjects() {
  const projects = useProjects({ page: 1 });

  if (projects.isError) {
    return (
      <QueryError
        error={projects.error}
        onRetry={() => void projects.refetch()}
        retrying={projects.isFetching}
      />
    );
  }

  if (projects.isPending) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }, (_, index) => (
          <Skeleton key={index} className="h-10 w-full" />
        ))}
      </div>
    );
  }

  const recent = projects.data.items.slice(0, RECENT_PROJECTS_COUNT);
  if (recent.length === 0) {
    return (
      <Empty className="py-8">
        <EmptyHeader>
          <EmptyTitle>Chưa có dự án</EmptyTitle>
          <EmptyDescription>
            Tạo dự án đầu tiên để bắt đầu quy trình thẩm định.
          </EmptyDescription>
        </EmptyHeader>
        <EmptyContent>
          <CreateProjectDialog />
        </EmptyContent>
      </Empty>
    );
  }

  return (
    <ul className="divide-y">
      {recent.map((project) => (
        <li key={project.id}>
          <Link
            to={paths.project.path}
            params={{ projectId: project.id }}
            className="-mx-2 flex items-center justify-between gap-4 rounded-md px-2 py-2.5 hover:bg-muted/60"
          >
            <div className="min-w-0">
              <div className="truncate text-sm font-medium">{project.name}</div>
              <div className="truncate text-xs text-muted-foreground">
                {project.description || "Chưa có mô tả"}
              </div>
            </div>
            <time
              dateTime={project.created_at}
              className="shrink-0 text-xs text-muted-foreground"
            >
              {formatRelative(project.created_at)}
            </time>
          </Link>
        </li>
      ))}
    </ul>
  );
}
