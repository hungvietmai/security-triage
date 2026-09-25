import { Link } from "@tanstack/react-router";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { paths } from "@/config/paths";
import type { Project } from "@/features/projects/types";
import { formatDateTime, formatRelative, shortId } from "@/utils/format";

function SkeletonRow() {
  return (
    <TableRow>
      <TableCell>
        <Skeleton className="h-4 w-40" />
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <Skeleton className="h-4 w-64" />
      </TableCell>
      <TableCell className="hidden sm:table-cell">
        <Skeleton className="h-4 w-16" />
      </TableCell>
      <TableCell>
        <Skeleton className="ml-auto h-4 w-20" />
      </TableCell>
    </TableRow>
  );
}

function ProjectRow({ project }: { project: Project }) {
  return (
    <TableRow>
      <TableCell className="max-w-0 font-medium">
        <Link
          to={paths.project.path}
          params={{ projectId: project.id }}
          className="block truncate hover:underline"
        >
          {project.name}
        </Link>
      </TableCell>
      <TableCell className="hidden max-w-0 truncate text-muted-foreground md:table-cell">
        {project.description || "—"}
      </TableCell>
      <TableCell className="hidden font-mono text-xs text-muted-foreground sm:table-cell">
        {shortId(project.id)}
      </TableCell>
      <TableCell className="text-right text-muted-foreground">
        <Tooltip>
          <TooltipTrigger asChild>
            <time dateTime={project.created_at}>
              {formatRelative(project.created_at)}
            </time>
          </TooltipTrigger>
          <TooltipContent>{formatDateTime(project.created_at)}</TooltipContent>
        </Tooltip>
      </TableCell>
    </TableRow>
  );
}

export function ProjectsTable({
  projects,
  loading = false,
}: {
  projects: Project[];
  loading?: boolean;
}) {
  return (
    <Table className="[&_td:first-child]:pl-4 [&_td:last-child]:pr-4 [&_th:first-child]:pl-4 [&_th:last-child]:pr-4">
      <TableHeader>
        <TableRow>
          <TableHead className="md:w-[40%]">Tên dự án</TableHead>
          <TableHead className="hidden md:table-cell">Mô tả</TableHead>
          <TableHead className="hidden w-28 sm:table-cell">Mã</TableHead>
          <TableHead className="w-36 text-right">Ngày tạo</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {loading
          ? Array.from({ length: 5 }, (_, index) => <SkeletonRow key={index} />)
          : projects.map((project) => (
              <ProjectRow key={project.id} project={project} />
            ))}
      </TableBody>
    </Table>
  );
}
