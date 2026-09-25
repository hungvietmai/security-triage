import type { ReactNode } from "react";
import { CopyButton } from "@/components/common/copy-button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { Project } from "@/features/projects/types";
import { formatDateTime, formatRelative } from "@/utils/format";

function DetailRow({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="grid gap-1 py-3 sm:grid-cols-3 sm:gap-4">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-sm sm:col-span-2">{children}</dd>
    </div>
  );
}

export function ProjectDetails({ project }: { project: Project }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Thông tin dự án</CardTitle>
      </CardHeader>
      <CardContent>
        <dl className="divide-y">
          <DetailRow label="Tên">{project.name}</DetailRow>
          <DetailRow label="Mô tả">
            {project.description ? (
              <p className="whitespace-pre-wrap">{project.description}</p>
            ) : (
              <span className="text-muted-foreground">Chưa có mô tả</span>
            )}
          </DetailRow>
          <DetailRow label="Mã dự án">
            <span className="inline-flex max-w-full items-center gap-1">
              <code className="truncate font-mono text-xs">{project.id}</code>
              <CopyButton value={project.id} label="Sao chép mã dự án" />
            </span>
          </DetailRow>
          <DetailRow label="Ngày tạo">
            {formatDateTime(project.created_at)}{" "}
            <span className="text-muted-foreground">
              ({formatRelative(project.created_at)})
            </span>
          </DetailRow>
        </dl>
      </CardContent>
    </Card>
  );
}
