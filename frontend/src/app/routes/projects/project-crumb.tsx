import { getRouteApi } from "@tanstack/react-router";
import { useProject } from "@/features/projects/api/get-project";

const route = getRouteApi("/projects/$projectId");

/** Breadcrumb label; shares the detail query cache with the page. */
export function ProjectCrumb() {
  const { projectId } = route.useParams();
  const project = useProject({ projectId });
  if (project.data) return project.data.name;
  return project.isPending ? "Đang tải…" : "Không tìm thấy";
}
