import { getRouteApi, useNavigate } from "@tanstack/react-router";
import { PageHeader } from "@/components/common/page-header";
import { paths } from "@/config/paths";
import { CreateProjectDialog } from "@/features/projects/components/create-project-dialog";
import { ProjectsList } from "@/features/projects/components/projects-list";

const route = getRouteApi("/projects/");

export function ProjectsRoute() {
  const { page } = route.useSearch();
  const navigate = useNavigate();

  return (
    <>
      <PageHeader
        title="Dự án"
        description="Mỗi dự án gom các bản mã nguồn, lượt quét và kết quả thẩm định của một đối tượng đánh giá."
        actions={<CreateProjectDialog />}
      />
      <ProjectsList
        page={page}
        onPageChange={(next) =>
          void navigate({ to: paths.projects.path, search: { page: next } })
        }
      />
    </>
  );
}
