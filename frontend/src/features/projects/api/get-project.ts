import { queryOptions, useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api-client";
import type { QueryConfig } from "@/lib/react-query";
import type { Project } from "@/features/projects/types";

export function getProject(
  projectId: string,
  signal?: AbortSignal,
): Promise<Project> {
  return api.get<Project>(`/projects/${encodeURIComponent(projectId)}`, {
    signal,
  });
}

export function getProjectQueryOptions(projectId: string) {
  return queryOptions({
    queryKey: ["projects", "detail", projectId],
    queryFn: ({ signal }) => getProject(projectId, signal),
  });
}

export function useProject({
  projectId,
  queryConfig,
}: {
  projectId: string;
  queryConfig?: QueryConfig<typeof getProjectQueryOptions>;
}) {
  return useQuery({ ...getProjectQueryOptions(projectId), ...queryConfig });
}
