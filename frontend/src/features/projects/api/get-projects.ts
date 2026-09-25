import {
  keepPreviousData,
  queryOptions,
  useQuery,
} from "@tanstack/react-query";
import { api } from "@/lib/api-client";
import type { QueryConfig } from "@/lib/react-query";
import {
  PROJECTS_PAGE_SIZE,
  type ProjectPage,
} from "@/features/projects/types";

interface GetProjectsParams {
  /** 1-based, matching the `?page=` search param. */
  page: number;
  pageSize?: number;
}

export function getProjects(
  { page, pageSize = PROJECTS_PAGE_SIZE }: GetProjectsParams,
  signal?: AbortSignal,
): Promise<ProjectPage> {
  return api.get<ProjectPage>("/projects", {
    params: { limit: pageSize, offset: (page - 1) * pageSize },
    signal,
  });
}

export function getProjectsQueryOptions({
  page,
  pageSize = PROJECTS_PAGE_SIZE,
}: GetProjectsParams) {
  return queryOptions({
    queryKey: ["projects", "list", { page, pageSize }],
    queryFn: ({ signal }) => getProjects({ page, pageSize }, signal),
    placeholderData: keepPreviousData,
  });
}

export function useProjects({
  queryConfig,
  ...params
}: GetProjectsParams & {
  queryConfig?: QueryConfig<typeof getProjectsQueryOptions>;
}) {
  return useQuery({ ...getProjectsQueryOptions(params), ...queryConfig });
}
