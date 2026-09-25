import { useMutation, useQueryClient } from "@tanstack/react-query";
import { z } from "zod";
import { api } from "@/lib/api-client";
import type { MutationConfig } from "@/lib/react-query";
import type { Schemas } from "@/types/api";
import {
  PROJECT_DESCRIPTION_MAX,
  PROJECT_NAME_MAX,
  type Project,
} from "@/features/projects/types";
import { getProjectQueryOptions } from "@/features/projects/api/get-project";

// Mirrors backend ProjectCreate: whitespace is stripped before the length checks.
export const createProjectInputSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, { error: "Nhập tên dự án." })
    .max(PROJECT_NAME_MAX, { error: `Tên tối đa ${PROJECT_NAME_MAX} ký tự.` }),
  description: z
    .string()
    .trim()
    .max(PROJECT_DESCRIPTION_MAX, {
      error: `Mô tả tối đa ${PROJECT_DESCRIPTION_MAX} ký tự.`,
    }),
});

export type CreateProjectInput = z.infer<typeof createProjectInputSchema>;

export function createProject(input: CreateProjectInput): Promise<Project> {
  const body: Schemas["ProjectCreate"] = {
    name: input.name,
    description: input.description || null,
  };
  return api.post<Project>("/projects", body);
}

export function useCreateProject({
  mutationConfig,
}: { mutationConfig?: MutationConfig<typeof createProject> } = {}) {
  const queryClient = useQueryClient();
  const { onSuccess, ...restConfig } = mutationConfig ?? {};
  return useMutation({
    ...restConfig,
    mutationFn: createProject,
    onSuccess: async (project, ...args) => {
      queryClient.setQueryData(
        getProjectQueryOptions(project.id).queryKey,
        project,
      );
      await queryClient.invalidateQueries({ queryKey: ["projects", "list"] });
      await onSuccess?.(project, ...args);
    },
  });
}
