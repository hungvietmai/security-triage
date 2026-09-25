export interface Project {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
}
export interface ProjectPage {
  items: Project[];
  total: number;
  limit: number;
  offset: number;
}
export interface Readiness {
  status: string;
  checks: Record<string, string>;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/v1${path}`, {
    ...init,
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok)
    throw new Error(
      `Yêu cầu thất bại (${response.status}). Kiểm tra API và PostgreSQL.`,
    );
  return response.json() as Promise<T>;
}
export const api = {
  projects: (offset = 0) =>
    request<ProjectPage>(`/projects?limit=12&offset=${offset}`),
  createProject: (name: string, description: string) =>
    request<Project>("/projects", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, description: description.trim() || null }),
    }),
  readiness: async (): Promise<Readiness> => {
    const response = await fetch("/api/v1/health/ready", {
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok && response.status !== 503)
      throw new Error("Không kết nối được API.");
    return response.json() as Promise<Readiness>;
  },
};
