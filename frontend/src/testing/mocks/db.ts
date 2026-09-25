import type { Schemas } from "@/types/api";

type Project = Schemas["ProjectRead"];

/** In-memory backend state shared by the MSW handlers; reset before each test. */
export const db = { projects: [] as Project[] };

let sequence = 0;

export function resetDb() {
  sequence = 0;
  db.projects = [];
}

export function makeProject(overrides: Partial<Project> = {}): Project {
  sequence += 1;
  return {
    id: `00000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`,
    name: `Dự án ${sequence}`,
    description: null,
    created_at: new Date(Date.now() - sequence * 60_000).toISOString(),
    ...overrides,
  };
}
