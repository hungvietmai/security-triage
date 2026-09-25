import type { Schemas } from "@/types/api";

export type Project = Schemas["ProjectRead"];
export type ProjectPage = Schemas["ProjectPage"];

/** Mirrors backend ProjectCreate limits. */
export const PROJECT_NAME_MAX = 120;
export const PROJECT_DESCRIPTION_MAX = 4000;

export const PROJECTS_PAGE_SIZE = 12;
