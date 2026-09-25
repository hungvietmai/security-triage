import { z } from "zod";

export const PROJECT_TABS = [
  "overview",
  "sources",
  "scans",
  "findings",
] as const;

export type ProjectTab = (typeof PROJECT_TABS)[number];

// Invalid values fall back to defaults instead of erroring.
export const projectsSearchSchema = z.object({
  page: z.number().int().min(1).default(1).catch(1),
});

export const projectSearchSchema = z.object({
  tab: z.enum(PROJECT_TABS).default("overview").catch("overview"),
});
