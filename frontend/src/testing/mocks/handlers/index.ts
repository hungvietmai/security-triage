import { healthHandlers } from "@/testing/mocks/handlers/health";
import { projectsHandlers } from "@/testing/mocks/handlers/projects";
import { scansHandlers } from "@/testing/mocks/handlers/scans";

export const handlers = [
  ...projectsHandlers,
  ...healthHandlers,
  ...scansHandlers,
];
