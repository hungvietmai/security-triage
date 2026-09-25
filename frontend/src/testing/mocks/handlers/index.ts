import { healthHandlers } from "@/testing/mocks/handlers/health";
import { projectsHandlers } from "@/testing/mocks/handlers/projects";

export const handlers = [...projectsHandlers, ...healthHandlers];
