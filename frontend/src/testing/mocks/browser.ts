import { setupWorker } from "msw/browser";
import { makeProject, db } from "@/testing/mocks/db";
import { handlers } from "@/testing/mocks/handlers";

/** Start the in-browser mock API (VITE_APP_ENABLE_API_MOCKING=true), seeded with sample projects. */
export async function startMockApi() {
  db.projects = [
    makeProject({
      name: "Dữ liệu mock: Python command injection",
      description: "Sinh bởi MSW; không phải dữ liệu từ backend.",
    }),
  ];
  await setupWorker(...handlers).start({ onUnhandledRequest: "bypass" });
}
