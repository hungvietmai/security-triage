import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "@/app";
import { env } from "@/config/env";
import "@/index.css";

async function enableMocking() {
  // Tree-shaken from production builds: import.meta.env.DEV is false there.
  if (!import.meta.env.DEV || !env.ENABLE_API_MOCKING) return;
  const { startMockApi } = await import("@/testing/mocks/browser");
  await startMockApi();
}

void enableMocking().then(() => {
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
});
