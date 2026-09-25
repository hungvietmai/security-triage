import { defineConfig, mergeConfig } from "vitest/config";
import viteConfig from "./vite.config.ts";

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: "jsdom",
      // Gives relative "/api/..." fetches a base URL, as in the browser.
      environmentOptions: { jsdom: { url: "http://localhost/" } },
      setupFiles: ["./src/testing/setup-tests.ts"],
      include: ["src/**/*.test.{ts,tsx}"],
      restoreMocks: true,
    },
  }),
);
