import { defineConfig, mergeConfig } from "vitest/config";
import { fileURLToPath, URL } from "node:url";
import viteConfig from "./vite.config.ts";

export default mergeConfig(
  viteConfig,
  defineConfig({
    resolve: {
      alias: { "@test": fileURLToPath(new URL("./tests", import.meta.url)) },
    },
    test: {
      environment: "jsdom",
      // Gives relative "/api/..." fetches a base URL, as in the browser.
      environmentOptions: { jsdom: { url: "http://localhost/" } },
      setupFiles: ["./tests/setup-tests.ts"],
      include: ["tests/**/*.test.{ts,tsx}"],
      restoreMocks: true,
    },
  }),
);
