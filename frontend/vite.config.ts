import { fileURLToPath, URL } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

/** Matches modules of the given packages; Vite module ids always use "/". */
const vendor = (packages: string) => new RegExp(`/node_modules/(${packages})/`);

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  build: {
    rolldownOptions: {
      output: {
        // Long-lived vendor chunks; pages are split per route in app/router.tsx.
        codeSplitting: {
          groups: [
            { name: "react", test: vendor("react|react-dom|scheduler") },
            { name: "tanstack", test: vendor("@tanstack/[^/]+") },
            {
              name: "forms",
              test: vendor("zod|react-hook-form|@hookform/[^/]+"),
            },
            {
              name: "ui",
              test: vendor(
                "radix-ui|@radix-ui/[^/]+|@floating-ui/[^/]+|sonner|lucide-react|cn",
              ),
            },
          ],
        },
      },
    },
  },
  server: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: process.env.API_PROXY_TARGET ?? "http://localhost:8000",
      },
    },
  },
});
