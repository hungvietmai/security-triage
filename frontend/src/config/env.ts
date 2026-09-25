import { z } from "zod";

const envSchema = z.object({
  /** API prefix; the dev server and Nginx proxy it to FastAPI. */
  API_URL: z.string().default("/api/v1"),
  /** Swagger UI served by FastAPI. */
  API_DOCS_URL: z.string().default("/api/docs"),
  /** Development only: answer API calls in the browser with MSW mocks. */
  ENABLE_API_MOCKING: z
    .enum(["true", "false"])
    .default("false")
    .transform((value) => value === "true"),
});

function readEnv() {
  // Only VITE_-prefixed variables reach the bundle; strip the prefix.
  const values = Object.fromEntries(
    Object.entries(import.meta.env)
      .filter(([key]) => key.startsWith("VITE_APP_"))
      .map(([key, value]) => [key.replace("VITE_APP_", ""), value]),
  );
  const parsed = envSchema.safeParse(values);
  if (!parsed.success) {
    throw new Error(
      `Invalid VITE_APP_* environment variables:\n${z.prettifyError(parsed.error)}`,
    );
  }
  return parsed.data;
}

export const env = readEnv();
