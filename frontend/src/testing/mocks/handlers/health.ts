import { http, HttpResponse } from "msw";
import { env } from "@/config/env";
import type { Schemas } from "@/types/api";

export const readyResponse: Schemas["Readiness"] = {
  status: "ok",
  checks: { postgres: "ok", redis: "ok", storage: "ok" },
};

export const healthHandlers = [
  http.get(`${env.API_URL}/health/ready`, () =>
    HttpResponse.json(readyResponse),
  ),
  http.get(`${env.API_URL}/health/live`, () =>
    HttpResponse.json({ status: "ok" } satisfies Schemas["Liveness"]),
  ),
];
