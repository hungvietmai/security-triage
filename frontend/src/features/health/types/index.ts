import type { Schemas } from "@/types/api";

export type Readiness = Schemas["Readiness"];
export type Liveness = Schemas["Liveness"];
export type ServiceKey = keyof Readiness["checks"];
export type ServiceState = Readiness["checks"][ServiceKey];

/** What the UI shows: the API's answer, or why there is none yet. */
export type DisplayState = ServiceState | "checking" | "unknown";

export const SERVICES: { key: ServiceKey; label: string; role: string }[] = [
  {
    key: "postgres",
    label: "PostgreSQL",
    role: "Metadata, cảnh báo, trạng thái",
  },
  { key: "redis", label: "Redis", role: "Hàng đợi tác vụ Celery" },
  { key: "storage", label: "SeaweedFS S3", role: "Mã nguồn, SARIF, log" },
];

export const HEALTH_REFRESH_MS = 15_000;
