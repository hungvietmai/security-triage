import type {
  DisplayState,
  Readiness,
  ServiceKey,
} from "@/features/health/types";

export function serviceState(
  readiness: Readiness | undefined,
  key: ServiceKey,
  { pending, failed }: { pending: boolean; failed: boolean },
): DisplayState {
  if (pending) return "checking";
  if (failed || !readiness) return "unknown";
  return readiness.checks[key];
}

export function overallState(
  readiness: Readiness | undefined,
  { pending, failed }: { pending: boolean; failed: boolean },
): DisplayState {
  if (pending) return "checking";
  if (failed || !readiness) return "unavailable";
  return readiness.status === "ok" ? "ok" : "unavailable";
}
