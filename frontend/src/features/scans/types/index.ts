import type { operations } from "@/types/api-schema";
import type { Schemas } from "@/types/api";

export type Scan = Schemas["ScanRead"];
export type ScanCreate = Schemas["ScanCreate"];
export type ScanAccepted = Schemas["ScanAccepted"];
export type Unit = Schemas["UnitSummary"];
export type UnitDetail = Schemas["UnitDetail"];
export type UnitPage = Schemas["UnitPage"];
export type Finding = Schemas["FindingRead"];
export type Tier = Unit["priority"];
export type UnitsQuery = NonNullable<
  operations["list_units_api_v1_scans__scan_id__units_get"]["parameters"]["query"]
>;
export type Tool = NonNullable<UnitsQuery["tool"]>;
export const TIERS = [
  "P1",
  "P2",
  "U",
  "P3",
  "P4",
] as const satisfies readonly Tier[];
export const TOOLS = ["semgrep", "codeql"] as const satisfies readonly Tool[];
export const UNITS_PAGE_SIZE = 20;
export const SCAN_POLL_INTERVAL = 3_000;

export function isScanActive(status: Scan["status"]) {
  return status === "queued" || status === "running";
}
