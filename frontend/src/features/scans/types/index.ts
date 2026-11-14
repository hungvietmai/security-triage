import type { operations } from "@/types/api-schema";
import type { Schemas } from "@/types/api";

export type Scan = Schemas["ScanRead"];
export type ScanCreate = Schemas["ScanCreate"];
export type ScanAccepted = Schemas["ScanAccepted"];
export type Unit = Schemas["UnitSummary"];
export type UnitDetail = Schemas["UnitDetail"];
export type UnitPage = Schemas["UnitPage"];
export type Finding = Schemas["FindingRead"];
export type ScanReport = Schemas["ScanReport"];
export type Disposition = Unit["disposition"];
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
// Tools of the screening step, with their display names; CodeQL is the adjudication step.
export const SCREENING_TOOLS = {
  semgrep: "Semgrep",
  bandit: "Bandit",
  eslint: "ESLint",
} as const satisfies Partial<Record<Tool, string>>;
export const TOOLS = [
  "semgrep",
  "bandit",
  "eslint",
  "codeql",
] as const satisfies readonly Tool[];
// The main review list, and candidates a tool proved false (kept, shown separately).
export const DISPOSITIONS = {
  review: "Danh sách rà chính",
  filtered: "Đã gạn",
} as const satisfies Record<Disposition, string>;
export const FILTER_RULES: Record<string, string> = {
  G3_SEMGREP_DEAD_BRANCH:
    "Semgrep chứng minh luồng chỉ đi qua nhánh không bao giờ chạy",
  G1_CODEQL_SAFETY_EVIDENCE: "Bằng chứng an toàn của CodeQL loại hết luồng",
  G2_LITERAL_COMMAND: "Lệnh là hằng (hệ thống và Bandit cùng xác nhận)",
};
export const UNITS_PAGE_SIZE = 20;
export const SCAN_POLL_INTERVAL = 3_000;

export function isScanActive(status: Scan["status"]) {
  return status === "queued" || status === "running";
}
