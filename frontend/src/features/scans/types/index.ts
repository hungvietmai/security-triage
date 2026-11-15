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
export type Family = NonNullable<Unit["analysis_family"]>;
export type EvidenceState = Unit["evidence_state"];
export type ScanFamily = Scan["families"][number];
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
  G4_JS_CONSTANT_COMMAND:
    "Semgrep chứng minh chuỗi lệnh của lời gọi JavaScript là hằng",
};
// Analysis families of a scan: one CWE each, or findings whose family could not be named.
export const FAMILIES = {
  "command-injection": "CWE-78 · Command injection",
  "path-traversal": "CWE-22 · Path traversal",
  "sql-injection": "CWE-89 · SQL injection",
  unassigned: "Chưa xác định nhóm",
} as const satisfies Record<Family, string>;
// What the evidence says about a unit. Separate from the scan's status and from the filter
// decision: only "refuted" ever moves a unit to the filtered list.
export const EVIDENCE_STATES = {
  refuted: "Bằng chứng bác bỏ cảnh báo",
  not_refuted: "Đã đối chiếu, bằng chứng không bác bỏ",
  insufficient: "Chưa đủ bằng chứng",
  unavailable: "Không lấy được bằng chứng",
  not_applicable: "Không áp dụng (chưa xác định nhóm)",
  not_assessed: "Lượt quét chưa có bước thẩm định",
} as const satisfies Record<EvidenceState, string>;
// Why a unit stays in the review list, by the code the backend records.
export const KEPT_REASONS: Record<string, string> = {
  run_incomplete: "Lượt quét chưa hoàn tất nên không gạn gì",
  no_refuting_evidence: "Không có bằng chứng cụ thể cho thấy cảnh báo sai",
  evidence_step_failed: "Bước chạy bằng chứng không hoàn tất",
  evidence_query_still_reports_flow: "Truy vấn bằng chứng vẫn báo luồng này",
  flow_rule_without_evidence_query:
    "Luồng do truy vấn chưa có truy vấn bằng chứng báo",
  evidence_baseline_does_not_report_this_alert:
    "Truy vấn đối chứng không báo cảnh báo này nên không đối chiếu được",
  independent_flow_claim: "Một công cụ khác vẫn khẳng định luồng dữ liệu",
  literal_proof_without_second_source:
    "Lệnh là hằng nhưng chưa có nguồn thứ hai xác nhận",
  reported_flow_avoids_the_dead_branch:
    "Có đường đi không qua nhánh không bao giờ chạy",
  flow_claim_without_a_trace_to_check:
    "Công cụ khác báo luồng nhưng không kèm đường đi để đối chiếu",
  family_not_ranked: "Nhóm phân tích chưa xếp hạng được cảnh báo này",
  no_filter_condition_for_family:
    "Nhóm này chỉ phát hiện và giữ: chưa có điều kiện gạn nào được đo",
  rule_not_claimed: "Không thành viên nào của lượt quét khai rule này",
  definition_unverified: "Không xác định được một định nghĩa rule đã ghim",
  ambiguous_family: "Nhiều hơn một nhóm phân tích khai rule này",
};
export const UNITS_PAGE_SIZE = 20;
export const SCAN_POLL_INTERVAL = 3_000;

export function isScanActive(status: Scan["status"]) {
  return status === "queued" || status === "running";
}
