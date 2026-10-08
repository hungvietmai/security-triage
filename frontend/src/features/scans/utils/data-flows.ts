import type { Finding } from "@/features/scans/types";

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function message(value: unknown) {
  if (typeof value === "string") return value;
  const text = record(value).text ?? record(value).markdown;
  return typeof text === "string" ? text : "Không có mô tả bước";
}

// SARIF is arbitrary JSON in the API: validate each level before reading it.
export function getDataFlows(rawResult: Finding["raw_result"]) {
  return array(rawResult.codeFlows)
    .flatMap((flow) =>
      array(record(flow).threadFlows).map((thread) =>
        array(record(thread).locations).map((step) => {
          const location = record(record(step).location);
          const physical = record(location.physicalLocation);
          const uri = record(physical.artifactLocation).uri;
          const line = record(physical.region).startLine;
          return `${typeof uri === "string" ? uri : "Không rõ file"}:${typeof line === "number" ? line : "—"} – ${message(location.message)}`;
        }),
      ),
    )
    .filter((thread) => thread.length > 0);
}
