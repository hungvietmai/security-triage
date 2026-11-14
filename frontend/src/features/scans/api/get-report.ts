import { queryOptions, useQuery } from "@tanstack/react-query";
import { env } from "@/config/env";
import type { ScanReport } from "@/features/scans/types";
import { api } from "@/lib/api-client";
import type { QueryConfig } from "@/lib/react-query";

export function getReport(scanId: string, signal?: AbortSignal) {
  return api.get<ScanReport>(`/scans/${encodeURIComponent(scanId)}/report`, {
    signal,
  });
}

/** Merged SARIF of every original alert; filtered candidates carry a suppression. */
export function getSarifUrl(scanId: string) {
  return `${env.API_URL}/scans/${encodeURIComponent(scanId)}/report.sarif`;
}

export function getReportQueryOptions(scanId: string) {
  return queryOptions({
    queryKey: ["scans", "detail", scanId, "report"],
    queryFn: ({ signal }) => getReport(scanId, signal),
  });
}

export function useReport({
  scanId,
  queryConfig,
}: {
  scanId: string;
  queryConfig?: QueryConfig<typeof getReportQueryOptions>;
}) {
  return useQuery({ ...getReportQueryOptions(scanId), ...queryConfig });
}
