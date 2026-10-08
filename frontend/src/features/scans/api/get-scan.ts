import { queryOptions, useQuery } from "@tanstack/react-query";
import {
  isScanActive,
  SCAN_POLL_INTERVAL,
  type Scan,
} from "@/features/scans/types";
import { api } from "@/lib/api-client";
import type { QueryConfig } from "@/lib/react-query";

export function getScan(scanId: string, signal?: AbortSignal) {
  return api.get<Scan>(`/scans/${encodeURIComponent(scanId)}`, { signal });
}

export function getScanQueryOptions(scanId: string) {
  return queryOptions({
    queryKey: ["scans", "detail", scanId],
    queryFn: ({ signal }) => getScan(scanId, signal),
    refetchInterval: (query) =>
      query.state.data && isScanActive(query.state.data.status)
        ? SCAN_POLL_INTERVAL
        : false,
  });
}

export function useScan({
  scanId,
  queryConfig,
}: {
  scanId: string;
  queryConfig?: QueryConfig<typeof getScanQueryOptions>;
}) {
  return useQuery({ ...getScanQueryOptions(scanId), ...queryConfig });
}
