import { queryOptions, useQuery } from "@tanstack/react-query";
import {
  UNITS_PAGE_SIZE,
  type UnitsQuery,
  type UnitPage,
} from "@/features/scans/types";
import { api } from "@/lib/api-client";
import type { QueryConfig } from "@/lib/react-query";

export function getUnits(
  scanId: string,
  params: UnitsQuery = {},
  signal?: AbortSignal,
) {
  return api.get<UnitPage>(`/scans/${encodeURIComponent(scanId)}/units`, {
    params: {
      ...params,
      limit: params.limit ?? UNITS_PAGE_SIZE,
      tier: params.tier ?? undefined,
      tool: params.tool ?? undefined,
    },
    signal,
  });
}

export function getUnitsQueryOptions(scanId: string, params: UnitsQuery = {}) {
  return queryOptions({
    queryKey: ["scans", "list", scanId, params],
    queryFn: ({ signal }) => getUnits(scanId, params, signal),
  });
}

export function useUnits({
  scanId,
  params,
  queryConfig,
}: {
  scanId: string;
  params?: UnitsQuery;
  queryConfig?: QueryConfig<typeof getUnitsQueryOptions>;
}) {
  return useQuery({ ...getUnitsQueryOptions(scanId, params), ...queryConfig });
}
