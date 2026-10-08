import { queryOptions, useQuery } from "@tanstack/react-query";
import type { UnitDetail } from "@/features/scans/types";
import { api } from "@/lib/api-client";
import type { QueryConfig } from "@/lib/react-query";

export function getUnit(scanId: string, unitId: string, signal?: AbortSignal) {
  return api.get<UnitDetail>(
    `/scans/${encodeURIComponent(scanId)}/units/${encodeURIComponent(unitId)}`,
    { signal },
  );
}

export function getUnitQueryOptions(scanId: string, unitId: string) {
  return queryOptions({
    queryKey: ["scans", "detail", scanId, "unit", unitId],
    queryFn: ({ signal }) => getUnit(scanId, unitId, signal),
  });
}

export function useUnit({
  scanId,
  unitId,
  queryConfig,
}: {
  scanId: string;
  unitId: string;
  queryConfig?: QueryConfig<typeof getUnitQueryOptions>;
}) {
  return useQuery({ ...getUnitQueryOptions(scanId, unitId), ...queryConfig });
}
