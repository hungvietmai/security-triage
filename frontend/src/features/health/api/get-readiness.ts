import { queryOptions, useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api-client";
import type { QueryConfig } from "@/lib/react-query";
import { HEALTH_REFRESH_MS, type Readiness } from "@/features/health/types";

// Readiness answers 503 with the same body when a dependency is down.
export function getReadiness(signal?: AbortSignal): Promise<Readiness> {
  return api.get<Readiness>("/health/ready", { signal, acceptStatus: [503] });
}

export function getReadinessQueryOptions() {
  return queryOptions({
    queryKey: ["health", "readiness"],
    queryFn: ({ signal }) => getReadiness(signal),
    refetchInterval: HEALTH_REFRESH_MS,
    staleTime: 5_000,
    retry: false,
  });
}

export function useReadiness({
  queryConfig,
}: { queryConfig?: QueryConfig<typeof getReadinessQueryOptions> } = {}) {
  return useQuery({ ...getReadinessQueryOptions(), ...queryConfig });
}
