import { queryOptions, useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api-client";
import type { QueryConfig } from "@/lib/react-query";
import { HEALTH_REFRESH_MS, type Liveness } from "@/features/health/types";

export function getLiveness(signal?: AbortSignal): Promise<Liveness> {
  return api.get<Liveness>("/health/live", { signal });
}

export function getLivenessQueryOptions() {
  return queryOptions({
    queryKey: ["health", "liveness"],
    queryFn: ({ signal }) => getLiveness(signal),
    refetchInterval: HEALTH_REFRESH_MS,
    staleTime: 5_000,
    retry: false,
  });
}

export function useLiveness({
  queryConfig,
}: { queryConfig?: QueryConfig<typeof getLivenessQueryOptions> } = {}) {
  return useQuery({ ...getLivenessQueryOptions(), ...queryConfig });
}
