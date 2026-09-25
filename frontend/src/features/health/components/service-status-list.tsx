import { QueryError } from "@/components/common/query-error";
import { useReadiness } from "@/features/health/api/get-readiness";
import { StatusLabel } from "@/features/health/components/status-label";
import { SERVICES } from "@/features/health/types";
import { serviceState } from "@/features/health/utils/service-state";

/** Compact list of dependency states, e.g. for the dashboard card. */
export function ServiceStatusList() {
  const readiness = useReadiness();

  if (readiness.isError) {
    return (
      <QueryError error={readiness.error} title="Không kết nối được API" />
    );
  }

  return (
    <ul className="divide-y">
      {SERVICES.map((service) => (
        <li
          key={service.key}
          className="flex items-center justify-between gap-4 py-2.5 text-sm"
        >
          <div className="min-w-0">
            <div className="font-medium">{service.label}</div>
            <div className="truncate text-xs text-muted-foreground">
              {service.role}
            </div>
          </div>
          <span className="shrink-0 text-muted-foreground">
            <StatusLabel
              state={serviceState(readiness.data, service.key, {
                pending: readiness.isPending,
                failed: false,
              })}
            />
          </span>
        </li>
      ))}
    </ul>
  );
}
