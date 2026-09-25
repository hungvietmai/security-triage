import {
  DatabaseIcon,
  HardDriveIcon,
  ListTodoIcon,
  RotateCwIcon,
  ServerIcon,
  type LucideIcon,
} from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useLiveness } from "@/features/health/api/get-liveness";
import { useReadiness } from "@/features/health/api/get-readiness";
import { StatusLabel } from "@/features/health/components/status-label";
import {
  SERVICES,
  type DisplayState,
  type ServiceKey,
} from "@/features/health/types";
import { serviceState } from "@/features/health/utils/service-state";
import { formatDateTime } from "@/utils/format";

const ICONS: Record<ServiceKey, LucideIcon> = {
  postgres: DatabaseIcon,
  redis: ListTodoIcon,
  storage: HardDriveIcon,
};

function ServiceCard({
  icon: Icon,
  title,
  description,
  state,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
  state: DisplayState;
}) {
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Icon className="size-4 text-muted-foreground" />
          {title}
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="text-sm">
        <StatusLabel state={state} />
      </CardContent>
    </Card>
  );
}

export function RefreshHealthButton() {
  const readiness = useReadiness();
  const liveness = useLiveness();
  const refreshing = readiness.isFetching || liveness.isFetching;

  return (
    <Button
      variant="outline"
      disabled={refreshing}
      onClick={() => {
        void readiness.refetch();
        void liveness.refetch();
      }}
    >
      <RotateCwIcon
        data-icon="inline-start"
        className={refreshing ? "animate-spin" : undefined}
      />
      Kiểm tra lại
    </Button>
  );
}

/** Per-service status cards plus a banner when anything is down. */
export function HealthOverview() {
  const readiness = useReadiness();
  const liveness = useLiveness();
  const apiState: DisplayState = liveness.isPending
    ? "checking"
    : liveness.isSuccess
      ? "ok"
      : "unavailable";

  return (
    <>
      {readiness.isError ? (
        <Alert variant="destructive">
          <AlertTitle>Không kết nối được API</AlertTitle>
          <AlertDescription>{readiness.error.message}</AlertDescription>
        </Alert>
      ) : readiness.data?.status === "degraded" ? (
        <Alert variant="destructive">
          <AlertTitle>Một số dịch vụ không khả dụng</AlertTitle>
          <AlertDescription>
            API vẫn chạy nhưng các thao tác cần dịch vụ bị lỗi sẽ thất bại. Xem
            log bằng <code>docker compose logs -f api</code>.
          </AlertDescription>
        </Alert>
      ) : null}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <ServiceCard
          icon={ServerIcon}
          title="API"
          description="FastAPI, liveness"
          state={apiState}
        />
        {SERVICES.map((service) => (
          <ServiceCard
            key={service.key}
            icon={ICONS[service.key]}
            title={service.label}
            description={service.role}
            state={serviceState(readiness.data, service.key, {
              pending: readiness.isPending,
              failed: readiness.isError,
            })}
          />
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Kiểm tra gần nhất</CardTitle>
          <CardDescription>
            {readiness.dataUpdatedAt
              ? formatDateTime(new Date(readiness.dataUpdatedAt))
              : "Chưa có"}
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Readiness kiểm tra truy vấn schema PostgreSQL, ping Redis và bucket
          S3. Worker Celery có healthcheck Docker riêng và chưa được báo qua
          API.
        </CardContent>
      </Card>
    </>
  );
}
