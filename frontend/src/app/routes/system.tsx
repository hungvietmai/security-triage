import { ExternalLinkIcon } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { env } from "@/config/env";
import {
  HealthOverview,
  RefreshHealthButton,
} from "@/features/health/components/health-overview";

const ENDPOINTS = [
  "GET /api/v1/health/live",
  "GET /api/v1/health/ready",
  "GET|POST /api/v1/projects",
  "GET /api/v1/projects/{project_id}",
];

export function SystemRoute() {
  return (
    <>
      <PageHeader
        title="Hệ thống"
        description="Trạng thái các dịch vụ mà API phụ thuộc. Tự kiểm tra lại mỗi 15 giây."
        actions={<RefreshHealthButton />}
      />
      <HealthOverview />
      <Card>
        <CardHeader>
          <CardTitle>Tài liệu API</CardTitle>
          <CardDescription>
            Đặc tả và thử trực tiếp các endpoint
          </CardDescription>
          <CardAction>
            <Button variant="outline" size="sm" asChild>
              <a href={env.API_DOCS_URL} target="_blank" rel="noreferrer">
                Swagger
                <ExternalLinkIcon data-icon="inline-end" />
              </a>
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="space-y-1 font-mono text-xs text-muted-foreground">
          {ENDPOINTS.map((endpoint) => (
            <div key={endpoint}>{endpoint}</div>
          ))}
        </CardContent>
      </Card>
    </>
  );
}
