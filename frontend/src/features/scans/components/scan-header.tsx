import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { Scan } from "@/features/scans/types";
import { formatDateTime } from "@/utils/format";

export function ScanHeader({ scan }: { scan: Scan }) {
  const rows = [
    ["Tạo", formatDateTime(scan.created_at)],
    [
      "Bắt đầu",
      scan.started_at ? formatDateTime(scan.started_at) : "Chưa bắt đầu",
    ],
    [
      "Kết thúc",
      scan.finished_at ? formatDateTime(scan.finished_at) : "Chưa kết thúc",
    ],
    ["Nguồn", scan.snapshot.source_coordinate ?? "Chưa có tọa độ nguồn"],
    ["Loại nguồn", scan.snapshot.source_kind ?? "Chưa xác định"],
    ["Snapshot", scan.snapshot.id],
    ["Trạng thái snapshot", scan.snapshot.status],
    ["sha256", scan.snapshot.sha256 ?? "Chưa có hash"],
    ["provenance_kind", scan.snapshot.provenance_kind ?? "Chưa xác định"],
    ["Profile", scan.profile ?? "Chưa ghi nhận"],
    ["Phiên bản bộ gộp", scan.reconciler_version ?? "Chưa ghi nhận"],
    ["Phiên bản chính sách", scan.policy_version ?? "Chưa ghi nhận"],
  ];
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          Thông tin scan <Badge variant="outline">{scan.status}</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {rows.map(([label, value]) => (
            <div key={label} className="min-w-0">
              <dt className="text-sm text-muted-foreground">{label}</dt>
              <dd className="text-sm break-all">
                {value}
                {label === "provenance_kind" && value === "tofu" && (
                  <Badge variant="secondary" className="ml-2">
                    tin lần tải đầu
                  </Badge>
                )}
              </dd>
            </div>
          ))}
        </dl>
        <div className="space-y-2 border-t pt-4">
          <h3 className="text-sm font-medium">Công cụ</h3>
          {scan.tool_runs.length === 0 && (
            <p className="text-sm text-muted-foreground">
              Chưa có lượt chạy công cụ.
            </p>
          )}
          {scan.tool_runs.map((run, index) => (
            <div
              key={`${run.tool}-${run.language}-${index}`}
              className="text-sm"
            >
              <p>
                {run.tool} · {run.language} · phiên bản{" "}
                {run.tool_version ?? "chưa ghi nhận"} · {run.status}
              </p>
              {run.error_message && (
                <p className="wrap-break-word text-destructive">
                  {run.error_message}
                </p>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
