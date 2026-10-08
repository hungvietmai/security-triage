import { getRouteApi, Link } from "@tanstack/react-router";
import { useState } from "react";
import { PageHeader } from "@/components/common/page-header";
import { QueryError } from "@/components/common/query-error";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, FieldLabel } from "@/components/ui/field";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { paths } from "@/config/paths";
import { useScan } from "@/features/scans/api/get-scan";
import { ScanHeader } from "@/features/scans/components/scan-header";
import { UnitDetailSheet } from "@/features/scans/components/unit-detail-sheet";
import { UnitsTable } from "@/features/scans/components/units-table";
import { isScanActive, TIERS, TOOLS } from "@/features/scans/types";
import { isApiError } from "@/lib/api-client";

const route = getRouteApi("/scans/$scanId");

export function ScanRoute() {
  const { scanId } = route.useParams();
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const [unitId, setUnitId] = useState<string | null>(null);
  const query = useScan({ scanId });
  const updateSearch = (next: Partial<typeof search>) => {
    setUnitId(null);
    void navigate({ search: { ...search, ...next } });
  };
  if (query.isPending) return <p role="status">Đang tải scan…</p>;
  if (query.isError)
    return isApiError(query.error, 404) ? (
      <p>Không tìm thấy scan.</p>
    ) : (
      <QueryError
        error={query.error}
        onRetry={() => void query.refetch()}
        retrying={query.isFetching}
      />
    );
  const scan = query.data;
  return (
    <div className="space-y-6">
      <PageHeader title="Chi tiết lượt quét" description={scan.id} />
      <Button asChild variant="outline">
        <Link
          to={paths.project.path}
          params={{ projectId: scan.project_id }}
          search={{ tab: "overview" }}
        >
          Về dự án
        </Link>
      </Button>
      <ScanHeader scan={scan} />
      {scan.status === "failed" ? (
        <Alert variant="destructive">
          <AlertTitle>Scan thất bại</AlertTitle>
          <AlertDescription>
            {scan.error_message ??
              scan.snapshot.error_message ??
              scan.tool_runs.find((run) => run.error_message)?.error_message ??
              "Máy chủ chưa cung cấp lý do thất bại."}
          </AlertDescription>
        </Alert>
      ) : (
        <>
          {scan.status === "partial" && (
            <Alert>
              <AlertTitle>Scan hoàn thành một phần</AlertTitle>
              <AlertDescription>
                {scan.error_message ??
                  "Kết quả chưa đầy đủ. Xem trạng thái và lỗi từng công cụ."}
              </AlertDescription>
            </Alert>
          )}
          <div className="flex flex-wrap gap-2" aria-label="Số đơn vị theo mức">
            {TIERS.map((tier) => (
              <Button
                key={tier}
                variant={search.tier === tier ? "default" : "outline"}
                aria-pressed={search.tier === tier}
                onClick={() =>
                  updateSearch({
                    tier: search.tier === tier ? undefined : tier,
                    page: 1,
                  })
                }
              >
                {tier}: {scan.unit_counts[tier] ?? 0}
              </Button>
            ))}
          </div>
          <div className="flex flex-wrap gap-4">
            <Field className="w-48">
              <FieldLabel htmlFor="tier-filter">Mức ưu tiên</FieldLabel>
              <Select
                value={search.tier ?? "all"}
                onValueChange={(value) =>
                  updateSearch({
                    tier: TIERS.find((tier) => tier === value),
                    page: 1,
                  })
                }
              >
                <SelectTrigger id="tier-filter">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Tất cả mức</SelectItem>
                  {TIERS.map((tier) => (
                    <SelectItem key={tier} value={tier}>
                      {tier}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            <Field className="w-48">
              <FieldLabel htmlFor="tool-filter">Công cụ</FieldLabel>
              <Select
                value={search.tool ?? "all"}
                onValueChange={(value) =>
                  updateSearch({
                    tool: TOOLS.find((tool) => tool === value),
                    page: 1,
                  })
                }
              >
                <SelectTrigger id="tool-filter">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Tất cả công cụ</SelectItem>
                  {TOOLS.map((tool) => (
                    <SelectItem key={tool} value={tool}>
                      {tool}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
          </div>
          <p className="text-sm text-muted-foreground">
            ✓/✗ cho biết có/không có cảnh báo tại đơn vị. Thiếu kết quả công cụ
            không chứng minh mã nguồn an toàn.
          </p>
          {isScanActive(scan.status) ? (
            <p role="status">
              Scan {scan.status}; tự cập nhật mỗi 3 giây. Đơn vị sẽ xuất hiện
              khi scan kết thúc.
            </p>
          ) : (
            <UnitsTable
              key={scanId}
              scanId={scanId}
              {...search}
              onPageChange={(page) => updateSearch({ page })}
              onSelect={setUnitId}
            />
          )}
          <UnitDetailSheet
            scanId={scanId}
            unitId={unitId}
            onClose={() => setUnitId(null)}
          />
        </>
      )}
    </div>
  );
}
