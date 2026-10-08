import { PaginationBar } from "@/components/common/pagination-bar";
import { QueryError } from "@/components/common/query-error";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useUnits } from "@/features/scans/api/get-units";
import { UNITS_PAGE_SIZE, type Tier, type Tool } from "@/features/scans/types";

export function UnitsTable({
  scanId,
  page,
  tier,
  tool,
  onPageChange,
  onSelect,
}: {
  scanId: string;
  page: number;
  tier?: Tier;
  tool?: Tool;
  onPageChange: (page: number) => void;
  onSelect: (unitId: string) => void;
}) {
  const query = useUnits({
    scanId,
    params: {
      limit: UNITS_PAGE_SIZE,
      offset: (page - 1) * UNITS_PAGE_SIZE,
      tier,
      tool,
    },
  });
  if (query.isPending) return <p role="status">Đang tải đơn vị…</p>;
  if (query.isError)
    return (
      <QueryError
        error={query.error}
        onRetry={() => void query.refetch()}
        retrying={query.isFetching}
      />
    );
  const data = query.data;
  return (
    <div className="space-y-4">
      {data.items.length === 0 ? (
        <p className="rounded-md border border-dashed p-6 text-muted-foreground">
          Không có đơn vị phù hợp bộ lọc. Kết quả này không chứng minh mã nguồn
          an toàn.
        </p>
      ) : (
        <Table aria-label="Đơn vị">
          <TableHeader>
            <TableRow>
              {[
                "Mức",
                "file:dòng",
                "Hàm sink",
                "Vai trò đối số",
                "Semgrep",
                "CodeQL",
                "decision_id",
                "Lý do",
              ].map((heading) => (
                <TableHead key={heading}>{heading}</TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.items.map((unit) => (
              <TableRow
                key={unit.id}
                className="cursor-pointer"
                onClick={() => onSelect(unit.id)}
              >
                <TableCell>
                  <Badge variant="outline">{unit.priority}</Badge>
                </TableCell>
                <TableCell>
                  <Button
                    variant="link"
                    className="h-auto max-w-80 justify-start p-0 text-left whitespace-normal"
                    aria-label={`Xem đơn vị ${unit.path ?? unit.unit_key}:${unit.start_line ?? "—"}`}
                    onClick={(event) => {
                      event.stopPropagation();
                      onSelect(unit.id);
                    }}
                  >
                    {unit.path ?? "Không rõ file"}:{unit.start_line ?? "—"}
                  </Button>
                </TableCell>
                <TableCell>{unit.sink_kind ?? "Chưa xác định"}</TableCell>
                <TableCell>{unit.argument_role ?? "Chưa xác định"}</TableCell>
                <TableCell>
                  <span
                    aria-label={
                      unit.tools.includes("semgrep")
                        ? "Có cảnh báo Semgrep"
                        : "Không có cảnh báo Semgrep"
                    }
                  >
                    {unit.tools.includes("semgrep") ? "✓" : "✗"}
                  </span>
                </TableCell>
                <TableCell>
                  <span
                    aria-label={
                      unit.tools.includes("codeql")
                        ? "Có cảnh báo CodeQL"
                        : "Không có cảnh báo CodeQL"
                    }
                  >
                    {unit.tools.includes("codeql") ? "✓" : "✗"}
                  </span>
                </TableCell>
                <TableCell>{unit.decision_id}</TableCell>
                <TableCell className="max-w-80 truncate" title={unit.reason}>
                  {unit.reason}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      <PaginationBar
        page={page}
        pageSize={data.limit}
        total={data.total}
        disabled={query.isFetching}
        onPageChange={onPageChange}
      />
    </div>
  );
}
