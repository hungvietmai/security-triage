import { QueryError } from "@/components/common/query-error";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { getSarifUrl, useReport } from "@/features/scans/api/get-report";
import {
  EVIDENCE_STATES,
  FAMILIES,
  FILTER_RULES,
  type EvidenceState,
  type ScanReport,
} from "@/features/scans/types";

const STAGES: { key: keyof ScanReport["stages"]; label: string }[] = [
  { key: "raw_alerts", label: "Cảnh báo thô của mọi công cụ" },
  { key: "units", label: "Đơn vị sau khi gộp theo lời gọi và vai trò đối số" },
  { key: "candidates", label: "Ứng viên rà soát (mỗi lời gọi một mục)" },
  { key: "main_list", label: "Danh sách rà chính sau khi gạn" },
  { key: "filtered", label: "Đã gạn vì có bằng chứng là cảnh báo sai" },
  {
    key: "demoted",
    label: "Chỉ hạ ưu tiên (P3/P4), vẫn trong danh sách rà chính",
  },
];

function Counts({
  label,
  head,
  rows,
}: {
  label: string;
  head: string[];
  rows: (string | number)[][];
}) {
  return (
    <Table aria-label={label}>
      <TableHeader>
        <TableRow>
          {head.map((heading) => (
            <TableHead key={heading}>{heading}</TableHead>
          ))}
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((row) => (
          <TableRow key={String(row[0])}>
            {row.map((cell, index) => (
              <TableCell key={index} className="whitespace-normal">
                {cell}
              </TableCell>
            ))}
          </TableRow>
        ))}
        {rows.length === 0 && (
          <TableRow>
            <TableCell colSpan={head.length}>Không có dữ liệu</TableCell>
          </TableRow>
        )}
      </TableBody>
    </Table>
  );
}

export function ScanReportPanel({ scanId }: { scanId: string }) {
  const query = useReport({ scanId });
  if (query.isPending) return <p role="status">Đang tải báo cáo…</p>;
  if (query.isError)
    return (
      <QueryError
        error={query.error}
        onRetry={() => void query.refetch()}
        retrying={query.isFetching}
      />
    );
  const report = query.data;
  const steps = Object.entries(report.steps).flatMap(([language, entries]) =>
    Object.entries(entries)
      // Version checks take a fraction of a second and say nothing about the scan.
      .filter(([step]) => !step.endsWith("-version"))
      .map(([step, record]) => [
        `${language} · ${step}`,
        String(record.status ?? "—"),
        typeof record.seconds === "number" ? record.seconds.toFixed(1) : "—",
        typeof record.raw_findings === "number" ? record.raw_findings : "—",
      ]),
  );
  return (
    <section className="space-y-4" aria-label="Báo cáo trước–sau">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-lg font-semibold">Báo cáo trước–sau</h2>
        <div className="flex flex-wrap gap-2">
          <Button asChild variant="outline">
            <a
              href={`data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(report, null, 2))}`}
              download={`scan-report-${report.scan_id}.json`}
            >
              Tải báo cáo JSON
            </a>
          </Button>
          <Button asChild variant="outline">
            <a
              href={getSarifUrl(scanId)}
              download={`scan-${report.scan_id}.sarif`}
            >
              Tải SARIF hợp nhất
            </a>
          </Button>
        </div>
      </div>
      <p className="text-sm text-muted-foreground">
        Gạn chỉ chuyển ứng viên ra khỏi danh sách rà chính khi một công cụ cung
        cấp bằng chứng cụ thể. Ứng viên đã gạn vẫn được giữ cùng cảnh báo gốc và
        lý do.
      </p>
      <Counts
        label="Các bước của quy trình"
        head={["Bước", "Số lượng"]}
        rows={STAGES.map(({ key, label }) => [label, report.stages[key]])}
      />
      <Counts
        label="Trước–sau theo nhóm phân tích"
        head={[
          "Nhóm",
          "Cảnh báo thô",
          "Đơn vị",
          "Ứng viên",
          "Danh sách rà chính",
          "Đã gạn",
          "Trạng thái bằng chứng",
        ]}
        rows={report.families.map((family) => [
          FAMILIES[family.family],
          family.raw_alerts,
          family.units,
          family.candidates,
          family.main_list,
          family.filtered,
          Object.entries(family.evidence_states)
            .map(
              ([state, count]) =>
                `${EVIDENCE_STATES[state as EvidenceState]}: ${count}`,
            )
            .join("; ") || "—",
        ])}
      />
      <Counts
        label="Đóng góp của từng công cụ"
        head={["Công cụ", "Ứng viên có báo", "Chỉ công cụ này báo"]}
        rows={Object.entries(report.sources).map(([tool, counts]) => [
          tool,
          counts.candidates,
          counts.only,
        ])}
      />
      <Counts
        label="Ứng viên đã gạn theo quy tắc"
        head={["Quy tắc gạn", "Số ứng viên"]}
        rows={Object.entries(report.filtered_by_rule).map(([rule, count]) => [
          FILTER_RULES[rule] ?? rule,
          count,
        ])}
      />
      <Counts
        label="Thời gian từng bước"
        head={["Ngôn ngữ · bước", "Trạng thái", "Giây", "Cảnh báo"]}
        rows={steps}
      />
    </section>
  );
}
