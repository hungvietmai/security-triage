import type { ReactNode } from "react";
import { QueryError } from "@/components/common/query-error";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useUnit } from "@/features/scans/api/get-unit";
import type { Finding, UnitDetail } from "@/features/scans/types";
import { getDataFlows } from "@/features/scans/utils/data-flows";
import { isApiError } from "@/lib/api-client";

function Detail({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <dt className="font-medium">{label}</dt>
      <dd className="break-words text-muted-foreground">{children}</dd>
    </div>
  );
}

function FindingEvidence({ finding }: { finding: Finding }) {
  const flows = getDataFlows(finding.raw_result);
  return (
    <article className="space-y-3 rounded-md border p-3">
      <h4 className="font-medium">
        {finding.tool} · {finding.raw_rule_id ?? finding.rule_id}
      </h4>
      <p className="break-words">{finding.message}</p>
      <p className="font-mono text-xs break-all">
        {finding.file_path ?? "Không rõ file"}:{finding.start_line ?? "—"}
      </p>
      <h5 className="font-medium">Vết dữ liệu</h5>
      {flows.length === 0 ? (
        <p className="text-muted-foreground">công cụ không cung cấp vết</p>
      ) : (
        flows.map((steps, index) => (
          <div key={index}>
            <p className="text-xs text-muted-foreground">Vết {index + 1}</p>
            <ol className="list-decimal space-y-2 pl-5">
              {steps.map((step, stepIndex) => (
                <li key={stepIndex} className="break-words">
                  {step}
                </li>
              ))}
            </ol>
          </div>
        ))
      )}
    </article>
  );
}

function UnitEvidence({ unit }: { unit: UnitDetail }) {
  return (
    <div className="space-y-6 p-4 pt-0">
      <section className="space-y-3">
        <h3 className="font-semibold">Quyết định</h3>
        <dl className="space-y-3">
          <Detail label="decision_id">{unit.decision_id}</Detail>
          <Detail label="reason">{unit.reason}</Detail>
          <Detail label="matched_conditions">
            {unit.matched_conditions.join(", ") || "Không có điều kiện khớp"}
          </Detail>
          <Detail label="unknown_fields">
            {unit.unknown_fields.join(", ") ||
              "Không ghi nhận trường chưa biết"}
          </Detail>
        </dl>
        <Table aria-label="predicate_values">
          <TableHeader>
            <TableRow>
              <TableHead>Điều kiện</TableHead>
              <TableHead>Giá trị</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {Object.entries(unit.predicate_values).map(([predicate, value]) => (
              <TableRow key={predicate}>
                <TableCell className="whitespace-normal">{predicate}</TableCell>
                <TableCell>{value ? "Đúng" : "Sai"}</TableCell>
              </TableRow>
            ))}
            {Object.keys(unit.predicate_values).length === 0 && (
              <TableRow>
                <TableCell colSpan={2}>Không có giá trị điều kiện</TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
        {unit.blocker_proof && (
          <div>
            <h4 className="font-medium">blocker_proof</h4>
            <pre className="mt-2 overflow-x-auto rounded-md bg-muted p-3 text-xs whitespace-pre-wrap">
              {JSON.stringify(unit.blocker_proof, null, 2)}
            </pre>
          </div>
        )}
      </section>
      <section className="space-y-3">
        <h3 className="font-semibold">Bằng chứng</h3>
        <dl className="space-y-3">
          <Detail label="source_types">
            {unit.source_types.join(", ") || "Chưa xác định"}
          </Detail>
          <Detail label="Vai trò đối số">
            {unit.argument_role ?? "Chưa xác định"}
          </Detail>
          <Detail label="Trạng thái shell">
            {unit.shell_state ?? "Chưa xác định"}
          </Detail>
          <Detail label="Mapping">{unit.mapping_status}</Detail>
        </dl>
        {unit.finding_evidence.length > 0 && (
          <div>
            <h4 className="font-medium">Bằng chứng từng cảnh báo</h4>
            <pre className="mt-2 overflow-x-auto rounded-md bg-muted p-3 text-xs whitespace-pre-wrap">
              {JSON.stringify(unit.finding_evidence, null, 2)}
            </pre>
          </div>
        )}
      </section>
      <section className="space-y-3">
        <h3 className="font-semibold">Cảnh báo thô</h3>
        <p className="text-muted-foreground">
          Thiếu vết không có nghĩa là an toàn.
        </p>
        {unit.findings.map((finding) => (
          <FindingEvidence key={finding.id} finding={finding} />
        ))}
        {unit.findings.length === 0 && (
          <p>Không có cảnh báo thô. công cụ không cung cấp vết</p>
        )}
      </section>
      <dl className="space-y-3 border-t pt-4 font-mono text-xs">
        <Detail label="policy_sha256">{unit.policy_sha256}</Detail>
        <Detail label="spec_sha256">{unit.spec_sha256}</Detail>
      </dl>
    </div>
  );
}

function UnitContent({ scanId, unitId }: { scanId: string; unitId: string }) {
  const unit = useUnit({ scanId, unitId });
  if (unit.isPending)
    return (
      <div className="p-4">
        <Skeleton className="h-48 w-full" />
        <p role="status">Đang tải bằng chứng…</p>
      </div>
    );
  if (unit.isError)
    return (
      <div className="p-4">
        {isApiError(unit.error, 404) ? (
          <p>Không tìm thấy đơn vị trong scan này.</p>
        ) : (
          <QueryError
            error={unit.error}
            onRetry={() => void unit.refetch()}
            retrying={unit.isFetching}
          />
        )}
      </div>
    );
  return <UnitEvidence unit={unit.data} />;
}

export function UnitDetailSheet({
  scanId,
  unitId,
  onClose,
}: {
  scanId: string;
  unitId: string | null;
  onClose: () => void;
}) {
  return (
    <Sheet
      open={unitId !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <SheetContent
        showCloseButton={false}
        className="w-full overflow-y-auto sm:max-w-2xl"
      >
        <SheetHeader>
          <SheetTitle>Chi tiết đơn vị</SheetTitle>
          <SheetDescription>
            Quyết định, bằng chứng và vết dữ liệu của cảnh báo.
          </SheetDescription>
          <SheetClose asChild>
            <Button variant="outline" className="mt-2 self-end">
              Đóng chi tiết
            </Button>
          </SheetClose>
        </SheetHeader>
        {unitId && <UnitContent key={unitId} scanId={scanId} unitId={unitId} />}
      </SheetContent>
    </Sheet>
  );
}
