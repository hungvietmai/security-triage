import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { FAMILIES, type Family, type ScanFamily } from "@/features/scans/types";

/** "python: completed" for every language a family ran in, or the profile's single run. */
function runStates(family: ScanFamily) {
  if (family.runs.length === 0) return "Theo trạng thái lượt quét";
  return family.runs.map((run) => `${run.language}: ${run.status}`).join(", ");
}

function evidenceSteps(family: ScanFamily) {
  const steps = family.runs.flatMap((run) =>
    Object.entries(run.evidence_steps).map(
      ([step, status]) => `${run.language} · ${step}: ${status}`,
    ),
  );
  return steps.length > 0 ? steps.join(", ") : "Không có bước bằng chứng";
}

/**
 * The analysis families of a scan: who assessed each one, how its run and its evidence steps
 * ended, and how its units are disposed. Three different facts, shown side by side.
 */
export function ScanFamilies({
  families,
  selected,
  onSelect,
}: {
  families: ScanFamily[];
  selected?: Family;
  onSelect: (family: Family | undefined) => void;
}) {
  if (families.length === 0) return null;
  return (
    <section className="space-y-3" aria-label="Nhóm phân tích">
      <h2 className="text-lg font-semibold">Nhóm phân tích (CWE)</h2>
      <p className="text-sm text-muted-foreground">
        Mỗi cảnh báo thuộc đúng một nhóm và được thẩm định bằng profile của nhóm
        đó. Trạng thái lượt chạy, trạng thái bước bằng chứng và quyết định gạn
        là ba thông tin riêng: thiếu bằng chứng thì cảnh báo vẫn ở danh sách rà.
      </p>
      <div className="flex flex-wrap gap-2" aria-label="Lọc theo nhóm">
        {families.map((family) => (
          <Button
            key={family.family}
            variant={selected === family.family ? "default" : "outline"}
            aria-pressed={selected === family.family}
            onClick={() =>
              onSelect(selected === family.family ? undefined : family.family)
            }
          >
            {FAMILIES[family.family]}: {family.units}
          </Button>
        ))}
      </div>
      <Table aria-label="Nhóm phân tích của lượt quét">
        <TableHeader>
          <TableRow>
            {[
              "Nhóm",
              "Profile thẩm định",
              "Lượt chạy",
              "Bước bằng chứng",
              "Đơn vị",
              "Rà chính",
              "Đã gạn",
              "Giữ lại chưa xếp hạng",
            ].map((heading) => (
              <TableHead key={heading}>{heading}</TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {families.map((family) => (
            <TableRow key={family.family}>
              <TableCell className="whitespace-normal">
                {FAMILIES[family.family]}
              </TableCell>
              <TableCell className="whitespace-normal">
                {family.profile_id ?? "Không có"}
              </TableCell>
              <TableCell className="whitespace-normal">
                {runStates(family)}
                {family.runs
                  .filter((run) => run.error)
                  .map((run) => (
                    <p
                      key={run.language}
                      className="wrap-break-word text-destructive"
                    >
                      {run.error}
                    </p>
                  ))}
              </TableCell>
              <TableCell className="whitespace-normal">
                {evidenceSteps(family)}
              </TableCell>
              <TableCell>{family.units}</TableCell>
              <TableCell>{family.review}</TableCell>
              <TableCell>{family.filtered}</TableCell>
              <TableCell>{family.held}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </section>
  );
}
