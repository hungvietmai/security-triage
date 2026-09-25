import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";
import { Button } from "@/components/ui/button";

/** Offset pagination footer: "1–12 / 40" plus previous/next. `page` is 1-based. */
export function PaginationBar({
  page,
  pageSize,
  total,
  disabled = false,
  onPageChange,
}: {
  page: number;
  pageSize: number;
  total: number;
  disabled?: boolean;
  onPageChange: (page: number) => void;
}) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const first = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const last = Math.min(page * pageSize, total);

  return (
    <nav
      className="flex w-full items-center justify-between gap-4 text-sm text-muted-foreground"
      aria-label="Phân trang"
    >
      <span className="tabular-nums">
        {first}–{last} / {total}
      </span>
      <div className="flex items-center gap-2">
        <span className="tabular-nums">
          Trang {Math.min(page, pageCount)} / {pageCount}
        </span>
        <Button
          variant="outline"
          size="icon-sm"
          aria-label="Trang trước"
          disabled={disabled || page <= 1}
          onClick={() => onPageChange(page - 1)}
        >
          <ChevronLeftIcon />
        </Button>
        <Button
          variant="outline"
          size="icon-sm"
          aria-label="Trang sau"
          disabled={disabled || page >= pageCount}
          onClick={() => onPageChange(page + 1)}
        >
          <ChevronRightIcon />
        </Button>
      </div>
    </nav>
  );
}
