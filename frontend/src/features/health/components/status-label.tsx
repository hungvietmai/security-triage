import type { DisplayState } from "@/features/health/types";
import { cn } from "@/lib/utils";

const LABELS: Record<DisplayState, string> = {
  ok: "Sẵn sàng",
  unavailable: "Không khả dụng",
  checking: "Đang kiểm tra",
  unknown: "Không rõ",
};

export function StatusDot({ state }: { state: DisplayState }) {
  return (
    <span
      aria-hidden
      className={cn(
        "inline-block size-2 shrink-0 rounded-full",
        state === "ok" && "bg-emerald-500",
        state === "unavailable" && "bg-destructive",
        state === "checking" && "animate-pulse bg-muted-foreground/50",
        state === "unknown" && "bg-muted-foreground/50",
      )}
    />
  );
}

export function StatusLabel({ state }: { state: DisplayState }) {
  return (
    <span className="inline-flex items-center gap-2">
      <StatusDot state={state} />
      {LABELS[state]}
    </span>
  );
}
