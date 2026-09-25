import { TriangleAlertIcon } from "lucide-react";
import { Button } from "@/components/ui/button";

/** Last-resort screen when rendering fails outside any route. */
export function MainErrorFallback() {
  return (
    <div
      role="alert"
      className="flex min-h-svh flex-col items-center justify-center gap-4 p-6 text-center"
    >
      <TriangleAlertIcon className="size-8 text-destructive" />
      <h1 className="text-lg font-semibold">Ứng dụng gặp lỗi</h1>
      <p className="max-w-md text-sm text-muted-foreground">
        Đã xảy ra lỗi không mong muốn. Tải lại trang để thử lại.
      </p>
      <Button onClick={() => window.location.reload()}>Tải lại trang</Button>
    </div>
  );
}
