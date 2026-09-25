import { AlertCircleIcon, RotateCwIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

export function QueryError({
  error,
  title = "Không tải được dữ liệu",
  onRetry,
  retrying = false,
}: {
  error: Error;
  title?: string;
  onRetry?: () => void;
  retrying?: boolean;
}) {
  return (
    <Alert variant="destructive">
      <AlertCircleIcon />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>
        <p>{error.message}</p>
        {onRetry && (
          <Button
            variant="outline"
            size="sm"
            className="mt-2"
            onClick={onRetry}
            disabled={retrying}
          >
            <RotateCwIcon
              data-icon="inline-start"
              className={retrying ? "animate-spin" : undefined}
            />
            Thử lại
          </Button>
        )}
      </AlertDescription>
    </Alert>
  );
}
