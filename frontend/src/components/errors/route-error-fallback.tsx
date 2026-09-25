import { useQueryErrorResetBoundary } from "@tanstack/react-query";
import { useRouter, type ErrorComponentProps } from "@tanstack/react-router";
import { RotateCwIcon, TriangleAlertIcon } from "lucide-react";
import { useEffect } from "react";
import { Button } from "@/components/ui/button";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";

/** Shown in place of a route whose component threw; the layout stays usable. */
export function RouteErrorFallback({ error }: ErrorComponentProps) {
  const router = useRouter();
  const queryErrorResetBoundary = useQueryErrorResetBoundary();

  useEffect(() => {
    queryErrorResetBoundary.reset();
  }, [queryErrorResetBoundary]);

  return (
    <Empty role="alert" className="flex-none border border-dashed py-12">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <TriangleAlertIcon />
        </EmptyMedia>
        <EmptyTitle>Không hiển thị được trang này</EmptyTitle>
        <EmptyDescription>
          {error instanceof Error ? error.message : String(error)}
        </EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <Button variant="outline" onClick={() => void router.invalidate()}>
          <RotateCwIcon data-icon="inline-start" />
          Thử lại
        </Button>
      </EmptyContent>
    </Empty>
  );
}
