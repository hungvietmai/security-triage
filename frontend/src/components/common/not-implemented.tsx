import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";

/**
 * Placeholder for a capability the backend does not provide yet.
 * It states the gap plainly instead of rendering sample data.
 */
export function NotImplemented({
  icon: Icon,
  title,
  description,
  planned,
  children,
}: {
  icon: LucideIcon;
  title: string;
  description: ReactNode;
  /** Planned behavior, shown as a short list. */
  planned?: string[];
  children?: ReactNode;
}) {
  return (
    <Empty className="flex-none border border-dashed py-12">
      <EmptyHeader className="max-w-lg">
        <EmptyMedia variant="icon">
          <Icon />
        </EmptyMedia>
        <EmptyTitle className="flex items-center gap-2">
          {title}
          <Badge variant="outline">Chưa triển khai</Badge>
        </EmptyTitle>
        <EmptyDescription>{description}</EmptyDescription>
      </EmptyHeader>
      {(planned?.length || children) && (
        <EmptyContent className="max-w-xl">
          {planned?.length ? (
            <ul className="w-full max-w-md list-disc space-y-1 pl-5 text-left text-sm text-muted-foreground">
              {planned.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          ) : null}
          {children}
        </EmptyContent>
      )}
    </Empty>
  );
}
