import { BookOpenIcon } from "lucide-react";
import type { ReactNode } from "react";
import { AppBreadcrumbs } from "@/components/layouts/app-breadcrumbs";
import { AppSidebar } from "@/components/layouts/app-sidebar";
import { ThemeToggle } from "@/components/layouts/theme-toggle";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { env } from "@/config/env";

/**
 * App shell: sidebar, header and content column. Feature-specific parts
 * (e.g. the system status entry) are passed in by the app layer.
 */
export function DashboardLayout({
  sidebarFooter,
  children,
}: {
  sidebarFooter?: ReactNode;
  children: ReactNode;
}) {
  return (
    <SidebarProvider>
      <AppSidebar footer={sidebarFooter} />
      {/* SidebarInset renders the page's <main> landmark. */}
      <SidebarInset>
        <header className="sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 border-b bg-background/95 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/80">
          <SidebarTrigger className="-ml-1" />
          <Separator
            orientation="vertical"
            className="mr-2 data-vertical:h-4 data-vertical:self-center"
          />
          <div className="min-w-0 flex-1">
            <AppBreadcrumbs />
          </div>
          <Button variant="ghost" size="sm" asChild>
            <a href={env.API_DOCS_URL} target="_blank" rel="noreferrer">
              <BookOpenIcon data-icon="inline-start" />
              <span className="hidden sm:inline">API docs</span>
            </a>
          </Button>
          <ThemeToggle />
        </header>
        <div className="mx-auto flex w-full max-w-6xl flex-1 flex-col gap-6 p-4 md:p-6 lg:p-8">
          {children}
        </div>
      </SidebarInset>
    </SidebarProvider>
  );
}
