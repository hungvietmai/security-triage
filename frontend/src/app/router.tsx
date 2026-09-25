import type { QueryClient } from "@tanstack/react-query";
import {
  createBrowserHistory,
  createRootRouteWithContext,
  createRoute,
  createRouter,
  lazyRouteComponent,
  type RouterHistory,
} from "@tanstack/react-router";
import { ProjectCrumb } from "@/app/routes/projects/project-crumb";
import {
  projectSearchSchema,
  projectsSearchSchema,
} from "@/app/routes/projects/search";
import { RootRoute } from "@/app/routes/root";
import { NotFoundRoute } from "@/app/routes/not-found";
import { RouteErrorFallback } from "@/components/errors/route-error-fallback";
import { paths } from "@/config/paths";
import { getReadinessQueryOptions } from "@/features/health/api/get-readiness";
import { getProjectQueryOptions } from "@/features/projects/api/get-project";
import { getProjectsQueryOptions } from "@/features/projects/api/get-projects";
import "@/types/router";

// Pages are split per route. Loaders only start fetching (hover preload
// included); pages render their own pending and error states.
const rootRoute = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: RootRoute,
  notFoundComponent: NotFoundRoute,
});

const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: paths.dashboard.path,
  component: lazyRouteComponent(
    () => import("@/app/routes/dashboard"),
    "DashboardRoute",
  ),
  staticData: { crumb: paths.dashboard.label },
  loader: ({ context }) => {
    void context.queryClient.prefetchQuery(
      getProjectsQueryOptions({ page: 1 }),
    );
  },
});

const projectsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "projects",
  staticData: { crumb: paths.projects.label },
});

const projectsIndexRoute = createRoute({
  getParentRoute: () => projectsRoute,
  path: "/",
  component: lazyRouteComponent(
    () => import("@/app/routes/projects/projects"),
    "ProjectsRoute",
  ),
  validateSearch: projectsSearchSchema,
  loaderDeps: ({ search }) => ({ page: search.page }),
  loader: ({ context, deps }) => {
    void context.queryClient.prefetchQuery(
      getProjectsQueryOptions({ page: deps.page }),
    );
  },
});

const projectRoute = createRoute({
  getParentRoute: () => projectsRoute,
  path: "$projectId",
  component: lazyRouteComponent(
    () => import("@/app/routes/projects/project"),
    "ProjectRoute",
  ),
  staticData: { crumb: ProjectCrumb },
  validateSearch: projectSearchSchema,
  loader: ({ context, params }) => {
    void context.queryClient.prefetchQuery(
      getProjectQueryOptions(params.projectId),
    );
  },
});

const scansRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "scans",
  component: lazyRouteComponent(
    () => import("@/app/routes/scans"),
    "ScansRoute",
  ),
  staticData: { crumb: paths.scans.label },
});

const findingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "findings",
  component: lazyRouteComponent(
    () => import("@/app/routes/findings"),
    "FindingsRoute",
  ),
  staticData: { crumb: paths.findings.label },
});

const systemRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "system",
  component: lazyRouteComponent(
    () => import("@/app/routes/system"),
    "SystemRoute",
  ),
  staticData: { crumb: paths.system.label },
  loader: ({ context }) => {
    void context.queryClient.prefetchQuery(getReadinessQueryOptions());
  },
});

const routeTree = rootRoute.addChildren([
  dashboardRoute,
  projectsRoute.addChildren([projectsIndexRoute, projectRoute]),
  scansRoute,
  findingsRoute,
  systemRoute,
]);

/** Tests pass their own QueryClient and a memory history. */
export function createAppRouter({
  queryClient,
  history = createBrowserHistory(),
}: {
  queryClient: QueryClient;
  history?: RouterHistory;
}) {
  return createRouter({
    routeTree,
    history,
    context: { queryClient },
    defaultErrorComponent: RouteErrorFallback,
    defaultPreload: "intent",
    // TanStack Query owns caching; always rerun the (non-blocking) loaders.
    defaultPreloadStaleTime: 0,
    scrollRestoration: true,
  });
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof createAppRouter>;
  }
}
