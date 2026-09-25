import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppProvider } from "@/app/provider";
import { createAppRouter } from "@/app/router";
import { createQueryClient, queryConfig } from "@/lib/react-query";

export * from "@testing-library/react";
export { db, makeProject } from "@/testing/mocks/db";
export { server } from "@/testing/mocks/server";

/**
 * Render the whole app at `path` — real router, providers and API client,
 * with MSW answering requests. Each call gets its own cache and history.
 */
export async function renderApp(path: string) {
  const queryClient = createQueryClient({
    queries: { ...queryConfig.queries, retry: false, staleTime: 0 },
  });
  const router = createAppRouter({
    queryClient,
    history: createMemoryHistory({ initialEntries: [path] }),
  });
  const user = userEvent.setup();
  const utils = render(
    <AppProvider queryClient={queryClient}>
      <RouterProvider router={router} />
    </AppProvider>,
  );
  await screen.findByRole("main");
  await router.load();
  return { ...utils, user, router, queryClient };
}

/** Queries scoped to the page content, excluding sidebar and header. */
export const mainContent = () => within(screen.getByRole("main"));
