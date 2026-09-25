import { describe, expect, it } from "vitest";
import {
  db,
  mainContent as main,
  makeProject,
  renderApp,
  screen,
  within,
} from "@/testing/test-utils";

describe("Project detail page", () => {
  it("shows the project's details and breadcrumb", async () => {
    const project = makeProject({
      name: "SecBench.js CWE-78",
      description: "Pinned package cases",
    });
    db.projects = [project];
    await renderApp(`/projects/${project.id}`);

    expect(
      await main().findByRole("heading", { level: 1, name: project.name }),
    ).toBeInTheDocument();
    expect(main().getByText(project.id)).toBeInTheDocument();
    expect(main().getAllByText("Pinned package cases").length).toBeGreaterThan(
      0,
    );
    const breadcrumb = within(
      screen.getByRole("navigation", { name: "breadcrumb" }),
    );
    expect(breadcrumb.getByText(project.name)).toBeInTheDocument();
  });

  it("switches tabs through the URL and marks unbuilt features", async () => {
    const project = makeProject();
    db.projects = [project];
    const { user, router } = await renderApp(`/projects/${project.id}`);

    await user.click(await main().findByRole("tab", { name: "Mã nguồn" }));

    expect(router.state.location.search).toEqual({ tab: "sources" });
    expect(await main().findByText("Bản mã nguồn")).toBeInTheDocument();
    expect(main().getByText("Chưa triển khai")).toBeInTheDocument();
  });

  it("opens the requested tab from the URL", async () => {
    const project = makeProject();
    db.projects = [project];
    await renderApp(`/projects/${project.id}?tab=findings`);
    expect(
      await main().findByRole("tab", { name: "Cảnh báo", selected: true }),
    ).toBeInTheDocument();
  });

  it("shows a not-found state for an unknown project", async () => {
    await renderApp("/projects/00000000-0000-4000-8000-999999999999");
    expect(await main().findByText("Không tìm thấy dự án")).toBeInTheDocument();
  });
});
