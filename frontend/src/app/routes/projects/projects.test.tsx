import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { PROJECTS_PAGE_SIZE } from "@/features/projects/types";
import {
  db,
  mainContent as main,
  makeProject,
  renderApp,
  screen,
  server,
  waitFor,
  within,
} from "@/testing/test-utils";

describe("Projects page", () => {
  it("shows an empty state when there are no projects", async () => {
    await renderApp("/projects");
    expect(await main().findByText("Chưa có dự án")).toBeInTheDocument();
  });

  it("pages through projects and keeps the page in the URL", async () => {
    db.projects = Array.from({ length: PROJECTS_PAGE_SIZE + 1 }, () =>
      makeProject(),
    );
    const { user, router } = await renderApp("/projects");

    expect(await main().findByText("Dự án 1")).toBeInTheDocument();
    expect(
      main().getByText(`1–${PROJECTS_PAGE_SIZE} / 13`),
    ).toBeInTheDocument();

    await user.click(main().getByRole("button", { name: "Trang sau" }));

    expect(await main().findByText("Dự án 13")).toBeInTheDocument();
    expect(main().queryByText("Dự án 1")).not.toBeInTheDocument();
    expect(router.state.location.search).toEqual({ page: 2 });
  });

  it("explains an out-of-range page instead of showing an empty table", async () => {
    db.projects = [makeProject()];
    await renderApp("/projects?page=5");
    expect(
      await main().findByText("Trang 5 không có dự án"),
    ).toBeInTheDocument();
    expect(main().getByRole("link", { name: "Về trang đầu" })).toHaveAttribute(
      "href",
      "/projects?page=1",
    );
  });

  it("falls back to page 1 for an invalid page parameter", async () => {
    db.projects = [makeProject()];
    const { router } = await renderApp("/projects?page=abc");
    expect(await main().findByText("Dự án 1")).toBeInTheDocument();
    expect(router.state.location.search).toEqual({ page: 1 });
  });

  it("shows the API error and recovers on retry", async () => {
    db.projects = [makeProject()];
    let failing = true;
    server.use(
      http.get("/api/v1/projects", () =>
        failing
          ? HttpResponse.json({ detail: "Database down" }, { status: 500 })
          : undefined,
      ),
    );
    const { user } = await renderApp("/projects");

    expect(await main().findByText("Database down")).toBeInTheDocument();
    failing = false;
    await user.click(main().getByRole("button", { name: "Thử lại" }));
    expect(await main().findByText("Dự án 1")).toBeInTheDocument();
  });
});

describe("Create project dialog", () => {
  async function openDialog() {
    const rendered = await renderApp("/projects");
    await main().findByText("Chưa có dự án");
    await rendered.user.click(
      main().getAllByRole("button", { name: "Tạo dự án" })[0],
    );
    const dialog = within(await screen.findByRole("dialog"));
    return { ...rendered, dialog };
  }

  it("validates the name before calling the API", async () => {
    let posted = false;
    server.use(
      http.post("/api/v1/projects", () => {
        posted = true;
        return HttpResponse.json({}, { status: 500 });
      }),
    );
    const { user, dialog } = await openDialog();

    await user.type(dialog.getByLabelText("Tên dự án"), "   ");
    await user.click(dialog.getByRole("button", { name: "Tạo dự án" }));

    expect(await dialog.findByText("Nhập tên dự án.")).toBeInTheDocument();
    expect(posted).toBe(false);
  });

  it("creates the project, then opens its detail page", async () => {
    const { user, dialog, router } = await openDialog();

    await user.type(dialog.getByLabelText("Tên dự án"), "  Payment API  ");
    await user.type(dialog.getByLabelText(/Mô tả/), "CWE-78 review");
    await user.click(dialog.getByRole("button", { name: "Tạo dự án" }));

    expect(
      await screen.findByRole("heading", { level: 1, name: "Payment API" }),
    ).toBeInTheDocument();
    expect(db.projects[0]).toMatchObject({
      name: "Payment API",
      description: "CWE-78 review",
    });
    expect(router.state.location.pathname).toBe(
      `/projects/${db.projects[0].id}`,
    );
    expect(
      await screen.findByText("Đã tạo dự án “Payment API”."),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("shows the server's validation message inside the dialog only", async () => {
    server.use(
      http.post("/api/v1/projects", () =>
        HttpResponse.json(
          {
            detail: [
              { loc: ["body", "name"], msg: "Name is taken", type: "x" },
            ],
          },
          { status: 422 },
        ),
      ),
    );
    const { user, dialog } = await openDialog();

    await user.type(dialog.getByLabelText("Tên dự án"), "Duplicate");
    await user.click(dialog.getByRole("button", { name: "Tạo dự án" }));

    expect(await dialog.findByText("name: Name is taken")).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    // handlesError suppresses the global toast, so the message appears once.
    expect(screen.getAllByText("name: Name is taken")).toHaveLength(1);
  });
});
