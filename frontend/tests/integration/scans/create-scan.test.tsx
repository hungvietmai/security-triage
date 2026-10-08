import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { db, makeScan } from "@/testing/mocks/db";
import {
  mainContent,
  makeProject,
  renderApp,
  screen,
  server,
  waitFor,
  within,
} from "@test/support/test-utils";
import type { Schemas } from "@/types/api";

async function openForm() {
  const project = makeProject();
  db.projects = [project];
  const app = await renderApp(`/projects/${project.id}`);
  await app.user.click(
    await mainContent().findByRole("button", { name: "Tạo scan" }),
  );
  return {
    ...app,
    project,
    dialog: within(screen.getByRole("dialog", { name: "Tạo scan mới" })),
  };
}

describe("Create scan dialog", () => {
  it("blocks invalid npm names and version ranges without sending a request", async () => {
    let calls = 0;
    server.use(
      http.post("/api/v1/projects/:projectId/scans", () => {
        calls++;
        return HttpResponse.json({});
      }),
    );
    const { user, dialog } = await openForm();
    await user.type(dialog.getByLabelText("Tên npm"), "@Scope/pkg");
    await user.type(dialog.getByLabelText("Phiên bản"), "^1.2.3");
    await user.click(dialog.getByRole("button", { name: "Tạo scan" }));
    expect(
      await dialog.findByText(
        "Tên npm không hợp lệ (có thể dùng @scope/package).",
        { exact: true },
      ),
    ).toBeInTheDocument();
    expect(dialog.getByLabelText("Tên npm")).toHaveAttribute(
      "aria-invalid",
      "true",
    );
    expect(dialog.getByLabelText("Phiên bản")).toHaveAttribute(
      "aria-invalid",
      "true",
    );
    expect(calls).toBe(0);
  });

  it("creates a scoped npm package at an exact version and opens the accepted scan", async () => {
    let input: Schemas["ScanCreate"] | undefined;
    server.use(
      http.post(
        "/api/v1/projects/:projectId/scans",
        async ({ request, params }) => {
          input = (await request.json()) as Schemas["ScanCreate"];
          const scan = makeScan({ project_id: String(params.projectId) });
          db.scans = [scan];
          return HttpResponse.json(
            {
              scan_id: scan.id,
              snapshot_id: scan.snapshot.id,
              status: "queued",
            },
            { status: 202 },
          );
        },
      ),
    );
    const { user, router, dialog } = await openForm();
    await user.type(dialog.getByLabelText("Tên npm"), "@scope/package");
    await user.type(dialog.getByLabelText("Phiên bản"), "1.2.3-beta.1+build.2");
    await user.click(dialog.getByRole("button", { name: "Tạo scan" }));
    expect(
      await mainContent().findByRole("heading", {
        level: 1,
        name: "Chi tiết lượt quét",
      }),
    ).toBeInTheDocument();
    expect(router.state.location.pathname).toBe(`/scans/${db.scans[0].id}`);
    expect(input).toEqual({
      source: {
        kind: "npm",
        package: "@scope/package",
        version: "1.2.3-beta.1+build.2",
      },
      profile: "command-injection-v0.1",
    });
  });

  it.each([
    ["source", "npm", "version"],
    ["source", "npm"],
  ])("attaches a 422 issue at %j to the version field", async (...location) => {
    server.use(
      http.post("/api/v1/projects/:projectId/scans", () =>
        HttpResponse.json(
          {
            detail: [
              {
                loc: ["body", ...location],
                msg: "Value error, npm version must be an exact SemVer version",
                type: "value_error",
              },
            ],
          },
          { status: 422 },
        ),
      ),
    );
    const { user, dialog } = await openForm();
    await user.type(dialog.getByLabelText("Tên npm"), "demo");
    await user.type(dialog.getByLabelText("Phiên bản"), "1.2.3");
    await user.click(dialog.getByRole("button", { name: "Tạo scan" }));
    await waitFor(() =>
      expect(dialog.getByLabelText("Phiên bản")).toHaveAccessibleDescription(
        "Value error, npm version must be an exact SemVer version",
      ),
    );
  });

  it("validates GitHub owner/repo and lowercase 40-character commits before submitting", async () => {
    let received: Schemas["ScanCreate"] | undefined;
    server.use(
      http.post("/api/v1/projects/:projectId/scans", async ({ request }) => {
        received = (await request.json()) as Schemas["ScanCreate"];
        return HttpResponse.json({ detail: "Try again" }, { status: 503 });
      }),
    );
    const { user, dialog } = await openForm();
    await user.click(dialog.getByRole("combobox", { name: "Nguồn" }));
    await user.click(screen.getByRole("option", { name: "GitHub" }));
    await user.type(dialog.getByLabelText("Owner GitHub"), "-owner");
    await user.type(dialog.getByLabelText("Repo GitHub"), "..");
    await user.type(dialog.getByLabelText("Commit"), "A".repeat(40));
    await user.click(dialog.getByRole("button", { name: "Tạo scan" }));
    await waitFor(() =>
      expect(dialog.getByLabelText("Commit")).toHaveAttribute(
        "aria-invalid",
        "true",
      ),
    );
    expect(dialog.getByLabelText("Owner GitHub")).toHaveAttribute(
      "aria-invalid",
      "true",
    );
    expect(dialog.getByLabelText("Repo GitHub")).toHaveAttribute(
      "aria-invalid",
      "true",
    );
    expect(received).toBeUndefined();
    await user.clear(dialog.getByLabelText("Owner GitHub"));
    await user.type(dialog.getByLabelText("Owner GitHub"), "owner");
    await user.clear(dialog.getByLabelText("Repo GitHub"));
    await user.type(dialog.getByLabelText("Repo GitHub"), "repo");
    await user.clear(dialog.getByLabelText("Commit"));
    await user.type(dialog.getByLabelText("Commit"), "a".repeat(40));
    await user.click(dialog.getByRole("button", { name: "Tạo scan" }));
    await dialog.findByText("Try again");
    expect(received?.source).toEqual({
      kind: "github",
      owner: "owner",
      repo: "repo",
      commit: "a".repeat(40),
    });
  });
});
