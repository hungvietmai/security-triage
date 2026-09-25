import { describe, expect, it } from "vitest";
import {
  db,
  mainContent as main,
  makeProject,
  renderApp,
} from "@/testing/test-utils";

describe("Dashboard", () => {
  it("shows the project count and the five most recent projects", async () => {
    db.projects = Array.from({ length: 7 }, () => makeProject());
    await renderApp("/");

    expect(await main().findByText("Dự án 1")).toBeInTheDocument();
    expect(main().getByText("Dự án 5")).toBeInTheDocument();
    expect(main().queryByText("Dự án 6")).not.toBeInTheDocument();
    expect(main().getByText("7")).toBeInTheDocument();
  });

  it("does not invent numbers for features that do not exist yet", async () => {
    await renderApp("/");
    await main().findByText("Chưa có dự án");
    expect(
      main().getByText("Chưa triển khai nạp mã nguồn"),
    ).toBeInTheDocument();
    expect(main().getByText("Chưa triển khai thẩm định")).toBeInTheDocument();
  });
});
