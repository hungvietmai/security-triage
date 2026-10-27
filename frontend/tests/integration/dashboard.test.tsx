import { describe, expect, it } from "vitest";
import {
  db,
  mainContent as main,
  makeProject,
  renderApp,
} from "@test/support/test-utils";

describe("Dashboard", () => {
  it("shows the project count and the five most recent projects", async () => {
    db.projects = Array.from({ length: 7 }, () => makeProject());
    await renderApp("/");

    expect(await main().findByText("Dự án 1")).toBeInTheDocument();
    expect(main().getByText("Dự án 5")).toBeInTheDocument();
    expect(main().queryByText("Dự án 6")).not.toBeInTheDocument();
    expect(main().getByText("7")).toBeInTheDocument();
  });

  it("does not invent numbers the API cannot provide", async () => {
    await renderApp("/");
    await main().findByText("Chưa có dự án");
    expect(main().getAllByText(/^Chưa có API thống kê/)).toHaveLength(3);
  });

  it("marks only the unintegrated pipeline step as missing", async () => {
    await renderApp("/");
    await main().findByText("Chưa có dự án");
    expect(main().getAllByText("Chưa có", { exact: true })).toHaveLength(1);
    expect(main().getByText("Bằng chứng an toàn CWE-22")).toBeInTheDocument();
  });
});
