import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { db, makeScan, makeUnit } from "@/testing/mocks/db";
import {
  mainContent as main,
  renderApp,
  screen,
  server,
  waitFor,
  within,
} from "@test/support/test-utils";

function seed() {
  const scan = makeScan({ unit_counts: { P1: 1, P2: 1, U: 1, P3: 0, P4: 0 } });
  const units = [
    makeUnit({ path: "first.js" }),
    makeUnit({ priority: "P2", path: "second.js", tools: ["semgrep"] }),
    makeUnit({ priority: "U", path: "third.js", tools: ["codeql"] }),
  ];
  db.scans = [scan];
  db.units[scan.id] = units;
  return { scan, units };
}

describe("Scan detail", () => {
  it("renders provenance, versions, decision columns and tier counts", async () => {
    const { scan } = seed();
    await renderApp(`/scans/${scan.id}`);
    const table = within(await main().findByRole("table", { name: "Đơn vị" }));
    expect(main().getByText("tin lần tải đầu")).toBeInTheDocument();
    expect(main().getByText(scan.snapshot.sha256!)).toBeInTheDocument();
    expect(
      main().getByText(/semgrep · javascript · phiên bản 1.2.3/),
    ).toBeInTheDocument();
    expect(
      main().getByText(/codeql · javascript · phiên bản 2.3.4/),
    ).toBeInTheDocument();
    expect(main().getByRole("button", { name: "P1: 1" })).toBeInTheDocument();
    expect(
      table.getByRole("columnheader", { name: "decision_id" }),
    ).toBeInTheDocument();
    expect(table.getAllByText("D01")).toHaveLength(3);
    expect(table.getByLabelText("Không có cảnh báo CodeQL")).toHaveTextContent(
      "✗",
    );
  });

  it("reads tier and tool from the URL and changes both filters through shareable links", async () => {
    const { scan } = seed();
    const { user, router } = await renderApp(
      `/scans/${scan.id}?tier=P2&tool=semgrep`,
    );
    await main().findByRole("button", { name: "Xem đơn vị second.js:12" });
    expect(
      main().queryByRole("button", { name: "Xem đơn vị first.js:12" }),
    ).not.toBeInTheDocument();
    expect(
      main().getByRole("combobox", { name: "Mức ưu tiên" }),
    ).toHaveTextContent("P2");
    expect(main().getByRole("combobox", { name: "Công cụ" })).toHaveTextContent(
      "semgrep",
    );
    await user.click(main().getByRole("button", { name: "P1: 1" }));
    await main().findByRole("button", { name: "Xem đơn vị first.js:12" });
    expect(router.state.location.search).toMatchObject({
      tier: "P1",
      tool: "semgrep",
      page: 1,
    });
    await user.click(main().getByRole("combobox", { name: "Công cụ" }));
    await user.click(screen.getByRole("option", { name: "codeql" }));
    await waitFor(() =>
      expect(router.state.location.search.tool).toBe("codeql"),
    );
    await user.click(main().getByRole("button", { name: "U: 1" }));
    await main().findByRole("button", { name: "Xem đơn vị third.js:12" });
    expect(
      main().queryByRole("button", { name: "Xem đơn vị first.js:12" }),
    ).not.toBeInTheDocument();
    expect(router.state.location.href).toContain("tier=U");
    expect(router.state.location.href).toContain("tool=codeql");
  });

  it("paginates units and resets the page when a filter changes", async () => {
    const { scan } = seed();
    db.units[scan.id] = Array.from({ length: 21 }, (_, index) =>
      makeUnit({ path: `file-${index}.js` }),
    );
    const { user, router } = await renderApp(`/scans/${scan.id}?page=2`);
    await main().findByRole("button", { name: "Xem đơn vị file-20.js:12" });
    expect(
      main().queryByRole("button", { name: "Xem đơn vị file-0.js:12" }),
    ).not.toBeInTheDocument();
    await user.click(main().getByRole("button", { name: "Trang trước" }));
    await main().findByRole("button", { name: "Xem đơn vị file-0.js:12" });
    await user.click(main().getByRole("button", { name: "Trang sau" }));
    await main().findByRole("button", { name: "Xem đơn vị file-20.js:12" });
    await user.click(main().getByRole("button", { name: "P1: 1" }));
    await main().findByRole("button", { name: "Xem đơn vị file-0.js:12" });
    expect(router.state.location.search.page).toBe(1);
  });

  it("defaults invalid search params and shows failed reasons without fetching an empty table", async () => {
    const { scan } = seed();
    scan.status = "failed";
    scan.error_message = "Archive integrity mismatch";
    let unitRequests = 0;
    server.use(
      http.get("/api/v1/scans/:scanId/units", () => {
        unitRequests++;
        return HttpResponse.json({ items: [] });
      }),
    );
    const { router } = await renderApp(
      `/scans/${scan.id}?page=-1&tier=PX&tool=other`,
    );
    expect(
      await main().findByText("Archive integrity mismatch"),
    ).toBeInTheDocument();
    expect(router.state.location.search).toEqual({ page: 1 });
    expect(main().queryByRole("table")).not.toBeInTheDocument();
    expect(unitRequests).toBe(0);
  });

  it("shows partial tool failures alongside the available units", async () => {
    const { scan } = seed();
    scan.status = "partial";
    scan.tool_runs[1] = {
      ...scan.tool_runs[1],
      status: "failed",
      error_message: "CodeQL database failed",
    };
    await renderApp(`/scans/${scan.id}`);
    await main().findByRole("table", { name: "Đơn vị" });
    expect(main().getByText("Scan hoàn thành một phần")).toBeInTheDocument();
    expect(main().getByText("CodeQL database failed")).toBeInTheDocument();
  });

  it("opens decision evidence and every code/thread flow from a row", async () => {
    const { scan, units } = seed();
    units[0].blocker_proof = { id: "proof", expression: "echo hello" };
    units[0].findings[0].raw_result = {
      codeFlows: [
        {
          threadFlows: [
            {
              locations: [
                {
                  location: {
                    physicalLocation: {
                      artifactLocation: { uri: "input.js" },
                      region: { startLine: 2 },
                    },
                    message: { text: "User input" },
                  },
                },
                {
                  location: {
                    physicalLocation: {
                      artifactLocation: { uri: "first.js" },
                      region: { startLine: 12 },
                    },
                    message: { text: "Command sink" },
                  },
                },
              ],
            },
            {
              locations: [
                {
                  location: {
                    physicalLocation: {
                      artifactLocation: { uri: "helper.js" },
                      region: { startLine: 4 },
                    },
                    message: { text: "Second thread" },
                  },
                },
              ],
            },
          ],
        },
        {
          threadFlows: [
            {
              locations: [
                {
                  location: {
                    physicalLocation: {
                      artifactLocation: { uri: "other.js" },
                      region: { startLine: 9 },
                    },
                    message: { text: "Other flow" },
                  },
                },
              ],
            },
          ],
        },
      ],
    };
    const { user } = await renderApp(`/scans/${scan.id}`);
    await user.click(
      await main().findByRole("button", { name: "Xem đơn vị first.js:12" }),
    );
    const panel = within(
      await screen.findByRole("dialog", { name: "Chi tiết đơn vị" }),
    );
    expect(
      await panel.findByText("input.js:2 – User input"),
    ).toBeInTheDocument();
    expect(panel.getByText("first.js:12 – Command sink")).toBeInTheDocument();
    expect(panel.getByText("helper.js:4 – Second thread")).toBeInTheDocument();
    expect(panel.getByText("other.js:9 – Other flow")).toBeInTheDocument();
    expect(panel.getAllByRole("list")).toHaveLength(3);
    expect(panel.getByText("absent")).toBeInTheDocument();
    expect(
      panel.getByText("source_library_input_or_unknown"),
    ).toBeInTheDocument();
    expect(panel.getByText("blocker_proof")).toBeInTheDocument();
    const predicates = within(
      panel.getByRole("table", { name: "predicate_values" }),
    );
    expect(predicates.getByText("Đúng")).toBeInTheDocument();
    expect(predicates.getByText("Sai")).toBeInTheDocument();
    expect(panel.getByText(units[0].policy_sha256)).toBeInTheDocument();
    expect(panel.getByText(units[0].spec_sha256)).toBeInTheDocument();
  });

  it.each([
    {},
    { codeFlows: [] },
    { codeFlows: [{ threadFlows: [{ locations: [] }] }] },
    { codeFlows: [null, { threadFlows: "broken" }] },
  ])(
    "explicitly reports missing traces for raw result %j",
    async (rawResult) => {
      const { scan, units } = seed();
      units[0].findings[0].raw_result = rawResult;
      const { user } = await renderApp(`/scans/${scan.id}`);
      await user.click(
        await main().findByRole("button", { name: "Xem đơn vị first.js:12" }),
      );
      const panel = within(
        await screen.findByRole("dialog", { name: "Chi tiết đơn vị" }),
      );
      expect(
        await panel.findByText("công cụ không cung cấp vết"),
      ).toBeInTheDocument();
      expect(
        panel.getByText("Thiếu vết không có nghĩa là an toàn."),
      ).toBeInTheDocument();
    },
  );
});
