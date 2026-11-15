import { describe, expect, it } from "vitest";
import { db, makeScan, makeUnit } from "@/testing/mocks/db";
import {
  mainContent as main,
  renderApp,
  screen,
  waitFor,
  within,
} from "@test/support/test-utils";

const REASON =
  "Đã gạn khỏi danh sách rà chính: truy vấn có bằng chứng an toàn không còn báo luồng nào.";

function seed() {
  const scan = makeScan({
    unit_counts: { P1: 1, P2: 0, U: 0, P3: 1, P4: 0 },
    disposition_counts: { review: 1, filtered: 1 },
  });
  const kept = makeUnit({ path: "kept.py", priority: "P3", tools: ["bandit"] });
  const filtered = makeUnit({
    path: "gone.py",
    tools: ["semgrep", "codeql"],
    disposition: "filtered",
    filter_rule: "G1_CODEQL_SAFETY_EVIDENCE",
    adjudication: {
      status: "filtered",
      rule: "G1_CODEQL_SAFETY_EVIDENCE",
      reason: REASON,
      kept_because: [],
      evidence: [
        { tool: "codeql-safety-evidence", refuted_raw_ids: ["codeql:0:0"] },
      ],
    },
    candidate: {
      key: "call-1",
      basis: "same_call_site",
      unit_ids: ["unit-a", "unit-b"],
      tools: ["codeql", "semgrep"],
      priority: "P1",
    },
  });
  db.scans = [scan];
  db.units[scan.id] = [kept, filtered];
  return { scan };
}

describe("Adjudication on the scan page", () => {
  it("lists filtered units separately and reopens the original alert with its reason", async () => {
    const { scan } = seed();
    const { user, router } = await renderApp(`/scans/${scan.id}`);
    await main().findByRole("button", { name: "Xem đơn vị kept.py:12" });
    // Both units are listed until a list is chosen: nothing is hidden by default.
    expect(
      main().getByRole("button", { name: "Xem đơn vị gone.py:12" }),
    ).toBeInTheDocument();

    await user.click(main().getByRole("button", { name: "Đã gạn: 1" }));
    await waitFor(() =>
      expect(router.state.location.search.list).toBe("filtered"),
    );
    const table = within(await main().findByRole("table", { name: "Đơn vị" }));
    await waitFor(() =>
      expect(
        table.queryByRole("button", { name: "Xem đơn vị kept.py:12" }),
      ).not.toBeInTheDocument(),
    );
    expect(
      table.getByText("Đã gạn: Bằng chứng an toàn của CodeQL loại hết luồng"),
    ).toBeInTheDocument();

    await user.click(
      table.getByRole("button", { name: "Xem đơn vị gone.py:12" }),
    );
    const sheet = within(await screen.findByRole("dialog"));
    expect(
      await sheet.findByText(
        "Đã gạn khỏi danh sách rà chính. Cảnh báo gốc vẫn được giữ ở bên dưới.",
      ),
    ).toBeInTheDocument();
    expect(sheet.getByText(REASON)).toBeInTheDocument();
    expect(
      sheet.getByText(/Cùng một lời gọi với 1 đơn vị khác/),
    ).toBeInTheDocument();
    expect(sheet.getByText(/refuted_raw_ids/)).toBeInTheDocument();
    // The original alert of the filtered unit is still there to read.
    expect(sheet.getByText("User input reaches a command")).toBeInTheDocument();
  });

  it("shows the main list with why a unit was kept", async () => {
    const { scan } = seed();
    const { user } = await renderApp(`/scans/${scan.id}?list=review`);
    const table = within(await main().findByRole("table", { name: "Đơn vị" }));
    await table.findByRole("button", { name: "Xem đơn vị kept.py:12" });
    expect(
      table.queryByRole("button", { name: "Xem đơn vị gone.py:12" }),
    ).not.toBeInTheDocument();
    expect(
      main().getByRole("button", { name: "Danh sách rà chính: 1" }),
    ).toHaveAttribute("aria-pressed", "true");
    await user.click(
      table.getByRole("button", { name: "Xem đơn vị kept.py:12" }),
    );
    const sheet = within(await screen.findByRole("dialog"));
    expect(
      await sheet.findByText("Nằm trong danh sách rà chính."),
    ).toBeInTheDocument();
  });

  it("counts evidence results and unranked alerts apart from the alerts", async () => {
    const { scan } = seed();
    db.results[scan.id] = { evidence_results: 4, unranked_alerts: 3 };
    await renderApp(`/scans/${scan.id}`);
    const report = within(
      await main().findByRole("region", { name: "Báo cáo trước–sau" }),
    );
    const stages = within(
      await report.findByRole("table", { name: "Các bước của quy trình" }),
    );
    // Two units and one more alert, plus the three alerts no unit holds.
    expect(
      within(
        stages.getByRole("row", { name: /Cảnh báo của các công cụ phát hiện/ }),
      ).getByText("6"),
    ).toBeInTheDocument();
    expect(
      within(
        stages.getByRole("row", { name: /Kết quả của truy vấn bằng chứng/ }),
      ).getByText("4"),
    ).toBeInTheDocument();
    expect(
      within(
        stages.getByRole("row", { name: /Cảnh báo chưa xếp hạng/ }),
      ).getByText("3"),
    ).toBeInTheDocument();
  });

  it("leaves the exception rows out when there is nothing to report", async () => {
    const { scan } = seed();
    await renderApp(`/scans/${scan.id}`);
    const report = within(
      await main().findByRole("region", { name: "Báo cáo trước–sau" }),
    );
    const stages = within(
      await report.findByRole("table", { name: "Các bước của quy trình" }),
    );
    expect(
      stages.getByRole("row", { name: /Cảnh báo của các công cụ phát hiện/ }),
    ).toBeInTheDocument();
    expect(
      stages.queryByRole("row", { name: /Kết quả của truy vấn bằng chứng/ }),
    ).not.toBeInTheDocument();
    expect(
      stages.queryByRole("row", { name: /Cảnh báo chưa xếp hạng/ }),
    ).not.toBeInTheDocument();
  });

  it("renders the before/after report with export links", async () => {
    const { scan } = seed();
    await renderApp(`/scans/${scan.id}`);
    const report = within(
      await main().findByRole("region", { name: "Báo cáo trước–sau" }),
    );
    const stages = within(
      await report.findByRole("table", { name: "Các bước của quy trình" }),
    );
    expect(
      within(
        stages.getByRole("row", { name: /Danh sách rà chính sau khi gạn/ }),
      ).getByText("1"),
    ).toBeInTheDocument();
    expect(
      within(
        stages.getByRole("row", { name: /Đã gạn vì thỏa điều kiện gạn/ }),
      ).getByText("1"),
    ).toBeInTheDocument();
    const sources = within(
      report.getByRole("table", { name: "Đóng góp của từng công cụ" }),
    );
    // Bandit alone reported kept.py: a candidate no other tool contributed.
    expect(
      within(sources.getByRole("row", { name: /bandit/ })).getAllByText("1"),
    ).toHaveLength(2);
    expect(
      report.getByText("Bằng chứng an toàn của CodeQL loại hết luồng"),
    ).toBeInTheDocument();
    expect(report.getByText("12.3")).toBeInTheDocument();

    const json = report.getByRole("link", { name: "Tải báo cáo JSON" });
    expect(json).toHaveAttribute("download", `scan-report-${scan.id}.json`);
    expect(decodeURIComponent(json.getAttribute("href") ?? "")).toContain(
      '"filtered": 1',
    );
    expect(
      report.getByRole("link", { name: "Tải SARIF hợp nhất" }),
    ).toHaveAttribute("href", `/api/v1/scans/${scan.id}/report.sarif`);
  });
});
