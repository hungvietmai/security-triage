import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { db, makeScan, makeUnit } from "@/testing/mocks/db";
import {
  mainContent as main,
  makeProject,
  renderApp,
  screen,
  server,
  waitFor,
  within,
} from "@test/support/test-utils";
import type { Schemas } from "@/types/api";

type Family = Schemas["FamilyRead"];

const COMMAND: Family = {
  family: "command-injection",
  cwe: "CWE-78",
  label: "Command injection",
  profile_id: "command-injection-v0.3",
  profile_sha256: "1".repeat(64),
  runs: [
    {
      language: "python",
      status: "completed",
      error: null,
      raw_findings: 2,
      evidence_steps: { "codeql-evidence": "completed" },
    },
  ],
  units: 1,
  review: 1,
  filtered: 0,
  held: 0,
};
const PATH: Family = {
  family: "path-traversal",
  cwe: "CWE-22",
  label: "Path traversal",
  profile_id: "path-traversal-v0.2",
  profile_sha256: "2".repeat(64),
  runs: [
    {
      language: "python",
      status: "completed",
      error: null,
      raw_findings: 3,
      evidence_steps: { "codeql-path-traversal": "completed" },
    },
  ],
  units: 2,
  review: 1,
  filtered: 1,
  held: 0,
};

/** A composite scan: one command unit, one path unit kept and one path unit filtered. */
function seed(overrides: { path?: Partial<Family> } = {}) {
  const scan = makeScan({
    profile: "multi-cwe-v0.1",
    reconciler_version: "family-composition-v0.1",
    policy_version: "family-composition-v0.1",
    unit_counts: { P1: 2, P2: 0, U: 0, P3: 0, P4: 1 },
    disposition_counts: { review: 2, filtered: 1 },
    families: [COMMAND, { ...PATH, ...overrides.path }],
  });
  const command = makeUnit({
    path: "run.py",
    kept_because: ["no_refuting_evidence"],
  });
  const kept = makeUnit({
    path: "read.py",
    sink_kind: "codeql-path-injection-sink",
    argument_role: null,
    shell_state: null,
    analysis_family: "path-traversal",
    cwe: "CWE-22",
    tools: ["codeql"],
    decision_id: "EV_KEPT_NO_PROOF",
    evidence_state: "not_refuted",
    kept_because: ["evidence_query_still_reports_flow"],
    adjudication: {
      status: "kept",
      rule: null,
      rules: [],
      kept_because: ["evidence_query_still_reports_flow"],
      reason: "Truy vấn có bằng chứng an toàn vẫn báo vị trí này.",
      evidence: [],
    },
  });
  kept.findings[0] = {
    ...kept.findings[0],
    tool: "codeql",
    rule_id: "st/cwe-22/none",
    cwe_ids: ["cwe-022"],
    mapped_cwes: ["CWE-22"],
    analysis_family: "path-traversal",
    family_status: "resolved",
    family_basis: "pass_provenance",
    tool_pass: "codeql-path-traversal",
  };
  const hidden = makeUnit({
    path: "safe.py",
    priority: "P4",
    analysis_family: "path-traversal",
    cwe: "CWE-22",
    tools: ["codeql"],
    disposition: "filtered",
    filter_rule: "G1_CODEQL_SAFETY_EVIDENCE",
    evidence_state: "refuted",
  });
  db.scans = [scan];
  db.units[scan.id] = [command, kept, hidden];
  return { scan };
}

describe("A scan with several analysis families", () => {
  it("offers the multi-CWE profile and sends it", async () => {
    let input: Schemas["ScanCreate"] | undefined;
    server.use(
      http.post(
        "/api/v1/projects/:projectId/scans",
        async ({ request, params }) => {
          input = (await request.json()) as Schemas["ScanCreate"];
          const scan = makeScan({
            project_id: String(params.projectId),
            profile: "multi-cwe-v0.1",
          });
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
    const project = makeProject();
    db.projects = [project];
    const { user } = await renderApp(`/projects/${project.id}`);
    await user.click(await main().findByRole("button", { name: "Tạo scan" }));
    const dialog = within(screen.getByRole("dialog", { name: "Tạo scan mới" }));
    await user.click(dialog.getByRole("combobox", { name: "Profile" }));
    await user.click(
      screen.getByRole("option", {
        name: "CWE-78 + CWE-22 · Đa CWE trong một lượt quét",
      }),
    );
    expect(
      dialog.getByText(/dùng chung một database CodeQL/),
    ).toBeInTheDocument();
    await user.type(dialog.getByLabelText("Tên npm"), "demo");
    await user.type(dialog.getByLabelText("Phiên bản"), "1.0.0");
    await user.click(dialog.getByRole("button", { name: "Tạo scan" }));
    await waitFor(() =>
      expect(input).toEqual({
        source: { kind: "npm", package: "demo", version: "1.0.0" },
        profile: "multi-cwe-v0.1",
      }),
    );
  });

  it("shows each family with its profile, run state, evidence steps and dispositions", async () => {
    const { scan } = seed();
    await renderApp(`/scans/${scan.id}`);
    const families = within(
      await main().findByRole("table", {
        name: "Nhóm phân tích của lượt quét",
      }),
    );
    const command = within(
      families.getByRole("row", { name: /CWE-78 · Command injection/ }),
    );
    expect(command.getByText("command-injection-v0.3")).toBeInTheDocument();
    expect(command.getByText("python: completed")).toBeInTheDocument();
    expect(
      command.getByText("python · codeql-evidence: completed"),
    ).toBeInTheDocument();
    const path = within(
      families.getByRole("row", { name: /CWE-22 · Path traversal/ }),
    );
    expect(path.getByText("path-traversal-v0.2")).toBeInTheDocument();
    expect(
      path.getByText("python · codeql-path-traversal: completed"),
    ).toBeInTheDocument();
    // Units 2, main list 1, filtered 1, held 0.
    expect(path.getAllByRole("cell").map((cell) => cell.textContent)).toEqual([
      "CWE-22 · Path traversal",
      "path-traversal-v0.2",
      "python: completed",
      "python · codeql-path-traversal: completed",
      "2",
      "1",
      "1",
      "0",
    ]);

    const table = within(await main().findByRole("table", { name: "Đơn vị" }));
    expect(
      table.getByRole("columnheader", { name: "Nhóm" }),
    ).toBeInTheDocument();
    const kept = within(table.getByRole("row", { name: /read\.py:12/ }));
    expect(kept.getByText("CWE-22")).toBeInTheDocument();
    // The filter decision and the evidence state are separate columns.
    expect(kept.getByText("Danh sách rà chính")).toBeInTheDocument();
    expect(
      kept.getByText("Đã đối chiếu, bằng chứng không bác bỏ"),
    ).toBeInTheDocument();
    const hidden = within(table.getByRole("row", { name: /safe\.py:12/ }));
    expect(hidden.getByText("Bằng chứng bác bỏ cảnh báo")).toBeInTheDocument();
    expect(
      within(table.getByRole("row", { name: /run\.py:12/ })).getByText(
        "CWE-78",
      ),
    ).toBeInTheDocument();
  });

  it("filters the units by family through a shareable link", async () => {
    const { scan } = seed();
    const { user, router } = await renderApp(`/scans/${scan.id}`);
    await main().findByRole("button", { name: "Xem đơn vị run.py:12" });
    await user.click(
      main().getByRole("button", { name: "CWE-22 · Path traversal: 2" }),
    );
    await waitFor(() =>
      expect(router.state.location.search.family).toBe("path-traversal"),
    );
    await waitFor(() =>
      expect(
        main().queryByRole("button", { name: "Xem đơn vị run.py:12" }),
      ).not.toBeInTheDocument(),
    );
    expect(
      main().getByRole("button", { name: "Xem đơn vị read.py:12" }),
    ).toBeInTheDocument();
    expect(
      main().getByRole("button", { name: "Xem đơn vị safe.py:12" }),
    ).toBeInTheDocument();
    // Family and list filters combine.
    await user.click(main().getByRole("button", { name: "Đã gạn: 1" }));
    await waitFor(() =>
      expect(
        main().queryByRole("button", { name: "Xem đơn vị read.py:12" }),
      ).not.toBeInTheDocument(),
    );
    expect(router.state.location.search).toMatchObject({
      family: "path-traversal",
      list: "filtered",
    });
    // Pressing the family again clears only that filter.
    await user.click(
      main().getByRole("button", { name: "CWE-22 · Path traversal: 2" }),
    );
    await waitFor(() =>
      expect(router.state.location.search.family).toBeUndefined(),
    );
  });

  it("reads the family from the URL and ignores an unknown one", async () => {
    const { scan } = seed();
    await renderApp(`/scans/${scan.id}?family=command-injection`);
    await main().findByRole("button", { name: "Xem đơn vị run.py:12" });
    expect(
      main().queryByRole("button", { name: "Xem đơn vị read.py:12" }),
    ).not.toBeInTheDocument();
    expect(
      main().getByRole("button", { name: "CWE-78 · Command injection: 1" }),
    ).toHaveAttribute("aria-pressed", "true");

    const { router } = await renderApp(`/scans/${scan.id}?family=xss`);
    expect(router.state.location.search.family).toBeUndefined();
  });

  it("opens a path unit with its family, evidence state and both kinds of CWE label", async () => {
    const { scan } = seed();
    const { user } = await renderApp(`/scans/${scan.id}`);
    await user.click(
      await main().findByRole("button", { name: "Xem đơn vị read.py:12" }),
    );
    const sheet = within(await screen.findByRole("dialog"));
    expect(
      await sheet.findByText("CWE-22 · Path traversal"),
    ).toBeInTheDocument();
    expect(
      sheet.getByText("Đã đối chiếu, bằng chứng không bác bỏ"),
    ).toBeInTheDocument();
    expect(
      sheet.getByText("Truy vấn bằng chứng vẫn báo luồng này"),
    ).toBeInTheDocument();
    // What the tool wrote and what the pinned rule maps to are shown side by side.
    expect(sheet.getByText("cwe-022")).toBeInTheDocument();
    expect(sheet.getByText("CWE-22")).toBeInTheDocument();
    expect(
      sheet.getByText("path-traversal (pass_provenance)"),
    ).toBeInTheDocument();
    expect(sheet.getByText("codeql-path-traversal")).toBeInTheDocument();
    // Command-call fields are not shown for a path sink.
    expect(sheet.queryByText("Trạng thái shell")).not.toBeInTheDocument();
    expect(sheet.queryByText("Vai trò đối số")).not.toBeInTheDocument();
  });

  it("keeps command-call fields and says when a scan did not classify its alerts", async () => {
    const { scan } = seed();
    const { user } = await renderApp(`/scans/${scan.id}`);
    await user.click(
      await main().findByRole("button", { name: "Xem đơn vị run.py:12" }),
    );
    const sheet = within(await screen.findByRole("dialog"));
    expect(
      await sheet.findByText("CWE-78 · Command injection"),
    ).toBeInTheDocument();
    expect(sheet.getByText("Trạng thái shell")).toBeInTheDocument();
    expect(sheet.getByText("Chưa đủ bằng chứng")).toBeInTheDocument();
    expect(
      sheet.getByText("Không có bằng chứng cụ thể cho thấy cảnh báo sai"),
    ).toBeInTheDocument();
    expect(
      sheet.getByText("Lượt quét này không phân loại"),
    ).toBeInTheDocument();
  });

  it("shows a family that could not rank its alerts as held for review, with the error", async () => {
    const { scan } = seed({
      path: {
        review: 2,
        filtered: 0,
        held: 2,
        runs: [
          {
            language: "python",
            status: "failed",
            error: "ValueError: Unexpected rule in a safety-evidence scan",
            raw_findings: 3,
            evidence_steps: { "codeql-path-traversal": "completed" },
          },
        ],
      },
    });
    const held = makeUnit({
      path: "held.py",
      priority: "U",
      analysis_family: "path-traversal",
      cwe: "CWE-22",
      decision_id: "F10_FAMILY_NOT_RANKED",
      evidence_state: "unavailable",
      kept_because: ["family_not_ranked"],
    });
    db.scans = [{ ...scan, status: "partial", error_message: "python/path" }];
    db.units[scan.id] = [held];
    const { user } = await renderApp(`/scans/${scan.id}`);
    const families = within(
      await main().findByRole("table", {
        name: "Nhóm phân tích của lượt quét",
      }),
    );
    const path = within(
      families.getByRole("row", { name: /CWE-22 · Path traversal/ }),
    );
    expect(path.getByText("python: failed")).toBeInTheDocument();
    expect(
      path.getByText("ValueError: Unexpected rule in a safety-evidence scan"),
    ).toBeInTheDocument();
    const table = within(await main().findByRole("table", { name: "Đơn vị" }));
    const row = within(table.getByRole("row", { name: /held\.py:12/ }));
    expect(row.getByText("Danh sách rà chính")).toBeInTheDocument();
    expect(row.getByText("Không lấy được bằng chứng")).toBeInTheDocument();
    await user.click(
      table.getByRole("button", { name: "Xem đơn vị held.py:12" }),
    );
    const sheet = within(await screen.findByRole("dialog"));
    expect(
      await sheet.findByText("Nhóm phân tích chưa xếp hạng được cảnh báo này"),
    ).toBeInTheDocument();
  });

  it("reports the before/after counts per family", async () => {
    const { scan } = seed();
    await renderApp(`/scans/${scan.id}`);
    const report = within(
      await main().findByRole("region", { name: "Báo cáo trước–sau" }),
    );
    const families = within(
      await report.findByRole("table", {
        name: "Trước–sau theo nhóm phân tích",
      }),
    );
    expect(
      within(families.getByRole("row", { name: /CWE-22 · Path traversal/ }))
        .getAllByRole("cell")
        .map((cell) => cell.textContent),
    ).toEqual(["CWE-22 · Path traversal", "2", "2", "2", "1", "1", "—"]);
    expect(
      within(families.getByRole("row", { name: /CWE-78 · Command injection/ }))
        .getAllByRole("cell")
        .map((cell) => cell.textContent),
    ).toEqual(["CWE-78 · Command injection", "1", "1", "1", "1", "0", "—"]);
  });

  it("shows no family section for a scan that has not produced one", async () => {
    const scan = makeScan();
    db.scans = [scan];
    db.units[scan.id] = [makeUnit()];
    await renderApp(`/scans/${scan.id}`);
    await main().findByRole("table", { name: "Đơn vị" });
    expect(
      main().queryByRole("region", { name: "Nhóm phân tích" }),
    ).not.toBeInTheDocument();
  });

  it("offers the three-family profile and says SQL injection is only detected and kept", async () => {
    const project = makeProject();
    db.projects = [project];
    const { user } = await renderApp(`/projects/${project.id}`);
    await user.click(await main().findByRole("button", { name: "Tạo scan" }));
    const dialog = within(screen.getByRole("dialog", { name: "Tạo scan mới" }));
    await user.click(dialog.getByRole("combobox", { name: "Profile" }));
    await user.click(
      screen.getByRole("option", {
        name: "CWE-78 + CWE-22 + CWE-89 · Đa CWE, SQL injection chỉ phát hiện và giữ",
      }),
    );
    expect(dialog.getByText(/chưa được xếp hạng hay gạn/)).toBeInTheDocument();
  });

  it("shows a SQL injection unit as kept for review with no evidence to weigh", async () => {
    const sql: Family = {
      family: "sql-injection",
      cwe: "CWE-89",
      label: "SQL injection",
      profile_id: "sql-injection-v0.1",
      profile_sha256: "3".repeat(64),
      runs: [
        {
          language: "python",
          status: "completed",
          error: null,
          raw_findings: 1,
          evidence_steps: {},
        },
      ],
      units: 1,
      review: 1,
      filtered: 0,
      held: 0,
    };
    const scan = makeScan({
      profile: "multi-cwe-v0.2",
      reconciler_version: "family-composition-v0.1",
      policy_version: "family-composition-v0.1",
      unit_counts: { P1: 1, P2: 0, U: 1, P3: 0, P4: 0 },
      disposition_counts: { review: 2, filtered: 0 },
      families: [COMMAND, sql],
    });
    const command = makeUnit({ path: "run.py" });
    const query = makeUnit({
      path: "query.py",
      priority: "U",
      sink_kind: "codeql-reported-sink",
      argument_role: null,
      shell_state: null,
      analysis_family: "sql-injection",
      cwe: "CWE-89",
      tools: ["codeql"],
      decision_id: "K10_DETECTED_KEPT",
      evidence_state: "insufficient",
      kept_because: ["no_filter_condition_for_family"],
      adjudication: {
        status: "kept",
        rule: null,
        rules: [],
        kept_because: ["no_filter_condition_for_family"],
        reason: "Nhóm phân tích này chưa có điều kiện gạn nào đã được đo.",
        evidence: [],
      },
    });
    query.findings[0] = {
      ...query.findings[0],
      tool: "codeql",
      rule_id: "py/sql-injection",
      cwe_ids: ["cwe-089"],
      mapped_cwes: ["CWE-89"],
      analysis_family: "sql-injection",
      family_status: "resolved",
      family_basis: "pass_provenance",
      tool_pass: "codeql-sql-injection",
    };
    db.scans = [scan];
    db.units[scan.id] = [command, query];

    const { user } = await renderApp(`/scans/${scan.id}?family=sql-injection`);
    expect(
      await main().findByRole("button", { name: "CWE-89 · SQL injection: 1" }),
    ).toHaveAttribute("aria-pressed", "true");
    expect(
      main().queryByRole("button", { name: "Xem đơn vị run.py:12" }),
    ).not.toBeInTheDocument();
    await user.click(
      await main().findByRole("button", { name: "Xem đơn vị query.py:12" }),
    );
    const sheet = within(await screen.findByRole("dialog"));
    expect(
      await sheet.findByText("CWE-89 · SQL injection"),
    ).toBeInTheDocument();
    expect(sheet.getByText("Chưa đủ bằng chứng")).toBeInTheDocument();
    expect(
      sheet.getByText(
        "Nhóm này chỉ phát hiện và giữ: chưa có điều kiện gạn nào được đo",
      ),
    ).toBeInTheDocument();
    expect(sheet.getByText("cwe-089")).toBeInTheDocument();
    expect(
      sheet.getByText("Nằm trong danh sách rà chính."),
    ).toBeInTheDocument();
  });
});
