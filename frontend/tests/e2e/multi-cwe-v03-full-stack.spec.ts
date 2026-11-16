import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";

/**
 * The three-family profile with three CWE-89 tools (Semgrep, Bandit, CodeQL) against the
 * COMPLETE stack (Nginx, API, worker with the real scanners, PostgreSQL, object store). Like
 * the other full-stack tests it needs a running stack and network access for the worker, and
 * is skipped unless FULL_STACK_URL names the frontend:
 *
 *   FULL_STACK_URL=http://127.0.0.1:5173 FULL_STACK_OUTPUT=../artifacts/e2e-v03 \
 *     npx playwright test multi-cwe-v03-full-stack
 *
 * The source is development data without labels, the same PyGoat commit as the v0.2 test:
 * there CodeQL and Semgrep report inside one SQL execution call, so one unit holds both.
 * Nothing of the scanned source is executed.
 */
const stack = process.env.FULL_STACK_URL;
const output = process.env.FULL_STACK_OUTPUT;
const SOURCE = {
  owner: "adeyosemanputra",
  repo: "pygoat",
  commit: "2aa4cc14f251e4a780e94e200aed6b36a5b15c21",
};
const PROFILE_LABEL =
  "CWE-78 + CWE-22 + CWE-89 · SQL injection bằng Semgrep, Bandit và CodeQL";
const SQL_PASSES = [
  "bandit-sql-injection",
  "codeql-sql-injection",
  "semgrep-sql-injection",
];

type UnitDetail = {
  id: string;
  analysis_family: string | null;
  path: string | null;
  start_line: number | null;
  sink_kind: string | null;
  tools: string[];
  disposition: string;
  evidence_state: string;
  findings: { tool_pass: string | null; rule_id: string }[];
};

function save(name: string, content: string) {
  if (!output) return;
  mkdirSync(output, { recursive: true });
  writeFileSync(join(output, name), content, "utf-8");
}

test.describe("three-family scan with three CWE-89 tools on the complete stack", () => {
  test.skip(!stack, "Set FULL_STACK_URL to a running stack to run this test");
  test.setTimeout(40 * 60_000);

  test("creates a multi-cwe-v0.3 scan from the UI, merges only within one SQL call and keeps every SQL alert", async ({
    page,
  }) => {
    const api = `${stack}/api/v1`;
    const created = await page.request.post(`${api}/projects`, {
      data: { name: `Đa CWE v0.3 E2E ${new Date().toISOString()}` },
    });
    expect(created.status()).toBe(201);
    const project = (await created.json()) as { id: string };

    // Create the scan through the form: profile, GitHub source, submit.
    await page.goto(`${stack}/projects/${project.id}`);
    const main = page.getByRole("main");
    await main.getByRole("button", { name: "Tạo scan" }).click();
    const dialog = page.getByRole("dialog", { name: "Tạo scan mới" });
    await dialog.getByRole("combobox", { name: "Profile" }).click();
    await page.getByRole("option", { name: PROFILE_LABEL }).click();
    await expect(
      dialog.getByText(/chỉ được gộp khi cùng nằm trong một lời gọi/),
    ).toBeVisible();
    await dialog.getByRole("combobox", { name: "Nguồn" }).click();
    await page.getByRole("option", { name: "GitHub" }).click();
    await dialog.getByLabel("Owner GitHub").fill(SOURCE.owner);
    await dialog.getByLabel("Repo GitHub").fill(SOURCE.repo);
    await dialog.getByLabel("Commit").fill(SOURCE.commit);
    await dialog.getByRole("button", { name: "Tạo scan", exact: true }).click();
    await expect(page).toHaveURL(/\/scans\/[0-9a-f-]{36}/);
    const scanId = new URL(page.url()).pathname.split("/").pop()!;

    // The page polls until the worker has scanned, persisted and the families appear.
    const families = main.getByRole("table", {
      name: "Nhóm phân tích của lượt quét",
    });
    await expect(families).toBeVisible({ timeout: 35 * 60_000 });
    const scan = (await (
      await page.request.get(`${api}/scans/${scanId}`)
    ).json()) as {
      status: string;
      profile: string;
      tool_runs: { tool: string; language: string; status: string }[];
      families: {
        family: string;
        profile_id: string;
        units: number;
        review: number;
        filtered: number;
        runs: { language: string; status: string }[];
      }[];
    };
    save("scan.json", JSON.stringify(scan, null, 2));
    expect(scan.profile).toBe("multi-cwe-v0.3");
    expect(scan.status).toBe("completed");
    expect(scan.families.map((family) => family.family)).toEqual([
      "command-injection",
      "path-traversal",
      "sql-injection",
    ]);
    const sql = scan.families[2];
    expect(sql.profile_id).toBe("sql-injection-v0.2");
    expect(sql.units).toBeGreaterThan(0);
    // Detected and kept: every SQL unit is in the review list.
    expect(sql.review).toBe(sql.units);
    expect(sql.filtered).toBe(0);
    // Each CWE-89 tool ran as a pass of its own on Python.
    const pythonPasses = scan.tool_runs
      .filter(
        (run) =>
          run.language === "python" && run.tool.endsWith("-sql-injection"),
      )
      .map((run) => [run.tool, run.status]);
    expect(pythonPasses.sort()).toEqual(
      SQL_PASSES.map((name) => [name, "completed"]),
    );

    const sqlRow = families.getByRole("row", {
      name: /CWE-89 · SQL injection/,
    });
    await expect(sqlRow).toContainText("sql-injection-v0.2");
    await expect(sqlRow).toContainText("python: completed");

    // Filter by CWE-89 through the family button; every SQL unit is in the review list.
    await main
      .getByRole("button", {
        name: new RegExp(`^CWE-89 · SQL injection: ${sql.units}$`),
      })
      .click();
    await expect(page).toHaveURL(/family=sql-injection/);
    const units = main.getByRole("table", { name: "Đơn vị", exact: true });
    const rows = units.getByRole("row").filter({ hasText: "CWE-89" });
    await expect(rows).toHaveCount(sql.units);
    for (const text of await rows.allInnerTexts()) {
      expect(text).toContain("Danh sách rà chính");
      expect(text).toContain("Chưa đủ bằng chứng");
    }

    // The unit where two tools report inside one SQL execution call holds both alerts.
    const listed = (await (
      await page.request.get(`${api}/scans/${scanId}/units?limit=100`)
    ).json()) as { items: { id: string }[] };
    const details: UnitDetail[] = [];
    for (const item of listed.items) {
      details.push(
        (await (
          await page.request.get(`${api}/scans/${scanId}/units/${item.id}`)
        ).json()) as UnitDetail,
      );
    }
    const sqlUnits = details.filter(
      (unit) => unit.analysis_family === "sql-injection",
    );
    save("sql-units.json", JSON.stringify(sqlUnits, null, 2));
    const merged = sqlUnits.filter((unit) => unit.tools.length > 1);
    expect(merged.length).toBeGreaterThan(0);
    for (const unit of merged)
      expect(unit.sink_kind).toBe("sql-execution-call");
    // Alerts of different tools outside one located call are never in one unit.
    for (const unit of sqlUnits.filter(
      (unit) => unit.sink_kind !== "sql-execution-call",
    ))
      expect(unit.tools).toHaveLength(1);

    const target = merged[0];
    await units
      .getByRole("button", {
        name: `Xem đơn vị ${target.path}:${target.start_line}`,
      })
      .click();
    const sheet = page.getByRole("dialog", { name: "Chi tiết đơn vị" });
    await expect(sheet.getByText("CWE-89 · SQL injection")).toBeVisible();
    await expect(sheet.getByText("Chưa đủ bằng chứng")).toBeVisible();
    await expect(
      sheet.getByText(/được gộp thành một mục/).first(),
    ).toBeVisible();
    await expect(
      sheet.getByText(`công cụ đã báo: ${target.tools.join(", ")}`, {
        exact: false,
      }),
    ).toBeVisible();
    for (const pass of new Set(
      target.findings.map((finding) => finding.tool_pass!),
    ))
      await expect(
        sheet.getByText(pass, { exact: true }).first(),
      ).toBeVisible();
    if (output) await page.screenshot({ path: join(output, "unit.png") });
    await sheet.getByRole("button", { name: "Đóng chi tiết" }).click();

    // The before/after report: the SQL family has alerts and no filtered candidate.
    await page.goto(`${stack}/scans/${scanId}`);
    const report = main.getByRole("region", { name: "Báo cáo trước–sau" });
    const jsonHref = await report
      .getByRole("link", { name: "Tải báo cáo JSON" })
      .getAttribute("href");
    const exported = JSON.parse(
      decodeURIComponent(jsonHref!.replace(/^data:[^,]*,/, "")),
    ) as {
      profile: string;
      stages: Record<string, number>;
      raw_alerts: Record<string, number>;
      families: {
        family: string;
        raw_alerts: number;
        detection_alerts: number;
        evidence_results: number;
        units: number;
        main_list: number;
        filtered: number;
      }[];
      composition: { members: { profile_id: string }[] };
    };
    save("report.json", JSON.stringify(exported, null, 2));
    expect(exported.profile).toBe("multi-cwe-v0.3");
    expect(exported.composition.members.map((m) => m.profile_id)).toEqual([
      "command-injection-v0.3",
      "path-traversal-v0.2",
      "sql-injection-v0.2",
    ]);
    const sqlReport = exported.families.find(
      (family) => family.family === "sql-injection",
    )!;
    expect(sqlReport.raw_alerts).toBe(
      SQL_PASSES.reduce(
        (sum, name) => sum + (exported.raw_alerts[name] ?? 0),
        0,
      ),
    );
    expect(sqlReport.detection_alerts).toBe(sqlReport.raw_alerts);
    expect(sqlReport.units).toBe(sqlUnits.length);
    // Merging only ever lowers the count: never more units than alerts.
    expect(sqlReport.units).toBeLessThanOrEqual(sqlReport.raw_alerts);
    expect(sqlReport.main_list).toBe(sqlReport.units);
    expect(sqlReport.filtered).toBe(0);
    expect(exported.stages.unranked_alerts).toBe(0);
    expect(
      exported.families.reduce((sum, family) => sum + family.raw_alerts, 0),
    ).toBe(exported.stages.raw_alerts);

    // The SARIF export: every stored result, each CWE-89 result under its own pass, with its
    // own rule and CWE label, in the review list and never suppressed.
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      report.getByRole("link", { name: "Tải SARIF hợp nhất" }).click(),
    ]);
    expect(download.suggestedFilename()).toBe(`scan-${scanId}.sarif`);
    if (output) await download.saveAs(join(output, "report.sarif"));
    const sarif = (await (
      await page.request.get(`${api}/scans/${scanId}/report.sarif`)
    ).json()) as {
      runs: {
        tool: { driver: { name: string } };
        results: {
          ruleId: string;
          suppressions?: unknown[];
          properties: {
            securityTriage: {
              analysisFamily: string;
              cwe: string;
              disposition: string;
              ranked: boolean;
              resultRole: string;
              reportedCwes: string[];
              mappedCwes: string[];
            };
          };
        }[];
      }[];
    };
    const results = sarif.runs.flatMap((run) => run.results);
    expect(results.length).toBe(exported.stages.raw_alerts);
    const sqlRuns = sarif.runs.filter((run) =>
      SQL_PASSES.includes(run.tool.driver.name),
    );
    expect(
      new Set(sqlRuns.map((run) => run.tool.driver.name)).size,
    ).toBeGreaterThan(1);
    const sqlResults = sqlRuns.flatMap((run) =>
      run.results.map((result) => ({ pass: run.tool.driver.name, result })),
    );
    expect(sqlResults.length).toBe(sqlReport.raw_alerts);
    for (const { pass, result } of sqlResults) {
      const triage = result.properties.securityTriage;
      expect(triage.analysisFamily).toBe("sql-injection");
      expect(triage.cwe).toBe("CWE-89");
      expect(triage.mappedCwes).toEqual(["CWE-89"]);
      expect(triage.reportedCwes.length).toBeGreaterThan(0);
      expect(triage.disposition).toBe("review");
      expect(triage.ranked).toBe(true);
      expect(triage.resultRole).toBe("detection");
      expect(result.suppressions).toBeUndefined();
      if (pass === "bandit-sql-injection")
        expect(["B608", "B610", "B611"]).toContain(result.ruleId);
      if (pass === "codeql-sql-injection")
        expect(result.ruleId).toMatch(/^(py|js)\/sql-injection$/);
      // The upstream rule's own ID, not the scan's temporary staging folder.
      if (pass === "semgrep-sql-injection")
        expect(result.ruleId).not.toMatch(/^tmp\.|-rules\.r\d+\./);
    }
    save(
      "summary.json",
      JSON.stringify(
        {
          scanId,
          status: scan.status,
          families: scan.families,
          stages: exported.stages,
          sqlReport,
          sqlUnits: sqlUnits.length,
          mergedUnits: merged.length,
          sarifResults: results.length,
          sarifSqlResults: sqlResults.length,
        },
        null,
        2,
      ),
    );
    if (output)
      await page.screenshot({ path: join(output, "scan.png"), fullPage: true });
  });
});
