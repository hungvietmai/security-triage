import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";

/**
 * The three-family profile against the COMPLETE stack (Nginx, API, worker with the real
 * scanners, PostgreSQL, object store). Like multi-cwe-full-stack.spec.ts it needs a running
 * stack and network access for the worker, and is skipped unless FULL_STACK_URL names the
 * frontend:
 *
 *   FULL_STACK_URL=http://127.0.0.1:5173 FULL_STACK_OUTPUT=../artifacts/e2e-v02 \
 *     npx playwright test multi-cwe-v02-full-stack
 *
 * The source is development data in which all three families report on real code: PyGoat at
 * a pinned commit. Nothing of the scanned source is executed.
 */
const stack = process.env.FULL_STACK_URL;
const output = process.env.FULL_STACK_OUTPUT;
const SOURCE = {
  owner: "adeyosemanputra",
  repo: "pygoat",
  commit: "2aa4cc14f251e4a780e94e200aed6b36a5b15c21",
};
const PROFILE_LABEL =
  "CWE-78 + CWE-22 + CWE-89 · Đa CWE, SQL injection chỉ phát hiện và giữ";

function save(name: string, content: string) {
  if (!output) return;
  mkdirSync(output, { recursive: true });
  writeFileSync(join(output, name), content, "utf-8");
}

test.describe("three-family scan on the complete stack", () => {
  test.skip(!stack, "Set FULL_STACK_URL to a running stack to run this test");
  test.setTimeout(40 * 60_000);

  test("creates a multi-cwe-v0.2 scan from the UI and keeps every SQL injection alert for review", async ({
    page,
  }) => {
    const api = `${stack}/api/v1`;
    const created = await page.request.post(`${api}/projects`, {
      data: { name: `Đa CWE v0.2 E2E ${new Date().toISOString()}` },
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
    await expect(dialog.getByText(/chưa được xếp hạng hay gạn/)).toBeVisible();
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
    expect(scan.profile).toBe("multi-cwe-v0.2");
    expect(scan.status).toBe("completed");
    expect(scan.families.map((family) => family.family)).toEqual([
      "command-injection",
      "path-traversal",
      "sql-injection",
    ]);
    const sql = scan.families[2];
    expect(sql.profile_id).toBe("sql-injection-v0.1");
    expect(sql.units).toBeGreaterThan(0);
    // Detected and kept: every SQL unit is in the review list.
    expect(sql.review).toBe(sql.units);
    expect(sql.filtered).toBe(0);
    expect(sql.runs.map((run) => run.language).sort()).toEqual([
      "javascript",
      "python",
    ]);

    const sqlRow = families.getByRole("row", {
      name: /CWE-89 · SQL injection/,
    });
    await expect(sqlRow).toContainText("sql-injection-v0.1");
    await expect(sqlRow).toContainText("python: completed");

    // Filter by CWE-89 through the family button; the filter is a shareable link.
    await main
      .getByRole("button", {
        name: new RegExp(`^CWE-89 · SQL injection: ${sql.units}$`),
      })
      .click();
    await expect(page).toHaveURL(/family=sql-injection/);
    const units = main.getByRole("table", { name: "Đơn vị", exact: true });
    const rows = units.getByRole("row").filter({ hasText: "CWE-89" });
    await expect(rows).toHaveCount(sql.units);
    await expect(
      units.getByRole("row").filter({ hasText: "CWE-78" }),
    ).toHaveCount(0);
    for (const text of await rows.allInnerTexts()) {
      expect(text).toContain("Danh sách rà chính");
      expect(text).toContain("Chưa đủ bằng chứng");
    }

    // A SQL unit in detail: family, evidence state, keep reason, labels and tool pass.
    await rows.first().getByRole("button").first().click();
    const sheet = page.getByRole("dialog", { name: "Chi tiết đơn vị" });
    await expect(sheet.getByText("CWE-89 · SQL injection")).toBeVisible();
    await expect(sheet.getByText("Chưa đủ bằng chứng")).toBeVisible();
    await expect(
      sheet.getByText(
        "Nhóm này chỉ phát hiện và giữ: chưa có điều kiện gạn nào được đo",
      ),
    ).toBeVisible();
    await expect(sheet.getByText("cwe-089", { exact: true })).toBeVisible();
    await expect(
      sheet.getByText("codeql-sql-injection", { exact: true }),
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
    expect(exported.profile).toBe("multi-cwe-v0.2");
    expect(exported.composition.members.map((m) => m.profile_id)).toEqual([
      "command-injection-v0.3",
      "path-traversal-v0.2",
      "sql-injection-v0.1",
    ]);
    const sqlReport = exported.families.find(
      (family) => family.family === "sql-injection",
    )!;
    expect(sqlReport.raw_alerts).toBeGreaterThan(0);
    expect(sqlReport.detection_alerts).toBe(sqlReport.raw_alerts);
    expect(sqlReport.evidence_results).toBe(0);
    expect(sqlReport.main_list).toBe(sqlReport.units);
    expect(sqlReport.filtered).toBe(0);
    expect(exported.stages.unranked_alerts).toBe(0);
    expect(
      exported.families.reduce((sum, family) => sum + family.raw_alerts, 0),
    ).toBe(exported.stages.raw_alerts);

    // The SARIF export: every stored result, SQL results labelled and never suppressed.
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
    const sqlRun = sarif.runs.find(
      (run) => run.tool.driver.name === "codeql-sql-injection",
    )!;
    expect(sqlRun.results.length).toBe(sqlReport.raw_alerts);
    for (const result of sqlRun.results) {
      const triage = result.properties.securityTriage;
      expect(result.ruleId).toBe("py/sql-injection");
      expect(triage.analysisFamily).toBe("sql-injection");
      expect(triage.cwe).toBe("CWE-89");
      expect(triage.reportedCwes).toEqual(["cwe-089"]);
      expect(triage.mappedCwes).toEqual(["CWE-89"]);
      expect(triage.disposition).toBe("review");
      expect(triage.ranked).toBe(true);
      expect(triage.resultRole).toBe("detection");
      expect(result.suppressions).toBeUndefined();
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
          sarifResults: results.length,
          sarifSqlResults: sqlRun.results.length,
        },
        null,
        2,
      ),
    );
    if (output)
      await page.screenshot({ path: join(output, "scan.png"), fullPage: true });
  });
});
