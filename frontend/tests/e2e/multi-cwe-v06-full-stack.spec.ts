import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";

/**
 * The five-family profile (CWE-78, CWE-22, CWE-89, CWE-79 and CWE-918) against the COMPLETE
 * stack (Nginx, API, worker with the real scanners, PostgreSQL, object store). Like the other
 * full-stack tests it needs a running stack and network access for the worker, and is skipped
 * unless FULL_STACK_URL names the frontend:
 *
 *   FULL_STACK_URL=http://127.0.0.1:5173 FULL_STACK_OUTPUT=../artifacts/e2e-v06 \
 *     npx playwright test multi-cwe-v06-full-stack
 *
 * The source is development data without labels, the PyGoat commit of the v0.2, v0.3 and v0.5
 * tests: Python for every family but CWE-79, JavaScript for every family but CWE-22. The test
 * goes from choosing the profile in the form to downloading the SARIF export. Nothing of the
 * scanned source is executed.
 */
const stack = process.env.FULL_STACK_URL;
const output = process.env.FULL_STACK_OUTPUT;
const SOURCE = {
  owner: "adeyosemanputra",
  repo: "pygoat",
  commit: "2aa4cc14f251e4a780e94e200aed6b36a5b15c21",
};
const PROFILE_LABEL =
  "CWE-78 + CWE-22 + CWE-89 + CWE-79 + CWE-918 · Thử nghiệm: thêm SSRF cho Python và JavaScript/TypeScript";
const SSRF_PASS = "codeql-ssrf";
const SSRF_RULES = ["py/full-ssrf", "py/partial-ssrf", "js/request-forgery"];

type UnitDetail = {
  id: string;
  analysis_family: string | null;
  path: string | null;
  start_line: number | null;
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

test.describe("five-family scan with CWE-918 on the complete stack", () => {
  test.skip(!stack, "Set FULL_STACK_URL to a running stack to run this test");
  test.setTimeout(45 * 60_000);

  test("creates a multi-cwe-v0.6 scan from the UI, keeps every SSRF alert in its own family and exports it", async ({
    page,
  }) => {
    const api = `${stack}/api/v1`;
    const created = await page.request.post(`${api}/projects`, {
      data: { name: `Đa CWE v0.6 E2E ${new Date().toISOString()}` },
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
      dialog.getByText(/ba truy vấn SSRF phía máy chủ của CodeQL/),
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
    await expect(families).toBeVisible({ timeout: 40 * 60_000 });
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
    expect(scan.profile).toBe("multi-cwe-v0.6");
    expect(scan.status).toBe("completed");
    expect(scan.families.map((family) => family.family)).toEqual([
      "command-injection",
      "path-traversal",
      "sql-injection",
      "cross-site-scripting",
      "ssrf",
    ]);
    const ssrf = scan.families[4];
    expect(ssrf.profile_id).toBe("ssrf-v0.1");
    // Python and JavaScript/TypeScript, one pass each on that language's database.
    expect(ssrf.runs.map((run) => [run.language, run.status]).sort()).toEqual([
      ["javascript", "completed"],
      ["python", "completed"],
    ]);
    // Detected and kept: every SSRF unit is in the review list.
    expect(ssrf.units).toBeGreaterThan(0);
    expect(ssrf.review).toBe(ssrf.units);
    expect(ssrf.filtered).toBe(0);
    expect(
      scan.tool_runs
        .filter((run) => run.tool === SSRF_PASS)
        .map((run) => [run.language, run.status])
        .sort(),
    ).toEqual([
      ["javascript", "completed"],
      ["python", "completed"],
    ]);

    const ssrfRow = families.getByRole("row", {
      name: /CWE-918 · Server-side request forgery \(SSRF\)/,
    });
    await expect(ssrfRow).toContainText("ssrf-v0.1");
    await expect(ssrfRow).toContainText("python: completed");
    await expect(ssrfRow).toContainText("javascript: completed");

    // Filter by CWE-918 through the family button.
    await main
      .getByRole("button", {
        name: new RegExp(
          `^CWE-918 · Server-side request forgery \\(SSRF\\): ${ssrf.units}$`,
        ),
      })
      .click();
    await expect(page).toHaveURL(/family=ssrf/);
    const units = main.getByRole("table", { name: "Đơn vị", exact: true });
    const rows = units.getByRole("row").filter({ hasText: "CWE-918" });
    await expect(rows).toHaveCount(ssrf.units);
    for (const text of await rows.allInnerTexts()) {
      expect(text).toContain("Danh sách rà chính");
      expect(text).toContain("Chưa đủ bằng chứng");
    }

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
    const ssrfUnits = details.filter((unit) => unit.analysis_family === "ssrf");
    save("ssrf-units.json", JSON.stringify(ssrfUnits, null, 2));
    expect(ssrfUnits.length).toBe(ssrf.units);
    for (const unit of ssrfUnits) {
      expect(unit.tools).toEqual(["codeql"]);
      for (const finding of unit.findings) {
        expect(finding.tool_pass).toBe(SSRF_PASS);
        expect(SSRF_RULES).toContain(finding.rule_id);
      }
    }
    const target = ssrfUnits[0];
    await units
      .getByRole("button", {
        name: `Xem đơn vị ${target.path}:${target.start_line}`,
      })
      .click();
    const sheet = page.getByRole("dialog", { name: "Chi tiết đơn vị" });
    await expect(
      sheet.getByText("CWE-918 · Server-side request forgery (SSRF)"),
    ).toBeVisible();
    await expect(sheet.getByText("Chưa đủ bằng chứng")).toBeVisible();
    await expect(
      sheet.getByText(SSRF_PASS, { exact: true }).first(),
    ).toBeVisible();
    if (output) await page.screenshot({ path: join(output, "unit.png") });
    await sheet.getByRole("button", { name: "Đóng chi tiết" }).click();

    // The before/after report: five families, the SSRF family with no filtered candidate.
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
        units: number;
        main_list: number;
        filtered: number;
      }[];
      composition: { members: { profile_id: string }[] };
    };
    save("report.json", JSON.stringify(exported, null, 2));
    expect(exported.profile).toBe("multi-cwe-v0.6");
    expect(exported.composition.members.map((m) => m.profile_id)).toEqual([
      "command-injection-v0.3",
      "path-traversal-v0.2",
      "sql-injection-v0.3",
      "cross-site-scripting-v0.1",
      "ssrf-v0.1",
    ]);
    const ssrfReport = exported.families.find(
      (family) => family.family === "ssrf",
    )!;
    expect(ssrfReport.raw_alerts).toBe(exported.raw_alerts[SSRF_PASS] ?? 0);
    expect(ssrfReport.detection_alerts).toBe(ssrfReport.raw_alerts);
    expect(ssrfReport.units).toBe(ssrfUnits.length);
    expect(ssrfReport.main_list).toBe(ssrfReport.units);
    expect(ssrfReport.filtered).toBe(0);
    expect(exported.stages.unranked_alerts).toBe(0);
    expect(
      exported.families.reduce((sum, family) => sum + family.raw_alerts, 0),
    ).toBe(exported.stages.raw_alerts);

    // The SARIF export: every stored result; each CWE-918 result with CodeQL's own rule and
    // CWE label, in the review list and never suppressed.
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
              reportedCwes: string[];
              mappedCwes: string[];
            };
          };
        }[];
      }[];
    };
    const results = sarif.runs.flatMap((run) => run.results);
    expect(results.length).toBe(exported.stages.raw_alerts);
    const ssrfResults = sarif.runs
      .filter((run) => run.tool.driver.name === SSRF_PASS)
      .flatMap((run) => run.results);
    expect(ssrfResults.length).toBe(ssrfReport.raw_alerts);
    for (const result of ssrfResults) {
      const triage = result.properties.securityTriage;
      expect(SSRF_RULES).toContain(result.ruleId);
      expect(triage.analysisFamily).toBe("ssrf");
      expect(triage.cwe).toBe("CWE-918");
      expect(triage.mappedCwes).toEqual(["CWE-918"]);
      expect(triage.reportedCwes).toEqual(["cwe-918"]);
      expect(triage.disposition).toBe("review");
      expect(triage.ranked).toBe(true);
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
          ssrfReport,
          ssrfUnits: ssrfUnits.length,
          sarifResults: results.length,
          sarifSsrfResults: ssrfResults.length,
        },
        null,
        2,
      ),
    );
    if (output)
      await page.screenshot({ path: join(output, "scan.png"), fullPage: true });
  });
});
