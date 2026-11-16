import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";

/**
 * The four-family profile (CWE-78, CWE-22, CWE-89 and CWE-79) against the COMPLETE stack
 * (Nginx, API, worker with the real scanners, PostgreSQL, object store). Like the other
 * full-stack tests it needs a running stack and network access for the worker, and is skipped
 * unless FULL_STACK_URL names the frontend:
 *
 *   FULL_STACK_URL=http://127.0.0.1:5173 FULL_STACK_OUTPUT=../artifacts/e2e-v05 \
 *     npx playwright test multi-cwe-v05-full-stack
 *
 * The source is development data without labels, the PyGoat commit of the v0.2 and v0.3 tests:
 * Python for the first three families and JavaScript for all but CWE-22. The test goes from
 * choosing the profile in the form to downloading the SARIF export. Nothing of the scanned source
 * is executed.
 */
const stack = process.env.FULL_STACK_URL;
const output = process.env.FULL_STACK_OUTPUT;
const SOURCE = {
  owner: "adeyosemanputra",
  repo: "pygoat",
  commit: "2aa4cc14f251e4a780e94e200aed6b36a5b15c21",
};
const PROFILE_LABEL =
  "CWE-78 + CWE-22 + CWE-89 + CWE-79 · Thử nghiệm: thêm XSS cho JavaScript/TypeScript";
const XSS_PASS = "codeql-cross-site-scripting";
const XSS_RULES = [
  "js/xss-through-exception",
  "js/reflected-xss",
  "js/stored-xss",
  "js/html-constructed-from-input",
  "js/unsafe-jquery-plugin",
  "js/xss",
  "js/xss-through-dom",
];

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

test.describe("four-family scan with CWE-79 on the complete stack", () => {
  test.skip(!stack, "Set FULL_STACK_URL to a running stack to run this test");
  test.setTimeout(45 * 60_000);

  test("creates a multi-cwe-v0.5 scan from the UI, keeps every XSS alert in its own family and exports it", async ({
    page,
  }) => {
    const api = `${stack}/api/v1`;
    const created = await page.request.post(`${api}/projects`, {
      data: { name: `Đa CWE v0.5 E2E ${new Date().toISOString()}` },
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
      dialog.getByText(/bảy truy vấn XSS chuẩn của CodeQL/),
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
    expect(scan.profile).toBe("multi-cwe-v0.5");
    expect(scan.status).toBe("completed");
    expect(scan.families.map((family) => family.family)).toEqual([
      "command-injection",
      "path-traversal",
      "sql-injection",
      "cross-site-scripting",
    ]);
    const xss = scan.families[3];
    expect(xss.profile_id).toBe("cross-site-scripting-v0.1");
    // JavaScript/TypeScript only.
    expect(xss.runs).toEqual([
      expect.objectContaining({ language: "javascript", status: "completed" }),
    ]);
    // Detected and kept: every XSS unit is in the review list.
    expect(xss.review).toBe(xss.units);
    expect(xss.filtered).toBe(0);
    expect(
      scan.tool_runs
        .filter((run) => run.tool === XSS_PASS)
        .map((run) => [run.language, run.status]),
    ).toEqual([["javascript", "completed"]]);

    const xssRow = families.getByRole("row", {
      name: /CWE-79 · Cross-site scripting \(XSS\)/,
    });
    await expect(xssRow).toContainText("cross-site-scripting-v0.1");
    await expect(xssRow).toContainText("javascript: completed");

    // Filter by CWE-79 through the family button.
    await main
      .getByRole("button", {
        name: new RegExp(
          `^CWE-79 · Cross-site scripting \\(XSS\\): ${xss.units}$`,
        ),
      })
      .click();
    await expect(page).toHaveURL(/family=cross-site-scripting/);
    const units = main.getByRole("table", { name: "Đơn vị", exact: true });
    const rows = units.getByRole("row").filter({ hasText: "CWE-79" });
    await expect(rows).toHaveCount(xss.units);
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
    const xssUnits = details.filter(
      (unit) => unit.analysis_family === "cross-site-scripting",
    );
    save("xss-units.json", JSON.stringify(xssUnits, null, 2));
    expect(xssUnits.length).toBe(xss.units);
    for (const unit of xssUnits) {
      expect(unit.tools).toEqual(["codeql"]);
      for (const finding of unit.findings) {
        expect(finding.tool_pass).toBe(XSS_PASS);
        expect(XSS_RULES).toContain(finding.rule_id);
      }
    }
    if (xssUnits.length > 0) {
      const target = xssUnits[0];
      await units
        .getByRole("button", {
          name: `Xem đơn vị ${target.path}:${target.start_line}`,
        })
        .click();
      const sheet = page.getByRole("dialog", { name: "Chi tiết đơn vị" });
      await expect(
        sheet.getByText("CWE-79 · Cross-site scripting (XSS)"),
      ).toBeVisible();
      await expect(sheet.getByText("Chưa đủ bằng chứng")).toBeVisible();
      await expect(
        sheet.getByText(XSS_PASS, { exact: true }).first(),
      ).toBeVisible();
      if (output) await page.screenshot({ path: join(output, "unit.png") });
      await sheet.getByRole("button", { name: "Đóng chi tiết" }).click();
    }

    // The before/after report: four families, the XSS family with no filtered candidate.
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
    expect(exported.profile).toBe("multi-cwe-v0.5");
    expect(exported.composition.members.map((m) => m.profile_id)).toEqual([
      "command-injection-v0.3",
      "path-traversal-v0.2",
      "sql-injection-v0.3",
      "cross-site-scripting-v0.1",
    ]);
    const xssReport = exported.families.find(
      (family) => family.family === "cross-site-scripting",
    )!;
    expect(xssReport.raw_alerts).toBe(exported.raw_alerts[XSS_PASS] ?? 0);
    expect(xssReport.detection_alerts).toBe(xssReport.raw_alerts);
    expect(xssReport.units).toBe(xssUnits.length);
    expect(xssReport.main_list).toBe(xssReport.units);
    expect(xssReport.filtered).toBe(0);
    expect(exported.stages.unranked_alerts).toBe(0);
    expect(
      exported.families.reduce((sum, family) => sum + family.raw_alerts, 0),
    ).toBe(exported.stages.raw_alerts);

    // The SARIF export: every stored result; each CWE-79 result with CodeQL's own rule and
    // CWE labels, in the review list and never suppressed.
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
    const xssResults = sarif.runs
      .filter((run) => run.tool.driver.name === XSS_PASS)
      .flatMap((run) => run.results);
    expect(xssResults.length).toBe(xssReport.raw_alerts);
    for (const result of xssResults) {
      const triage = result.properties.securityTriage;
      expect(XSS_RULES).toContain(result.ruleId);
      expect(triage.analysisFamily).toBe("cross-site-scripting");
      expect(triage.cwe).toBe("CWE-79");
      expect(triage.mappedCwes).toEqual(["CWE-79", "CWE-116"]);
      expect(triage.reportedCwes).toContain("cwe-079");
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
          xssReport,
          xssUnits: xssUnits.length,
          sarifResults: results.length,
          sarifXssResults: xssResults.length,
        },
        null,
        2,
      ),
    );
    if (output)
      await page.screenshot({ path: join(output, "scan.png"), fullPage: true });
  });
});
