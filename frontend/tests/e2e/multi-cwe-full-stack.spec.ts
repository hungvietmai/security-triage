import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";

/**
 * Against the COMPLETE stack (Nginx, API, worker with the real scanners, PostgreSQL, object
 * store), unlike scan-workflow.spec.ts, which stubs the HTTP API. It needs a running stack and
 * network access for the worker, takes several minutes, and is therefore skipped unless
 * FULL_STACK_URL names the frontend, e.g.:
 *
 *   FULL_STACK_URL=http://127.0.0.1:5173 FULL_STACK_OUTPUT=../artifacts/e2e \
 *     npx playwright test multi-cwe-full-stack
 *
 * The source is development data that has both families: OWASP BenchmarkPython at a pinned
 * commit. Nothing of the scanned source is executed.
 */
const stack = process.env.FULL_STACK_URL;
const output = process.env.FULL_STACK_OUTPUT;
const SOURCE = {
  owner: "OWASP-Benchmark",
  repo: "BenchmarkPython",
  commit: "f1291485808b66e20ddb6b01b10dc71b3df8c8ba",
};

function save(name: string, content: string) {
  if (!output) return;
  mkdirSync(output, { recursive: true });
  writeFileSync(join(output, name), content, "utf-8");
}

test.describe("multi-CWE scan on the complete stack", () => {
  test.skip(!stack, "Set FULL_STACK_URL to a running stack to run this test");
  test.setTimeout(40 * 60_000);

  test("creates a multi-CWE scan from the UI, reads both families and exports the reports", async ({
    page,
  }) => {
    const api = `${stack}/api/v1`;
    const created = await page.request.post(`${api}/projects`, {
      data: { name: `Đa CWE E2E ${new Date().toISOString()}` },
    });
    expect(created.status()).toBe(201);
    const project = (await created.json()) as { id: string };

    // Create the scan through the form: profile, GitHub source, submit.
    await page.goto(`${stack}/projects/${project.id}`);
    const main = page.getByRole("main");
    await main.getByRole("button", { name: "Tạo scan" }).click();
    const dialog = page.getByRole("dialog", { name: "Tạo scan mới" });
    await dialog.getByRole("combobox", { name: "Profile" }).click();
    await page
      .getByRole("option", {
        name: "CWE-78 + CWE-22 · Đa CWE trong một lượt quét",
      })
      .click();
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
        units: number;
        review: number;
        filtered: number;
        held: number;
        runs: { language: string; status: string }[];
      }[];
      disposition_counts: { review: number; filtered: number };
    };
    save("scan.json", JSON.stringify(scan, null, 2));
    expect(scan.profile).toBe("multi-cwe-v0.1");
    expect(["completed", "partial"]).toContain(scan.status);
    const command = scan.families.find(
      (f) => f.family === "command-injection",
    )!;
    const path = scan.families.find((f) => f.family === "path-traversal")!;
    expect(command.units).toBeGreaterThan(0);
    expect(path.units).toBeGreaterThan(0);

    // Both families are listed with the profile that assessed them.
    const commandRow = families.getByRole("row", {
      name: /CWE-78 · Command injection/,
    });
    await expect(commandRow).toContainText("command-injection-v0.3");
    const pathRow = families.getByRole("row", {
      name: /CWE-22 · Path traversal/,
    });
    await expect(pathRow).toContainText("path-traversal-v0.2");
    await expect(pathRow).toContainText("codeql-path-traversal");

    // Filter by CWE: the URL carries the family and only that family's units are listed.
    await main
      .getByRole("button", { name: `CWE-22 · Path traversal: ${path.units}` })
      .click();
    await expect(page).toHaveURL(/family=path-traversal/);
    const units = main.getByRole("table", { name: "Đơn vị", exact: true });
    await expect(units).toBeVisible();
    const rows = units.getByRole("row");
    const shown = (await rows.count()) - 1;
    expect(shown).toBeGreaterThan(0);
    for (let index = 1; index <= shown; index++)
      await expect(rows.nth(index)).toContainText("CWE-22");
    // The reload keeps the filter: it lives in the URL.
    await page.reload();
    await expect(
      main.getByRole("button", {
        name: `CWE-22 · Path traversal: ${path.units}`,
      }),
    ).toHaveAttribute("aria-pressed", "true");

    // The filtered list of that family: units a tool's evidence refuted, kept on file.
    if (path.filtered > 0) {
      await main
        .getByRole("button", {
          name: `Đã gạn: ${scan.disposition_counts.filtered}`,
        })
        .click();
      await expect(page).toHaveURL(/list=filtered/);
      await expect(
        units.getByText("Bằng chứng bác bỏ cảnh báo").first(),
      ).toBeVisible();
      await main
        .getByRole("button", {
          name: `Đã gạn: ${scan.disposition_counts.filtered}`,
        })
        .click();
    }

    // Open a unit: family, evidence state, reason and both kinds of CWE label.
    await units
      .getByRole("button", { name: /^Xem đơn vị / })
      .first()
      .click();
    const sheet = page.getByRole("dialog", { name: "Chi tiết đơn vị" });
    await expect(sheet.getByText("CWE-22 · Path traversal")).toBeVisible();
    await expect(sheet.getByText("Trạng thái bằng chứng")).toBeVisible();
    await expect(
      sheet.getByText("CWE theo rule đã ghim").first(),
    ).toBeVisible();
    await expect(sheet.getByText("CWE do công cụ báo").first()).toBeVisible();
    await expect(
      sheet.getByText("codeql-path-traversal").first(),
    ).toBeVisible();
    await page.screenshot({
      path: output ? join(output, "unit.png") : undefined,
    });
    await sheet.getByRole("button", { name: "Đóng chi tiết" }).click();

    // The other family through the same control.
    await main
      .getByRole("button", {
        name: `CWE-78 · Command injection: ${command.units}`,
      })
      .click();
    await expect(page).toHaveURL(/family=command-injection/);
    await expect(units.getByRole("row").nth(1)).toContainText("CWE-78");

    // Export the before/after report (JSON) and the merged SARIF from the page's own links.
    const report = main.getByRole("region", { name: "Báo cáo trước–sau" });
    await expect(
      report.getByRole("table", { name: "Trước–sau theo nhóm phân tích" }),
    ).toBeVisible();
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
        units: number;
        filtered: number;
      }[];
      composition: { members: { profile_id: string }[] };
    };
    save("report.json", JSON.stringify(exported, null, 2));
    expect(exported.profile).toBe("multi-cwe-v0.1");
    expect(exported.composition.members.map((m) => m.profile_id)).toEqual([
      "command-injection-v0.3",
      "path-traversal-v0.2",
    ]);
    expect(
      exported.families.reduce((sum, family) => sum + family.units, 0),
    ).toBe(exported.stages.units);
    expect(
      exported.families.reduce((sum, family) => sum + family.raw_alerts, 0),
    ).toBe(exported.stages.raw_alerts);

    const [download] = await Promise.all([
      page.waitForEvent("download"),
      report.getByRole("link", { name: "Tải SARIF hợp nhất" }).click(),
    ]);
    expect(download.suggestedFilename()).toBe(`scan-${scanId}.sarif`);
    const sarifPath = output
      ? join(output, "report.sarif")
      : await download.path();
    if (output) await download.saveAs(sarifPath);
    const sarif = (await (
      await page.request.get(`${api}/scans/${scanId}/report.sarif`)
    ).json()) as {
      version: string;
      runs: {
        results: {
          suppressions?: unknown[];
          properties: {
            securityTriage: { analysisFamily: string; disposition: string };
          };
        }[];
      }[];
    };
    expect(sarif.version).toBe("2.1.0");
    const results = sarif.runs.flatMap((run) => run.results);
    // Every original alert is exported, each in exactly one family.
    expect(results.length).toBe(exported.stages.raw_alerts);
    const byFamily = new Map<string, number>();
    for (const result of results) {
      const family = result.properties.securityTriage.analysisFamily;
      byFamily.set(family, (byFamily.get(family) ?? 0) + 1);
      expect(Boolean(result.suppressions)).toBe(
        result.properties.securityTriage.disposition === "filtered",
      );
    }
    for (const family of exported.families)
      expect(byFamily.get(family.family)).toBe(family.raw_alerts);
    save(
      "summary.json",
      JSON.stringify(
        {
          scanId,
          status: scan.status,
          families: scan.families,
          stages: exported.stages,
          sarifResults: results.length,
          sarifByFamily: Object.fromEntries(byFamily),
        },
        null,
        2,
      ),
    );
    await page.screenshot({
      path: output ? join(output, "scan.png") : undefined,
      fullPage: true,
    });
  });
});
