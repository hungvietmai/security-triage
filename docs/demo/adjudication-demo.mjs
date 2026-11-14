// Real-stack demo and check of merging, filtering and the before/after report.
// Drives the built frontend (nginx -> api -> PostgreSQL) on scans the worker already finished,
// so nothing here starts a scanner. The expected values belong to the two development
// snapshots named in docs/demo/README.md; the script fails if the page shows anything else.
import { readFileSync } from "node:fs";
import { chromium } from "playwright";

const base = process.env.BASE ?? "http://frontend";
const out = process.env.OUT ?? "/out";
const cwe78 = process.env.SCAN_CWE78; // OWASP BenchmarkPython, profile command-injection-v0.2
const cwe22 = process.env.SCAN_CWE22; // pipecat, profile path-traversal-v0.2
if (!cwe78 || !cwe22) throw new Error("Set SCAN_CWE78 and SCAN_CWE22 to scan IDs");

const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width: 1440, height: 1000 },
  acceptDownloads: true,
});
const page = await context.newPage();
page.setDefaultTimeout(30_000);
let step = "start";
const log = (message) => console.log(`[${new Date().toISOString()}] ${message}`);
const at = (name) => {
  step = name;
  log(`step: ${name}`);
};
const expect = (condition, message) => {
  if (!condition) throw new Error(`Expectation failed: ${message}`);
};
const main = page.getByRole("main");
const table = main.getByRole("table", { name: "Đơn vị", exact: true });
const sheet = page.getByRole("dialog", { name: "Chi tiết đơn vị" });
const closeSheet = async () => {
  await sheet.getByRole("button", { name: "Đóng chi tiết" }).click();
  await sheet.waitFor({ state: "hidden" });
};
const rows = () => table.getByRole("button", { name: /^Xem đơn vị / });
// The detail sheet slides in; a screenshot taken during the animation is washed out.
const shootSheet = async (name) => {
  await page.waitForTimeout(800);
  await page.screenshot({ path: `${out}/${name}` });
};

try {
  at("CWE-78: open the scan; nothing is hidden by default");
  await page.goto(`${base}/scans/${cwe78}`);
  await table.waitFor();
  await main.getByRole("button", { name: "Danh sách rà chính: 22" }).waitFor();
  await main.getByRole("button", { name: "Đã gạn: 2" }).waitFor();
  await page.screenshot({ path: `${out}/cwe78-scan-overview.png`, fullPage: true });

  at("CWE-78: three tools reporting one call are one unit");
  await page.goto(`${base}/scans/${cwe78}?list=review&tier=P1`);
  await rows().first().waitFor();
  expect((await rows().count()) === 7, "seven P1 units in the main list");
  await rows().first().click();
  await sheet.getByText("công cụ đã báo: bandit, codeql, semgrep").waitFor();
  const alerts = await sheet.getByRole("article").count();
  expect(alerts >= 3, `at least three original alerts in one unit, saw ${alerts}`);
  await shootSheet("cwe78-merged-candidate.png");
  await closeSheet();

  at("CWE-78: a call only Bandit reported stays in the main list");
  await page.goto(`${base}/scans/${cwe78}?list=review&tier=P3&tool=bandit`);
  const banditOnly = table.getByRole("button", { name: /BenchmarkTest00899\.py/ });
  await banditOnly.waitFor();
  await banditOnly.click();
  await sheet.getByText("Nằm trong danh sách rà chính.").waitFor();
  await sheet.getByText("công cụ đã báo: bandit", { exact: false }).first().waitFor();
  await sheet.getByText("Không có bằng chứng cụ thể cho thấy đây là cảnh báo sai.").waitFor();
  await shootSheet("cwe78-single-tool-kept.png");
  await closeSheet();

  at("CWE-78: the filtered list shows the rule; the original alerts can be reopened");
  await page.goto(`${base}/scans/${cwe78}`);
  await table.waitFor();
  await main.getByRole("button", { name: "Đã gạn: 2" }).click();
  await page.waitForURL(/list=filtered/);
  // 01097 satisfies the open-source rule (Semgrep) first; 01098 only the CodeQL rule.
  await table
    .getByText("Đã gạn: Semgrep chứng minh luồng chỉ đi qua nhánh không bao giờ chạy")
    .waitFor();
  await table.getByText("Đã gạn: Bằng chứng an toàn của CodeQL loại hết luồng").waitFor();
  expect((await rows().count()) === 2, "two filtered units");
  await page.screenshot({ path: `${out}/cwe78-filtered-list.png`, fullPage: true });
  await table.getByRole("button", { name: /BenchmarkTest01097\.py/ }).click();
  await sheet
    .getByText("Đã gạn khỏi danh sách rà chính. Cảnh báo gốc vẫn được giữ ở bên dưới.")
    .waitFor();
  await sheet.getByRole("heading", { name: "Bằng chứng gạn" }).waitFor();
  // Both evidence sources are shown: Semgrep's rule pair and CodeQL's evidence query.
  await sheet.getByText(/st-cmd-flow-all/).first().waitFor();
  await sheet.getByText(/st\/cwe-78\/all/).first().waitFor();
  expect((await sheet.getByRole("article").count()) >= 3, "original alerts are still listed");
  await shootSheet("cwe78-filtered-detail.png");
  await closeSheet();

  at("CWE-78: before/after report and its two exports");
  const report = main.getByRole("region", { name: "Báo cáo trước–sau" });
  await report.scrollIntoViewIfNeeded();
  const stage = (name) =>
    report.getByRole("table", { name: "Các bước của quy trình" }).getByRole("row", { name });
  await stage(/Cảnh báo thô của mọi công cụ 51/).waitFor();
  await stage(/Ứng viên rà soát \(mỗi lời gọi một mục\) 20/).waitFor();
  await stage(/Danh sách rà chính sau khi gạn 18/).waitFor();
  await stage(/Đã gạn vì có bằng chứng là cảnh báo sai 2/).waitFor();
  await report.screenshot({ path: `${out}/cwe78-report.png` });
  for (const [link, file] of [
    ["Tải báo cáo JSON", "exported-report.json"],
    ["Tải SARIF hợp nhất", "exported-report.sarif"],
  ]) {
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      report.getByRole("link", { name: link }).click(),
    ]);
    await download.saveAs(`${out}/${file}`);
  }
  const exported = JSON.parse(readFileSync(`${out}/exported-report.json`, "utf8"));
  expect(exported.stages.filtered === 2 && exported.stages.main_list === 18, "exported stages");
  const sarif = JSON.parse(readFileSync(`${out}/exported-report.sarif`, "utf8"));
  const results = sarif.runs.flatMap((run) => run.results);
  const suppressed = results.filter((result) => result.suppressions?.length).length;
  expect(sarif.version === "2.1.0" && results.length === 51, "SARIF keeps all 51 alerts");
  expect(suppressed > 0 && suppressed < results.length, "only filtered alerts are suppressed");
  log(`exports: ${results.length} SARIF results, ${suppressed} suppressed`);

  at("CWE-22: alerts removed by safety evidence are filtered, not deleted");
  await page.goto(`${base}/scans/${cwe22}?list=filtered`);
  await rows().first().waitFor();
  expect((await rows().count()) === 3, "three filtered CWE-22 units");
  await rows().first().click();
  await sheet
    .getByText("Đã gạn khỏi danh sách rà chính. Cảnh báo gốc vẫn được giữ ở bên dưới.")
    .waitFor();
  await sheet.getByText(/st\/cwe-22\/none/).first().waitFor();
  await shootSheet("cwe22-filtered-reopened.png");

  at("reload keeps the list and the unit can be opened again");
  await page.reload();
  await rows().first().waitFor();
  expect(page.url().includes("list=filtered"), "the chosen list survives a reload");
  log("all checks passed; screenshots written");
} catch (error) {
  console.log(`FAILED at "${step}": ${String(error).split("\n")[0]}`);
  await page.screenshot({ path: `${out}/failure.png`, fullPage: true });
  process.exitCode = 1;
} finally {
  await browser.close();
}
