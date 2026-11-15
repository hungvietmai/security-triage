// Real-stack demo and check of JavaScript matching and the constant-command filter (v0.3).
// Drives the built frontend (nginx -> api -> PostgreSQL) on two scans the worker already
// finished with profile command-injection-v0.3, so nothing here starts a scanner. Both
// packages are development data (see experiments/evaluation/js-matching-v0.3/README.md).
// The script fails if the page shows anything other than what is expected below.
import { chromium } from "playwright";

const base = process.env.BASE ?? "http://frontend";
const out = process.env.OUT ?? "/out";
const kept = process.env.SCAN_KEPT; // kill-process-by-name@1.0.5
const filtered = process.env.SCAN_FILTERED; // arpping@2.0.0
if (!kept || !filtered) throw new Error("Set SCAN_KEPT and SCAN_FILTERED to scan IDs");

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const page = await context.newPage();
page.setDefaultTimeout(30_000);
let step = "start";
const at = (name) => {
  step = name;
  console.log(`[${new Date().toISOString()}] step: ${name}`);
};
const expect = (condition, message) => {
  if (!condition) throw new Error(`Expectation failed: ${message}`);
};
const main = page.getByRole("main");
const table = main.getByRole("table", { name: "Đơn vị", exact: true });
const sheet = page.getByRole("dialog", { name: "Chi tiết đơn vị" });
const rows = () => table.getByRole("button", { name: /^Xem đơn vị / });
// The detail sheet slides in; a screenshot taken during the animation is washed out.
const shootSheet = async (name) => {
  await page.waitForTimeout(800);
  await page.screenshot({ path: `${out}/${name}` });
};
const closeSheet = async () => {
  await sheet.getByRole("button", { name: "Đóng chi tiết" }).click();
  await sheet.waitFor({ state: "hidden" });
};

try {
  at("matching: two alias calls, each with the alerts of two tools, and nothing unmatched");
  await page.goto(`${base}/scans/${kept}`);
  await table.waitFor();
  await main.getByRole("button", { name: "Danh sách rà chính: 2" }).waitFor();
  await main.getByRole("button", { name: "Đã gạn: 0" }).waitFor();
  expect((await rows().count()) === 2, "two units, one per call");
  await page.screenshot({ path: `${out}/js-matching-scan.png`, fullPage: true });

  at("matching: the call keeps the original alerts of CodeQL and ESLint and stays for review");
  await rows().first().click();
  await sheet.getByText("Nằm trong danh sách rà chính.").waitFor();
  await sheet.getByText("công cụ đã báo: codeql, eslint").waitFor();
  const alerts = await sheet.getByRole("article").count();
  expect(alerts >= 2, `the original alerts of both tools are listed, saw ${alerts}`);
  await shootSheet("js-matching-kept-detail.png");
  await closeSheet();

  at("filtering: one call with a constant command is in the filtered list with its rule");
  await page.goto(`${base}/scans/${filtered}`);
  await table.waitFor();
  await main.getByRole("button", { name: "Đã gạn: 1" }).click();
  await page.waitForURL(/list=filtered/);
  await table
    .getByText("Đã gạn: Semgrep chứng minh chuỗi lệnh của lời gọi JavaScript là hằng")
    .waitFor();
  expect((await rows().count()) === 1, "one filtered unit");
  await page.screenshot({ path: `${out}/js-filtered-list.png`, fullPage: true });

  at("filtering: the decision shows the evidence, and the original alert can be reopened");
  await rows().first().click();
  await sheet
    .getByText("Đã gạn khỏi danh sách rà chính. Cảnh báo gốc vẫn được giữ ở bên dưới.")
    .waitFor();
  await sheet.getByRole("heading", { name: "Bằng chứng gạn" }).waitFor();
  await sheet.getByText(/st-js-constant-command/).first().waitFor();
  await sheet.getByText(/command_is_a_compile_time_constant/).first().waitFor();
  await sheet.getByText("công cụ đã báo: eslint").waitFor();
  expect((await sheet.getByRole("article").count()) >= 1, "the original alert is still listed");
  await shootSheet("js-filtered-detail.png");
  await closeSheet();

  at("filtering: the known vulnerable call of the same package stays in the main list");
  await page.goto(`${base}/scans/${filtered}?list=review`);
  await rows().first().waitFor();
  expect((await rows().count()) >= 1, "the main list is not empty");
  await page.screenshot({ path: `${out}/js-filtered-main-list.png`, fullPage: true });
  console.log("all steps passed");
} catch (error) {
  await page.screenshot({ path: `${out}/failure.png`, fullPage: true });
  console.error(`FAILED at step "${step}": ${error.message}`);
  process.exitCode = 1;
} finally {
  await browser.close();
}
