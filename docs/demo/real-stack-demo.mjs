// Real-stack demo: drives the built frontend (nginx -> api -> worker with real Semgrep/CodeQL).
import { chromium } from "playwright";

const base = process.env.BASE ?? "http://frontend";
const out = process.env.OUT ?? "/out";
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
page.setDefaultTimeout(30_000);
let step = "start";
const log = (message) => console.log(`[${new Date().toISOString()}] ${message}`);
const at = (name) => {
  step = name;
  log(`step: ${name}`);
};

try {
  at("open projects");
  await page.goto(`${base}/projects`);
  at("open create-project dialog");
  await page.getByRole("button", { name: "Tạo dự án" }).first().click();
  const create = page.getByRole("dialog");
  await create.getByLabel("Tên dự án").fill("Demo curling@0.2.0");
  at("submit project");
  await create.getByRole("button", { name: "Tạo dự án" }).click();
  at("open project");
  // Creating a project navigates straight to its page.
  const main = page.getByRole("main");
  const createScan = main.getByRole("button", { name: "Tạo scan" });
  await createScan.waitFor();
  log(`project page ${page.url()}`);

  at("open create-scan dialog");
  await createScan.click();
  const scan = page.getByRole("dialog", { name: "Tạo scan mới" });
  await scan.getByLabel("Tên npm").fill("curling");
  await scan.getByLabel("Phiên bản").fill("0.2.0");
  at("submit scan");
  await scan.getByRole("button", { name: "Tạo scan", exact: true }).click();
  await page.waitForURL(/\/scans\//);
  log(`scan page ${page.url()}`);

  // The worker runs the pinned scanners; the page polls until the scan finishes.
  at("wait for scan to finish");
  await main
    .getByRole("table", { name: "Đơn vị", exact: true })
    .waitFor({ timeout: 20 * 60_000 });
  await page.screenshot({ path: `${out}/curling-scan-units.png`, fullPage: true });

  at("open unit evidence");
  await main.getByRole("button", { name: /^Xem đơn vị / }).first().click();
  const sheet = page.getByRole("dialog", { name: "Chi tiết đơn vị" });
  // One "Vết dữ liệu" section per raw finding (curling has six CodeQL alerts).
  const trace = sheet.getByRole("heading", { name: "Vết dữ liệu" }).first();
  await trace.waitFor();
  await page.screenshot({ path: `${out}/curling-unit-evidence.png` });
  await trace.scrollIntoViewIfNeeded();
  await page.screenshot({ path: `${out}/curling-unit-trace.png` });
  log("screenshots written");
} catch (error) {
  console.log(`FAILED at "${step}": ${String(error).split("\n")[0]}`);
  await page.screenshot({ path: `${out}/failure.png`, fullPage: true });
  process.exitCode = 1;
} finally {
  await browser.close();
}
