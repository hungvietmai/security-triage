import { expect, test } from "@playwright/test";
import { installBrowserApi } from "@test/support/browser-api";

test("creates a scan, polls to completion, reloads URL filters and opens evidence in Chromium", async ({
  page,
}) => {
  const api = await installBrowserApi(page);
  await page.goto(`/projects/${api.project.id}`);
  const main = page.getByRole("main");
  await main.getByRole("button", { name: "Tạo scan" }).click();
  const dialog = page.getByRole("dialog", { name: "Tạo scan mới" });
  await dialog.getByLabel("Tên npm").fill("@Scope/pkg");
  await dialog.getByLabel("Phiên bản").fill("^1.2.3");
  await dialog.getByRole("button", { name: "Tạo scan", exact: true }).click();
  await expect(dialog.getByLabel("Tên npm")).toHaveAttribute(
    "aria-invalid",
    "true",
  );
  expect(api.createRequests).toBe(0);
  await dialog.getByLabel("Tên npm").fill("@scope/demo");
  await dialog.getByLabel("Phiên bản").fill("1.2.3");
  await dialog.getByRole("button", { name: "Tạo scan", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/scans/${api.scan.id}`));
  await expect(main.getByText(/Scan queued; tự cập nhật/)).toBeVisible();
  await expect(
    main.getByRole("table", { name: "Đơn vị", exact: true }),
  ).toBeVisible({ timeout: 12_000 });
  expect(api.scanInput?.source).toEqual({
    kind: "npm",
    package: "@scope/demo",
    version: "1.2.3",
  });
  const completedRequests = api.scanRequests;
  // Observe a complete poll interval to verify that terminal scans stay quiet.
  await page.waitForTimeout(3_500);
  expect(api.scanRequests).toBe(completedRequests);

  await main.getByRole("combobox", { name: "Công cụ", exact: true }).click();
  await page.getByRole("option", { name: "codeql", exact: true }).click();
  await main.getByRole("button", { name: "P1: 1" }).click();
  await expect(page).toHaveURL(/tier=P1/);
  await expect(page).toHaveURL(/tool=codeql/);
  await page.reload();
  await expect(
    main.getByRole("combobox", { name: "Mức ưu tiên" }),
  ).toContainText("P1");
  await expect(
    main.getByRole("combobox", { name: "Công cụ", exact: true }),
  ).toContainText("codeql");
  await main.getByRole("button", { name: "Xem đơn vị entry.js:12" }).click();
  const sheet = page.getByRole("dialog", { name: "Chi tiết đơn vị" });
  await expect(
    sheet.getByText("entry.js:2 – User input", { exact: true }),
  ).toBeVisible();
  await expect(
    sheet.getByText("entry.js:12 – Command sink", { exact: true }),
  ).toBeVisible();
  await expect(
    sheet.getByText(api.units[0].policy_sha256, { exact: true }),
  ).toBeVisible();
  await sheet.getByRole("button", { name: "Đóng chi tiết" }).click();
  await main.getByRole("combobox", { name: "Công cụ", exact: true }).click();
  await page
    .getByRole("option", { name: "Tất cả công cụ", exact: true })
    .click();
  await main.getByRole("button", { name: "P2: 1" }).click();
  await main.getByRole("button", { name: "Xem đơn vị other.js:12" }).click();
  await expect(
    sheet.getByText("công cụ không cung cấp vết", { exact: true }),
  ).toBeVisible();
  api.assertHandled();
});

test("shows a failed scan's reason and never requests an empty units table", async ({
  page,
}) => {
  const api = await installBrowserApi(page, { failed: true });
  await page.goto(`/scans/${api.scan.id}`);
  const main = page.getByRole("main");
  await expect(
    main.getByText("Archive integrity mismatch", { exact: true }),
  ).toBeVisible();
  await expect(main.getByRole("table")).toHaveCount(0);
  expect(api.unitRequests).toBe(0);
  api.assertHandled();
});
