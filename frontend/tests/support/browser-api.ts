import { expect, type Page } from "@playwright/test";
import { makeProject, makeScan, makeUnit } from "@/testing/mocks/db";
import type { Schemas } from "@/types/api";

/** Real-browser workflows with isolated HTTP fixtures; no backend/worker execution. */
export async function installBrowserApi(page: Page, { failed = false } = {}) {
  const project = makeProject({ name: "Dự án E2E", description: null });
  const scan = makeScan({
    project_id: project.id,
    error_message: failed ? "Archive integrity mismatch" : null,
    unit_counts: { P1: 1, P2: 1, U: 0, P3: 0, P4: 0 },
  });
  const units = [
    makeUnit({ path: "entry.js", priority: "P1" }),
    makeUnit({ path: "other.js", priority: "P2", tools: ["semgrep"] }),
  ];
  units[0].findings[0].raw_result = {
    codeFlows: [
      {
        threadFlows: [
          {
            locations: [
              {
                location: {
                  physicalLocation: {
                    artifactLocation: { uri: "entry.js" },
                    region: { startLine: 2 },
                  },
                  message: { text: "User input" },
                },
              },
              {
                location: {
                  physicalLocation: {
                    artifactLocation: { uri: "entry.js" },
                    region: { startLine: 12 },
                  },
                  message: { text: "Command sink" },
                },
              },
            ],
          },
        ],
      },
    ],
  };
  let scanRequests = 0;
  let unitRequests = 0;
  let createRequests = 0;
  let scanInput: Schemas["ScanCreate"] | undefined;
  const unhandled: string[] = [];
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.replace("/api/v1", "");
    const reply = (json: unknown, status = 200) =>
      route.fulfill({ status, json });
    if (path === "/health/ready")
      return reply({
        status: "ok",
        checks: { postgres: "ok", redis: "ok", storage: "ok" },
      } satisfies Schemas["Readiness"]);
    if (path === `/projects/${project.id}`) return reply(project);
    if (
      path === `/projects/${project.id}/scans` &&
      request.method() === "POST"
    ) {
      createRequests++;
      scanInput = request.postDataJSON() as Schemas["ScanCreate"];
      return reply(
        {
          scan_id: scan.id,
          snapshot_id: scan.snapshot.id,
          status: "queued",
        } satisfies Schemas["ScanAccepted"],
        202,
      );
    }
    if (path === `/scans/${scan.id}`) {
      const statuses = failed ? ["failed"] : ["queued", "running", "completed"];
      const status = statuses[Math.min(scanRequests++, statuses.length - 1)];
      return reply({ ...scan, status });
    }
    if (path === `/scans/${scan.id}/units`) {
      unitRequests++;
      const tier = url.searchParams.get("tier");
      const tool = url.searchParams.get("tool");
      const limit = Number(url.searchParams.get("limit") ?? 20);
      const offset = Number(url.searchParams.get("offset") ?? 0);
      const items = units.filter(
        (unit) =>
          (!tier || unit.priority === tier) &&
          (!tool || unit.tools.includes(tool)),
      );
      return reply({
        items: items.slice(offset, offset + limit),
        limit,
        offset,
        total: items.length,
      } satisfies Schemas["UnitPage"]);
    }
    const unit = units.find(
      (unit) => path === `/scans/${scan.id}/units/${unit.id}`,
    );
    if (unit) return reply(unit);
    unhandled.push(`${request.method()} ${path}`);
    return reply({ detail: "Unexpected browser test API request" }, 500);
  });
  return {
    project,
    scan,
    units,
    get scanRequests() {
      return scanRequests;
    },
    get unitRequests() {
      return unitRequests;
    },
    get createRequests() {
      return createRequests;
    },
    get scanInput() {
      return scanInput;
    },
    assertHandled() {
      expect(unhandled).toEqual([]);
    },
  };
}
