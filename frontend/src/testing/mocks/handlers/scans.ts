import { http, HttpResponse } from "msw";
import { env } from "@/config/env";
import { db, makeScan } from "@/testing/mocks/db";
import type { Schemas } from "@/types/api";

export const scansHandlers = [
  http.post(
    `${env.API_URL}/projects/:projectId/scans`,
    async ({ request, params }) => {
      if (!db.projects.some((project) => project.id === params.projectId))
        return HttpResponse.json(
          { detail: "Project not found" },
          { status: 404 },
        );
      const input = (await request.json()) as Schemas["ScanCreate"];
      const scan = makeScan({
        project_id: String(params.projectId),
        status: "queued",
        started_at: null,
        finished_at: null,
        profile: input.profile,
        tool_runs: [],
      });
      db.scans.push(scan);
      const accepted: Schemas["ScanAccepted"] = {
        scan_id: scan.id,
        snapshot_id: scan.snapshot.id,
        status: scan.status,
      };
      return HttpResponse.json(accepted, { status: 202 });
    },
  ),
  http.get(`${env.API_URL}/scans/:scanId`, ({ params }) => {
    const scan = db.scans.find((scan) => scan.id === params.scanId);
    return scan
      ? HttpResponse.json(scan)
      : HttpResponse.json({ detail: "Scan not found" }, { status: 404 });
  }),
  http.get(`${env.API_URL}/scans/:scanId/units`, ({ params, request }) => {
    if (!db.scans.some((scan) => scan.id === params.scanId))
      return HttpResponse.json({ detail: "Scan not found" }, { status: 404 });
    const search = new URL(request.url).searchParams;
    const tier = search.get("tier");
    const tool = search.get("tool");
    const limit = Number(search.get("limit") ?? 20);
    const offset = Number(search.get("offset") ?? 0);
    const units = (db.units[String(params.scanId)] ?? []).filter(
      (unit) =>
        (!tier || unit.priority === tier) &&
        (!tool || unit.tools.includes(tool)),
    );
    const page: Schemas["UnitPage"] = {
      items: units.slice(offset, offset + limit),
      total: units.length,
      limit,
      offset,
    };
    return HttpResponse.json(page);
  }),
  http.get(`${env.API_URL}/scans/:scanId/units/:unitId`, ({ params }) => {
    const unit = db.units[String(params.scanId)]?.find(
      (unit) => unit.id === params.unitId,
    );
    return unit
      ? HttpResponse.json(unit)
      : HttpResponse.json({ detail: "Unit not found" }, { status: 404 });
  }),
];
