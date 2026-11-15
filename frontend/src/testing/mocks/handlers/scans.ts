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
    const disposition = search.get("disposition");
    const family = search.get("family");
    const limit = Number(search.get("limit") ?? 20);
    const offset = Number(search.get("offset") ?? 0);
    const units = (db.units[String(params.scanId)] ?? []).filter(
      (unit) =>
        (!tier || unit.priority === tier) &&
        (!tool || unit.tools.includes(tool)) &&
        (!disposition || unit.disposition === disposition) &&
        (!family || unit.analysis_family === family),
    );
    const page: Schemas["UnitPage"] = {
      items: units.slice(offset, offset + limit),
      total: units.length,
      limit,
      offset,
    };
    return HttpResponse.json(page);
  }),
  http.get(`${env.API_URL}/scans/:scanId/report`, ({ params }) => {
    const scan = db.scans.find((scan) => scan.id === params.scanId);
    if (!scan)
      return HttpResponse.json({ detail: "Scan not found" }, { status: 404 });
    const units = db.units[scan.id] ?? [];
    const filtered = units.filter((unit) => unit.disposition === "filtered");
    const tools = [...new Set(units.flatMap((unit) => unit.tools))].sort();
    const evidence = db.results[scan.id]?.evidence_results ?? 0;
    const unranked = db.results[scan.id]?.unranked_alerts ?? 0;
    const report: Schemas["ScanReport"] = {
      scan_id: scan.id,
      status: scan.status,
      profile: scan.profile,
      profile_sha256: "f".repeat(64),
      policy_version: scan.policy_version,
      reconciler_version: scan.reconciler_version,
      snapshot: scan.snapshot,
      started_at: scan.started_at,
      finished_at: scan.finished_at,
      tool_versions: {},
      steps: {
        javascript: { codeql: { status: "completed", seconds: 12.34 } },
      },
      raw_alerts: Object.fromEntries(tools.map((tool) => [tool, 1])),
      stages: {
        raw_alerts: units.length + 1 + evidence + unranked,
        evidence_results: evidence,
        detection_alerts: units.length + 1 + unranked,
        unranked_alerts: unranked,
        units: units.length,
        candidates: units.length,
        main_list: units.length - filtered.length,
        filtered: filtered.length,
        demoted: 0,
      },
      sources: Object.fromEntries(
        tools.map((tool) => [
          tool,
          {
            candidates: units.filter((unit) => unit.tools.includes(tool))
              .length,
            only: units.filter(
              (unit) => unit.tools.length === 1 && unit.tools[0] === tool,
            ).length,
          },
        ]),
      ),
      main_list_by_priority: { P1: 0, P2: 0, U: 0, P3: 0, P4: 0 },
      filtered_by_rule: Object.fromEntries(
        filtered.map((unit) => [unit.filter_rule ?? "unspecified", 1]),
      ),
      families: scan.families.map((family) => {
        const mine = units.filter(
          (unit) => unit.analysis_family === family.family,
        );
        const gone = mine.filter((unit) => unit.disposition === "filtered");
        return {
          family: family.family,
          cwe: family.cwe,
          label: family.label,
          raw_alerts: mine.length,
          evidence_results: 0,
          detection_alerts: mine.length,
          units: mine.length,
          candidates: mine.length,
          main_list: mine.length - gone.length,
          filtered: gone.length,
          main_list_by_priority: { P1: 0, P2: 0, U: 0, P3: 0, P4: 0 },
          filtered_by_rule: {},
          evidence_states: {},
        };
      }),
      composition: null,
      candidates: [],
    };
    return HttpResponse.json(report);
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
