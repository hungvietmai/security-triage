import { http, HttpResponse } from "msw";
import { env } from "@/config/env";
import { db, makeProject } from "@/testing/mocks/db";
import type { Schemas } from "@/types/api";

export const projectsHandlers = [
  http.get(`${env.API_URL}/projects`, ({ request }) => {
    const url = new URL(request.url);
    const limit = Number(url.searchParams.get("limit") ?? 20);
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const page: Schemas["ProjectPage"] = {
      items: db.projects.slice(offset, offset + limit),
      total: db.projects.length,
      limit,
      offset,
    };
    return HttpResponse.json(page);
  }),

  http.get(`${env.API_URL}/projects/:projectId`, ({ params }) => {
    const project = db.projects.find((item) => item.id === params.projectId);
    return project
      ? HttpResponse.json(project)
      : HttpResponse.json({ detail: "Project not found" }, { status: 404 });
  }),

  http.post(`${env.API_URL}/projects`, async ({ request }) => {
    const body = (await request.json()) as Schemas["ProjectCreate"];
    const project = makeProject({
      name: body.name.trim(),
      description: body.description ?? null,
      created_at: new Date().toISOString(),
    });
    db.projects.unshift(project);
    return HttpResponse.json(project, { status: 201 });
  }),
];
