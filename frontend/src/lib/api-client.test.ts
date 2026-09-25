import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { server } from "@/testing/mocks/server";
import { api, ApiError, apiRequest } from "@/lib/api-client";

function respondWith(response: () => Response) {
  server.use(http.all("/api/v1/probe", response));
}

async function captureError(promise: Promise<unknown>): Promise<ApiError> {
  const error = await promise.then(
    () => null,
    (cause: unknown) => cause,
  );
  expect(error).toBeInstanceOf(ApiError);
  return error as ApiError;
}

describe("apiRequest", () => {
  it("sends JSON bodies and returns the parsed response", async () => {
    let received: unknown;
    server.use(
      http.post("/api/v1/probe", async ({ request }) => {
        received = {
          type: request.headers.get("content-type"),
          body: await request.json(),
        };
        return HttpResponse.json({ ok: true });
      }),
    );
    await expect(
      apiRequest("/probe", { method: "POST", json: { name: "x" } }),
    ).resolves.toEqual({ ok: true });
    expect(received).toEqual({
      type: "application/json",
      body: { name: "x" },
    });
  });

  it("encodes query params and skips undefined values", async () => {
    let search = "";
    server.use(
      http.get("/api/v1/probe", ({ request }) => {
        search = new URL(request.url).search;
        return HttpResponse.json({});
      }),
    );
    await api.get("/probe", {
      params: { limit: 12, offset: 0, q: "a b", skip: undefined },
    });
    expect(search).toBe("?limit=12&offset=0&q=a+b");
  });

  it("uses a string FastAPI detail as the message", async () => {
    respondWith(() =>
      HttpResponse.json({ detail: "Project not found" }, { status: 404 }),
    );
    const error = await captureError(apiRequest("/probe"));
    expect(error.status).toBe(404);
    expect(error.message).toBe("Project not found");
  });

  it("joins validation issues with their field names", async () => {
    respondWith(() =>
      HttpResponse.json(
        {
          detail: [
            { loc: ["body", "name"], msg: "String too short", type: "x" },
            { loc: ["query", "limit"], msg: "Too large", type: "y" },
          ],
        },
        { status: 422 },
      ),
    );
    const error = await captureError(apiRequest("/probe"));
    expect(error.message).toBe(
      "name: String too short; query.limit: Too large",
    );
  });

  it("falls back to a generic message for non-JSON server errors", async () => {
    respondWith(
      () => new HttpResponse("<html>Bad Gateway</html>", { status: 502 }),
    );
    const error = await captureError(apiRequest("/probe"));
    expect(error.status).toBe(502);
    expect(error.message).toMatch(/Máy chủ lỗi \(502\)/);
  });

  it("reports network failures with status 0", async () => {
    respondWith(() => HttpResponse.error());
    const error = await captureError(apiRequest("/probe"));
    expect(error.status).toBe(0);
    expect(error.message).toBe("Không kết nối được API.");
  });

  it("returns the body for explicitly accepted error statuses", async () => {
    respondWith(() =>
      HttpResponse.json({ status: "degraded" }, { status: 503 }),
    );
    await expect(
      apiRequest("/probe", { acceptStatus: [503] }),
    ).resolves.toEqual({ status: "degraded" });
  });
});
