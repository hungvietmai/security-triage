import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { Schemas } from "@/types/api";
import {
  mainContent as main,
  renderApp,
  screen,
  server,
  waitFor,
  within,
} from "@/testing/test-utils";

const degraded: Schemas["Readiness"] = {
  status: "degraded",
  checks: { postgres: "ok", redis: "unavailable", storage: "ok" },
};

describe("System page", () => {
  it("reports every service as ready", async () => {
    await renderApp("/system");
    // API (liveness) plus the three readiness checks.
    await waitFor(() =>
      expect(main().getAllByText("Sẵn sàng")).toHaveLength(4),
    );
    expect(
      main().queryByText("Một số dịch vụ không khả dụng"),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Tất cả dịch vụ sẵn sàng")).toBeInTheDocument();
  });

  it("flags the failing service when readiness is degraded (503)", async () => {
    server.use(
      http.get("/api/v1/health/ready", () =>
        HttpResponse.json(degraded, { status: 503 }),
      ),
    );
    await renderApp("/system");

    expect(
      await main().findByText("Một số dịch vụ không khả dụng"),
    ).toBeInTheDocument();
    const redisCard = main().getByText("Redis").closest("[data-slot=card]");
    expect(
      within(redisCard as HTMLElement).getByText("Không khả dụng"),
    ).toBeInTheDocument();
    expect(screen.getByText("Dịch vụ gặp sự cố")).toBeInTheDocument();
  });
});
