import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";
import { SCAN_POLL_INTERVAL } from "@/features/scans/types";
import { db, makeScan } from "@/testing/mocks/db";
import {
  act,
  mainContent,
  renderApp,
  server,
  waitFor,
} from "@test/support/test-utils";

describe("Scan polling", () => {
  it.each(["completed", "partial", "failed"])(
    "polls queued/running every 3 seconds and stops at %s",
    async (terminal) => {
      const scan = makeScan({ status: "queued" });
      db.scans = [scan];
      let status = "queued";
      let requests = 0;
      server.use(
        http.get("/api/v1/scans/:scanId", () => {
          requests++;
          return HttpResponse.json({ ...scan, status });
        }),
      );
      // Only fake intervals: MSW's network work and waitFor keep their real timers.
      vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
      let app: Awaited<ReturnType<typeof renderApp>> | undefined;
      try {
        app = await renderApp(`/scans/${scan.id}`);
        await mainContent().findByText(/Scan queued; tự cập nhật/);
        const initialRequests = requests;
        await act(async () => {
          await vi.advanceTimersByTimeAsync(SCAN_POLL_INTERVAL - 1);
        });
        expect(requests).toBe(initialRequests);
        status = "running";
        await act(async () => {
          await vi.advanceTimersByTimeAsync(1);
        });
        await mainContent().findByText(/Scan running; tự cập nhật/);
        expect(requests).toBe(initialRequests + 1);
        status = terminal;
        await act(async () => {
          await vi.advanceTimersByTimeAsync(SCAN_POLL_INTERVAL);
        });
        await waitFor(() =>
          expect(
            mainContent().getByText(terminal, { exact: true }),
          ).toBeInTheDocument(),
        );
        const terminalRequests = requests;
        await act(async () => {
          await vi.advanceTimersByTimeAsync(SCAN_POLL_INTERVAL * 3);
        });
        expect(requests).toBe(terminalRequests);
      } finally {
        app?.unmount();
        app?.queryClient.clear();
        vi.useRealTimers();
      }
    },
  );
});
