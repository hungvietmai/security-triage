import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, beforeEach } from "vitest";
import { resetDb } from "@/testing/mocks/db";
import { server } from "@/testing/mocks/server";

// jsdom lacks these browser APIs used by next-themes, the sidebar and Radix.
// Node-environment tests (e.g. architecture.test.ts) have no window at all.
if (typeof window !== "undefined") {
  window.matchMedia ??= (query: string) =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }) as MediaQueryList;
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
  Element.prototype.scrollIntoView ??= () => {};
}

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => resetDb());
afterEach(() => {
  cleanup();
  server.resetHandlers();
});
afterAll(() => server.close());
