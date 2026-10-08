import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, beforeEach } from "vitest";
import { resetDb } from "@/testing/mocks/db";
import { server } from "@test/support/server";

// jsdom lacks these browser APIs used by the theme provider, the sidebar and Radix.
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
  Element.prototype.hasPointerCapture ??= () => false;
  Element.prototype.setPointerCapture ??= () => {};
  Element.prototype.releasePointerCapture ??= () => {};
  // jsdom defines scrollTo but only logs "Not implemented"; the router's scroll
  // restoration calls it on every navigation.
  window.scrollTo = () => {};
}

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => resetDb());
afterEach(() => {
  cleanup();
  server.resetHandlers();
});
afterAll(() => server.close());
