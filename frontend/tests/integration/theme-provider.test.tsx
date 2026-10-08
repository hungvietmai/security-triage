import { act, render, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ThemeProvider } from "@/components/theme-provider";
import { useTheme } from "@/hooks/use-theme";
import { THEME_STORAGE_KEY } from "@/lib/theme";

const wrapper = ({ children }: { children: ReactNode }) => (
  <ThemeProvider>{children}</ThemeProvider>
);

function mockSystemDark(dark: boolean) {
  vi.spyOn(window, "matchMedia").mockImplementation(
    (query: string) =>
      ({
        matches: dark,
        media: query,
        addEventListener: () => {},
        removeEventListener: () => {},
      }) as unknown as MediaQueryList,
  );
}

const html = document.documentElement;

describe("ThemeProvider", () => {
  beforeEach(() => {
    localStorage.clear();
    html.classList.remove("dark");
    mockSystemDark(false);
  });
  afterEach(() => localStorage.clear());

  it("follows the system preference by default", () => {
    mockSystemDark(true);
    const { result } = renderHook(() => useTheme(), { wrapper });
    expect(result.current.theme).toBe("system");
    expect(result.current.resolvedTheme).toBe("dark");
    expect(html).toHaveClass("dark");
  });

  it("applies and remembers an explicit choice", () => {
    const { result } = renderHook(() => useTheme(), { wrapper });
    expect(html).not.toHaveClass("dark");

    act(() => result.current.setTheme("dark"));

    expect(html).toHaveClass("dark");
    expect(html.style.colorScheme).toBe("dark");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
  });

  it("restores the stored theme and ignores invalid values", () => {
    localStorage.setItem(THEME_STORAGE_KEY, "dark");
    expect(renderHook(() => useTheme(), { wrapper }).result.current.theme).toBe(
      "dark",
    );
    localStorage.setItem(THEME_STORAGE_KEY, "sepia");
    expect(renderHook(() => useTheme(), { wrapper }).result.current.theme).toBe(
      "system",
    );
  });

  it("does not render a <script> element", () => {
    const { container } = render(
      <ThemeProvider>
        <p>content</p>
      </ThemeProvider>,
    );
    expect(container.querySelector("script")).toBeNull();
  });

  it("requires a provider", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => renderHook(() => useTheme())).toThrow(/ThemeProvider/);
  });
});
