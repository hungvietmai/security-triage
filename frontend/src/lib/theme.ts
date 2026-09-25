import { createContext } from "react";

export type Theme = "light" | "dark" | "system";
export type ResolvedTheme = Exclude<Theme, "system">;

export interface ThemeState {
  /** The user's choice, possibly "system". */
  theme: Theme;
  /** What is actually shown. */
  resolvedTheme: ResolvedTheme;
  setTheme: (theme: Theme) => void;
}

/** Shared with the pre-paint script in index.html; keep both in sync. */
export const THEME_STORAGE_KEY = "theme";
export const DARK_QUERY = "(prefers-color-scheme: dark)";

export const ThemeContext = createContext<ThemeState | null>(null);

export function isTheme(value: unknown): value is Theme {
  return value === "light" || value === "dark" || value === "system";
}

/** Storage may be unavailable (private mode, blocked site data). */
export function readStoredTheme(fallback: Theme): Theme {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    return isTheme(stored) ? stored : fallback;
  } catch {
    return fallback;
  }
}

export function storeTheme(theme: Theme): void {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // The choice still applies for this session.
  }
}
