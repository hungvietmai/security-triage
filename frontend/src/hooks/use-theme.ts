import { useContext } from "react";
import { ThemeContext, type ThemeState } from "@/lib/theme";

export function useTheme(): ThemeState {
  const state = useContext(ThemeContext);
  if (!state) throw new Error("useTheme must be used within <ThemeProvider>");
  return state;
}
