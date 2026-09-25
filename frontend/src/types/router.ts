import type { ComponentType } from "react";

declare module "@tanstack/react-router" {
  interface StaticDataRouteOption {
    /** Breadcrumb label, or a component when the label depends on data. */
    crumb?: string | ComponentType;
  }
}
