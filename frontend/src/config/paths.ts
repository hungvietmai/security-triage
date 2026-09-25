// Route paths shared by the router (app/) and navigation (components/layouts/).
export const paths = {
  dashboard: { path: "/", label: "Tổng quan" },
  projects: { path: "/projects", label: "Dự án" },
  project: { path: "/projects/$projectId", label: "Dự án" },
  scans: { path: "/scans", label: "Lượt quét" },
  findings: { path: "/findings", label: "Cảnh báo" },
  system: { path: "/system", label: "Hệ thống" },
} as const;
