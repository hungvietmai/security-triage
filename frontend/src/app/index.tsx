import { RouterProvider } from "@tanstack/react-router";
import { useState } from "react";
import { AppProvider } from "@/app/provider";
import { createAppRouter } from "@/app/router";
import { createQueryClient } from "@/lib/react-query";

export function App() {
  const [queryClient] = useState(() => createQueryClient());
  const [router] = useState(() => createAppRouter({ queryClient }));

  return (
    <AppProvider queryClient={queryClient}>
      <RouterProvider router={router} />
    </AppProvider>
  );
}
