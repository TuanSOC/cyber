import { Suspense } from "react";

import { AuthGate } from "@/components/auth-gate";
import { FullPageLoading } from "@/components/full-page-loading";

// One Suspense boundary for the whole client-rendered app area: route params and search
// params are runtime data under Cache Components.
export default function AppLayout({ children }: LayoutProps<"/">) {
  return (
    <Suspense fallback={<FullPageLoading />}>
      <AuthGate>{children}</AuthGate>
    </Suspense>
  );
}
