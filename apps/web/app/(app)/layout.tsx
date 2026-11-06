import { Suspense } from "react";

import { AuthGate } from "@/components/auth-gate";
import { FullPageLoading } from "@/components/full-page-loading";
import { StepUpDialog } from "@/components/step-up/step-up-dialog";

// One Suspense boundary for the whole client-rendered app area: route params and search
// params are runtime data under Cache Components.
export default function AppLayout({ children }: LayoutProps<"/">) {
  return (
    <Suspense fallback={<FullPageLoading />}>
      <AuthGate>{children}</AuthGate>
      {/* M11 slot (phase 10): answers `step_up_required` prompts (lib/api.ts STEP_UP_EVENT). */}
      <StepUpDialog />
    </Suspense>
  );
}
