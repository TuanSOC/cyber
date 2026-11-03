import { ShieldCheck } from "lucide-react";
import { Suspense } from "react";

import { FullPageLoading } from "@/components/full-page-loading";

export default function AuthLayout({ children }: LayoutProps<"/">) {
  return (
    <main className="flex min-h-svh flex-col items-center justify-center gap-6 px-4 py-12">
      <div className="flex items-center gap-2 text-lg font-semibold tracking-tight">
        <ShieldCheck className="size-6 text-primary" aria-hidden />
        CyberLab AI
      </div>
      <div className="w-full max-w-sm">
        <Suspense fallback={<FullPageLoading />}>{children}</Suspense>
      </div>
    </main>
  );
}
