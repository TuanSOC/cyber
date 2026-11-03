import { ShieldCheck } from "lucide-react";

export function FullPageLoading({ message = "Loading…" }: { message?: string }) {
  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-3 text-muted-foreground">
      <ShieldCheck className="size-8 animate-pulse" aria-hidden />
      <p className="text-sm">{message}</p>
    </div>
  );
}
