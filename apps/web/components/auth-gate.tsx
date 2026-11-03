"use client";

import { useQueryClient } from "@tanstack/react-query";
import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";

import { FullPageLoading } from "@/components/full-page-loading";
import { Button } from "@/components/ui/button";
import { AUTH_EXPIRED_EVENT } from "@/lib/api";
import { useMe } from "@/lib/use-me";

/**
 * Client-side route guard. The access cookie is scoped to /api, so the Next server never
 * sees it; the API remains the only real enforcement point.
 */
export function AuthGate({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const queryClient = useQueryClient();
  const me = useMe();

  useEffect(() => {
    const toLogin = () => {
      queryClient.clear(); // never show one user's cached data to the next
      router.replace(`/login?next=${encodeURIComponent(pathname)}`);
    };
    if (me.isError && me.error.status === 401) toLogin();
    window.addEventListener(AUTH_EXPIRED_EVENT, toLogin);
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, toLogin);
  }, [me.isError, me.error, pathname, router, queryClient]);

  if (me.isPending || (me.isError && me.error.status === 401)) return <FullPageLoading />;
  if (me.isError) {
    return (
      <div className="flex min-h-svh flex-col items-center justify-center gap-3 text-center">
        <p className="text-sm text-muted-foreground">The service is unavailable right now.</p>
        <Button variant="outline" size="sm" onClick={() => void me.refetch()}>
          Retry
        </Button>
      </div>
    );
  }
  return <>{children}</>;
}
