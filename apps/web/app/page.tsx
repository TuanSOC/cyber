"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { FullPageLoading } from "@/components/full-page-loading";
import { Button } from "@/components/ui/button";
import { readLastOrg } from "@/lib/last-org";
import { orgPath } from "@/lib/nav";
import { useMe } from "@/lib/use-me";

/** "/" opens the last-used org, else the org the user joined first (their own). */
export default function Home() {
  const router = useRouter();
  const me = useMe();

  useEffect(() => {
    if (me.isError && me.error.status === 401) {
      router.replace("/login");
      return;
    }
    if (!me.data) return;
    const memberships = me.data.memberships;
    const last = readLastOrg();
    // Only orgs the user is a member of; the API lists the oldest membership (their own) first.
    const target =
      memberships.find((m) => m.organization_id === last) ?? memberships.at(0) ?? null;
    router.replace(target ? orgPath(target.organization_id) : "/login");
  }, [me.data, me.isError, me.error, router]);

  if (me.isError && me.error.status !== 401) {
    return (
      <div className="flex min-h-svh flex-col items-center justify-center gap-3 text-center">
        <p className="text-sm text-muted-foreground">The service is unavailable right now.</p>
        <Button variant="outline" size="sm" onClick={() => void me.refetch()}>
          Retry
        </Button>
      </div>
    );
  }
  return <FullPageLoading />;
}
