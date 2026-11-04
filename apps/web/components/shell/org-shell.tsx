"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect } from "react";

import { AppSidebar } from "@/components/shell/app-sidebar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { rememberOrg } from "@/lib/last-org";
import { OrgProvider } from "@/lib/org-context";
import { ROLE_LABELS } from "@/lib/roles";
import { useMe } from "@/lib/use-me";

export function OrgShell({ children }: { children: React.ReactNode }) {
  const { orgId } = useParams<{ orgId: string }>();
  const me = useMe();
  const membership = me.data?.memberships.find((m) => m.organization_id === orgId);

  useEffect(() => {
    if (membership) rememberOrg(membership.organization_id);
  }, [membership]);

  if (!me.data) return null; // AuthGate renders the loading state
  if (!membership) {
    return (
      <main className="flex min-h-svh flex-col items-center justify-center gap-4 p-6 text-center">
        <h1 className="text-xl font-semibold">Organization not found</h1>
        <p className="max-w-sm text-sm text-muted-foreground">
          It does not exist or you are not a member of it.
        </p>
        <Button asChild variant="outline">
          <Link href="/">Go to my organization</Link>
        </Button>
      </main>
    );
  }

  return (
    <OrgProvider
      value={{ orgId, orgName: membership.organization_name, role: membership.role }}
    >
      <SidebarProvider>
        <AppSidebar />
        {/* min-w-0: wide content (tables) scrolls inside its card, never widens the page */}
        <SidebarInset className="min-w-0">
          <header className="flex h-14 shrink-0 items-center gap-3 border-b px-4 print:hidden">
            <SidebarTrigger />
            <Separator orientation="vertical" className="h-5" />
            {/* Prominent org name: the user always knows which tenant they act in. */}
            <span className="truncate font-semibold" title={membership.organization_name}>
              {membership.organization_name}
            </span>
            <Badge variant="secondary">{ROLE_LABELS[membership.role]}</Badge>
          </header>
          <div className="min-w-0 flex-1 p-4 md:p-6 print:p-0">{children}</div>
        </SidebarInset>
      </SidebarProvider>
    </OrgProvider>
  );
}
