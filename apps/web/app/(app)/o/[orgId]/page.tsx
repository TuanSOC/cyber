"use client";

import Link from "next/link";

import { PageHeader } from "@/components/page-header";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { NAV, orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";

export default function OverviewPage() {
  const { orgId, orgName } = useOrg();
  const modules = NAV.filter((item) => item.segment && item.key !== "settings");

  return (
    <>
      <PageHeader title="Overview" description={`Workspace for ${orgName}.`} />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {modules.map((item) => (
          <Link key={item.key} href={orgPath(orgId, item.segment)} className="group">
            <Card className="h-full transition-colors group-hover:border-primary/50">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <item.icon className="size-4" aria-hidden />
                  {item.label}
                </CardTitle>
                <CardDescription>
                  {item.summary}
                  {item.plannedFor && (
                    <span className="mt-2 block text-xs">Planned for {item.plannedFor}</span>
                  )}
                </CardDescription>
              </CardHeader>
            </Card>
          </Link>
        ))}
      </div>
    </>
  );
}
