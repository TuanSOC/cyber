"use client";

import { Construction } from "lucide-react";
import { useParams } from "next/navigation";

import { NotFoundCard } from "@/components/not-found-card";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { orgPath, plannedModule } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";

/** Modules that are not built yet: an honest placeholder, never sample or fake data. */
export default function PlannedModulePage() {
  const { module } = useParams<{ module: string }>();
  const { orgId } = useOrg();
  const item = plannedModule(module);
  if (!item) {
    return <NotFoundCard title="Page not found" backHref={orgPath(orgId)} backLabel="Overview" />;
  }

  return (
    <>
      <PageHeader title={item.label} description={item.summary} />
      <Card>
        <CardContent className="flex flex-col items-center gap-3 py-16 text-center">
          <Construction className="size-8 text-muted-foreground" aria-hidden />
          <p className="font-medium">Planned for {item.plannedFor}</p>
          <p className="max-w-md text-sm text-muted-foreground">
            This module is not available yet. No data is shown until real analysis results exist.
          </p>
        </CardContent>
      </Card>
    </>
  );
}
