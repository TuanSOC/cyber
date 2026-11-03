import Link from "next/link";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

/** In-page "not found" for client-rendered routes (API 404s, unknown modules). */
export function NotFoundCard({ title, backHref, backLabel }: { title: string; backHref: string; backLabel: string }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center gap-3 py-16 text-center">
        <p className="font-medium">{title}</p>
        <p className="max-w-sm text-sm text-muted-foreground">
          It does not exist, or you do not have access to it in this organization.
        </p>
        <Button asChild variant="outline" size="sm">
          <Link href={backHref}>{backLabel}</Link>
        </Button>
      </CardContent>
    </Card>
  );
}
