"use client";

import { useState } from "react";

import { OperationsPanel } from "@/components/ops/ops-metrics";
import type { OpsWindow } from "@/lib/ops-metrics";
import { useOrg } from "@/lib/org-context";

export default function OperationsSettingsPage() {
  const { orgId, can } = useOrg();
  const [range, setRange] = useState<OpsWindow>("24h");
  if (!can("audit.read")) {
    return <p className="text-sm text-muted-foreground">Only owners and admins can view operations metrics.</p>;
  }
  return <OperationsPanel orgId={orgId} range={range} onRangeChange={setRange} />;
}
