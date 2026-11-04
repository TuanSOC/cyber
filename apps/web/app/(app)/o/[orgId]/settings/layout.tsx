"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { PageHeader } from "@/components/page-header";
import { orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";
import { cn } from "@/lib/utils";

export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  const { orgId, can } = useOrg();
  const pathname = usePathname();
  const tabs = [
    { href: orgPath(orgId, "settings"), label: "Organization" },
    { href: orgPath(orgId, "settings/members"), label: "Members" },
    { href: orgPath(orgId, "settings/integrations"), label: "Integrations" },
    ...(can("audit.read") ? [{ href: orgPath(orgId, "settings/audit"), label: "Audit log" }] : []),
  ];

  return (
    <>
      <PageHeader title="Settings" />
      <nav className="mb-6 flex gap-1 border-b" aria-label="Settings sections">
        {tabs.map((tab) => (
          <Link
            key={tab.href}
            href={tab.href}
            className={cn(
              "-mb-px border-b-2 px-3 py-2 text-sm text-muted-foreground hover:text-foreground",
              pathname === tab.href && "border-primary text-foreground",
              pathname !== tab.href && "border-transparent",
            )}
          >
            {tab.label}
          </Link>
        ))}
      </nav>
      {children}
    </>
  );
}
