"use client";

import { ShieldCheck } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { OrgSwitcher } from "@/components/shell/org-switcher";
import { UserMenu } from "@/components/shell/user-menu";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";
import { NAV, activeNavKey, orgPath } from "@/lib/nav";
import { useOrg } from "@/lib/org-context";

export function AppSidebar() {
  const { orgId } = useOrg();
  const pathname = usePathname();
  const activeKey = activeNavKey(pathname, orgId);

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <div className="flex items-center gap-2 px-2 py-1.5 font-semibold tracking-tight">
          <ShieldCheck className="size-5 shrink-0 text-primary" aria-hidden />
          <span className="truncate group-data-[collapsible=icon]:hidden">CyberLab AI</span>
        </div>
        <OrgSwitcher />
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {NAV.map((item) => {
                const href = orgPath(orgId, item.segment);
                const active = item.key === activeKey;
                return (
                  <SidebarMenuItem key={item.key}>
                    <SidebarMenuButton asChild isActive={active} tooltip={item.label}>
                      <Link href={href}>
                        <item.icon aria-hidden />
                        <span>{item.label}</span>
                      </Link>
                    </SidebarMenuButton>
                    {item.plannedFor && (
                      <SidebarMenuBadge className="text-[10px] text-muted-foreground">
                        soon
                      </SidebarMenuBadge>
                    )}
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter>
        <UserMenu />
      </SidebarFooter>
    </Sidebar>
  );
}
