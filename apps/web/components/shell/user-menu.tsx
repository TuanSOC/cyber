"use client";

import { useQueryClient } from "@tanstack/react-query";
import { ChevronsUpDown, LogOut, UserRound } from "lucide-react";
import { useRouter } from "next/navigation";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem } from "@/components/ui/sidebar";
import { api } from "@/lib/api";
import { useMe } from "@/lib/use-me";

export function UserMenu() {
  const me = useMe();
  const router = useRouter();
  const queryClient = useQueryClient();
  const user = me.data?.user;

  async function logout() {
    // A 403 (no CSRF cookie) means the session is already gone: treat as logged out.
    await api.POST("/api/v1/auth/logout").catch(() => undefined);
    router.replace("/login");
    // After navigating away, so mounted queries do not refetch with a dead session.
    queryClient.removeQueries();
  }

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton size="lg" tooltip={user?.display_name}>
              <UserRound aria-hidden />
              <span className="flex min-w-0 flex-col text-left leading-tight">
                <span className="truncate text-sm font-medium">{user?.display_name}</span>
                <span className="truncate text-xs text-muted-foreground">{user?.email}</span>
              </span>
              <ChevronsUpDown className="ml-auto size-4" aria-hidden />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-56" align="end" side="top">
            <DropdownMenuLabel className="truncate">{user?.email}</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={logout}>
              <LogOut className="size-4" aria-hidden /> Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
