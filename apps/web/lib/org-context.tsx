"use client";

import { createContext, useContext } from "react";

import type { MemberRole } from "@/lib/api";
import { can, type Permission } from "@/lib/roles";

export type OrgContextValue = {
  orgId: string;
  orgName: string;
  role: MemberRole;
};

const OrgContext = createContext<OrgContextValue | null>(null);

export const OrgProvider = OrgContext.Provider;

export function useOrg(): OrgContextValue & { can: (permission: Permission) => boolean } {
  const value = useContext(OrgContext);
  if (!value) throw new Error("useOrg must be used inside /o/[orgId]");
  return { ...value, can: (permission) => can(value.role, permission) };
}
