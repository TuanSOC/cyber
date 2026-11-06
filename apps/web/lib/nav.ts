import {
  Binary,
  Bot,
  Cpu,
  FileText,
  FolderSearch,
  HardDrive,
  LayoutDashboard,
  Network,
  Plug,
  Search,
  Settings,
  ShieldAlert,
  Skull,
  type LucideIcon,
} from "lucide-react";

import type { Permission } from "@/lib/roles";

export type NavItem = {
  key: string;
  label: string;
  icon: LucideIcon;
  /** Path segment under /o/[orgId]; "" is the overview. */
  segment: string;
  /** Set when the module is not built yet: shown as a planned page, never with fake data. */
  plannedFor?: string;
  summary: string;
};

export const NAV: NavItem[] = [
  { key: "overview", label: "Overview", icon: LayoutDashboard, segment: "", summary: "Case activity at a glance." },
  {
    key: "search",
    label: "Search",
    icon: Search,
    segment: "search",
    summary: "Org-wide search of cases, evidence, findings, alerts, notes and observables.",
  },
  {
    key: "investigations",
    label: "Investigations",
    icon: FolderSearch,
    segment: "investigations",
    summary: "Cases, evidence, hashes and chain of custody.",
  },
  {
    key: "pcap",
    label: "PCAP Analyzer",
    icon: Network,
    segment: "pcap",
    summary: "TShark, Zeek and Suricata analysis of captures with normalized findings.",
  },
  {
    key: "malware",
    label: "Malware Lab",
    icon: Skull,
    segment: "malware",
    summary: "Static analysis: PE/ELF metadata, YARA, capa, FLOSS, ClamAV, entropy, IOC extraction.",
  },
  {
    key: "forensics",
    label: "Forensics",
    icon: HardDrive,
    segment: "forensics",
    plannedFor: "a later milestone",
    summary: "Disk forensics with The Sleuth Kit and Plaso timelines.",
  },
  {
    key: "memory",
    label: "Memory Analysis",
    icon: Cpu,
    segment: "memory",
    summary: "Volatility 3 triage of memory images, offline: processes, network, memory regions and more.",
  },
  {
    key: "re",
    label: "Reverse Engineering",
    icon: Binary,
    segment: "reverse-engineering",
    plannedFor: "a later milestone",
    summary: "Ghidra headless and radare2 analysis.",
  },
  {
    key: "ti",
    label: "Threat Intel",
    icon: ShieldAlert,
    segment: "intel",
    summary: "IOC lookups and enrichment history from your enabled providers, source-attributed.",
  },
  {
    key: "ai",
    label: "AI Analyst",
    icon: Bot,
    segment: "ai-analyst",
    summary: "Evidence-cited explanations, timelines and recommendations.",
  },
  {
    key: "reports",
    label: "Reports",
    icon: FileText,
    segment: "reports",
    summary: "Investigation reports with evidence citations.",
  },
  {
    key: "integrations",
    label: "Integrations",
    icon: Plug,
    segment: "settings/integrations",
    summary: "Threat intelligence and AI provider keys and settings",
  },
  { key: "settings", label: "Settings", icon: Settings, segment: "settings", summary: "Organization and members." },
];

export type SettingsTab = {
  key: string;
  label: string;
  /** Path segment under /o/[orgId]. */
  segment: string;
  /** Shown only to members holding it (the API enforces it either way). */
  permission?: Permission;
};

/** The settings sub-navigation (M7 adds Retention and Operations). */
export const SETTINGS_TABS: SettingsTab[] = [
  { key: "organization", label: "Organization", segment: "settings" },
  { key: "members", label: "Members", segment: "settings/members" },
  { key: "integrations", label: "Integrations", segment: "settings/integrations" },
  { key: "retention", label: "Retention", segment: "settings/retention", permission: "org.read" },
  { key: "operations", label: "Operations", segment: "settings/operations", permission: "audit.read" },
  { key: "audit", label: "Audit log", segment: "settings/audit", permission: "audit.read" },
];

export function settingsTabs(can: (permission: Permission) => boolean): SettingsTab[] {
  return SETTINGS_TABS.filter((tab) => !tab.permission || can(tab.permission));
}

export function plannedModule(segment: string): NavItem | undefined {
  return NAV.find((item) => item.segment === segment && item.plannedFor);
}

/** The nav item for a path: the longest matching segment wins ("settings/integrations" over "settings"). */
export function activeNavKey(pathname: string, orgId: string): string | undefined {
  let best: NavItem | undefined;
  for (const item of NAV) {
    const href = orgPath(orgId, item.segment);
    const match = item.segment ? pathname === href || pathname.startsWith(`${href}/`) : pathname === href;
    if (match && (!best || item.segment.length > best.segment.length)) best = item;
  }
  return best?.key;
}

export function orgPath(orgId: string, segment = ""): string {
  return segment ? `/o/${orgId}/${segment}` : `/o/${orgId}`;
}
