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
  Settings,
  ShieldAlert,
  Skull,
  type LucideIcon,
} from "lucide-react";

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
    plannedFor: "a later milestone",
    summary: "Volatility 3 memory forensics.",
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
    plannedFor: "Milestone 5",
    summary: "Evidence-cited explanations, timelines and recommendations.",
  },
  {
    key: "reports",
    label: "Reports",
    icon: FileText,
    segment: "reports",
    plannedFor: "Milestone 6",
    summary: "Investigation reports with evidence citations.",
  },
  {
    key: "integrations",
    label: "Integrations",
    icon: Plug,
    segment: "settings/integrations",
    summary: "Threat intelligence provider keys and connectors.",
  },
  { key: "settings", label: "Settings", icon: Settings, segment: "settings", summary: "Organization and members." },
];

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
