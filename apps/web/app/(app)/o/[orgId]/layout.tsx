import { OrgShell } from "@/components/shell/org-shell";

export default function OrgLayout({ children }: LayoutProps<"/o/[orgId]">) {
  return <OrgShell>{children}</OrgShell>;
}
