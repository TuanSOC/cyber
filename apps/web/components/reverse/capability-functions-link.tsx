"use client";

/**
 * "Functions (n)" on a capability row of the Malware Lab (M10 phase 1 SLOT, mounted once in
 * `components/malware/signature-tabs.tsx`; phase 10 fills it): links to the functions of the
 * newest RE job of the sample that contain the capability's locations (RT8). A capability
 * without locations (a static job from before M10) says "re-run static analysis to link".
 * Renders nothing until phase 10.
 */
export function CapabilityFunctionsLink(_props: {
  orgId: string;
  staticJobId: string;
  capabilityId: string;
  locations: readonly string[];
  functions: number | null | undefined;
}) {
  return null;
}
