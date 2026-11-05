"use client";

import type { Schemas } from "@cyberlab/contracts";

/**
 * Slot (M7 phase 1, RT16): the evidence integrity strip (bytes purged on ..., hashes and custody
 * retained; declared vs detected type mismatch), mounted once in the evidence page. Phase 9
 * fills it from `EvidenceOut.purged_at`, `type_mismatch` and `declared_type`. Renders nothing
 * until then.
 */
export function EvidenceIntegrityStrip({ evidence }: { evidence: Schemas["EvidenceOut"] }) {
  void evidence;
  return null;
}
