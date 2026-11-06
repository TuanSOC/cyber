"use client";

/**
 * "Explain function" (M10 phase 1 SLOT, used inside the RE pages only; phase 10 fills it with
 * the `explain_function` AI run of phase 9): the target is one `re_functions` row; the API
 * refuses the task (`422 task_not_applicable`) until phase 9. Renders nothing until phase 10.
 */
export function ExplainFunctionButton(_props: { orgId: string; jobId: string; functionId: string }) {
  return null;
}
