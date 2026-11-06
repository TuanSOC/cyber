import type { Schemas } from "@cyberlab/contracts";

import { AUTH_EXPIRED_EVENT, ApiError, type ApiErrorBody, refreshSession } from "@/lib/api";
import { readCsrfToken } from "@/lib/csrf";

export type UploadHandle = {
  promise: Promise<Schemas["EvidenceOut"]>;
  abort: () => void;
};

/**
 * Streams the raw file to the evidence endpoint with XHR (fetch has no upload progress).
 * Never auto-resends a large body: on 401 the session is refreshed and the caller offers a
 * retry; if the session is gone the app is told to sign in again.
 */
export function uploadEvidence(
  orgId: string,
  investigationId: string,
  file: File,
  description: string,
  onProgress: (fraction: number) => void,
  options: { kind?: "memory" } = {},
): UploadHandle {
  const xhr = new XMLHttpRequest();
  const query = new URLSearchParams({ filename: file.name, description });
  // M8: a memory image (its own size limit, restricted from the upload, no automatic analysis).
  if (options.kind) query.set("kind", options.kind);
  const url =
    `/api/v1/orgs/${encodeURIComponent(orgId)}/investigations/` +
    `${encodeURIComponent(investigationId)}/evidence?${query}`;

  const promise = new Promise<Schemas["EvidenceOut"]>((resolve, reject) => {
    xhr.open("POST", url);
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.setRequestHeader("X-CSRF-Token", readCsrfToken());
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(event.loaded / event.total);
    };
    xhr.onload = async () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(JSON.parse(xhr.responseText) as Schemas["EvidenceOut"]);
        return;
      }
      let body: ApiErrorBody | null = null;
      try {
        body = JSON.parse(xhr.responseText) as ApiErrorBody;
      } catch {
        body = null;
      }
      if (xhr.status === 401) {
        const refreshed = await refreshSession();
        if (refreshed === "ok") {
          reject(new ApiError(401, "session_refreshed", "Your session was refreshed. Retry the upload."));
          return;
        }
        if (refreshed === "expired") window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT));
      }
      const retryAfter = Number(xhr.getResponseHeader("retry-after"));
      reject(
        new ApiError(
          xhr.status,
          body?.error.code ?? "upload_failed",
          body?.error.message ?? `Upload failed (${xhr.status})`,
          body?.error.details,
          Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : undefined,
        ),
      );
    };
    xhr.onerror = () =>
      reject(
        new ApiError(
          0,
          "network_error",
          "Upload interrupted. A very large file may exceed the evidence size limit or the organization's storage quota.",
        ),
      );
    xhr.onabort = () => reject(new ApiError(0, "aborted", "Upload cancelled"));
    xhr.send(file);
  });

  return { promise, abort: () => xhr.abort() };
}
