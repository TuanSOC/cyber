import path from "node:path";
import type { NextConfig } from "next";

// Docker Desktop on Windows does not forward file events into bind mounts, so dev compose
// opts into polling via NEXT_WATCH_POLL_MS. Unset everywhere else.
const pollIntervalMs = Number(process.env.NEXT_WATCH_POLL_MS) || undefined;

const nextConfig: NextConfig = {
  poweredByHeader: false,
  // Dev only: the e2e container reaches the dev server through the compose hostname
  // `gateway`; Next blocks dev assets for unknown origins by default.
  allowedDevOrigins: ["gateway"],
  ...(pollIntervalMs ? { watchOptions: { pollIntervalMs } } : {}),
  cacheComponents: true,
  // The signed-in area is client-rendered by design (the session cookie is scoped to /api,
  // so only the browser knows the user). It has no meaningful static shell, so neither
  // Partial Prefetching nor implicit instant-navigation validation applies; only segments
  // that explicitly export `instant` are validated.
  experimental: {
    instantInsights: { validationLevel: "manual-warning" },
  },
  // Monorepo: trace from the repo root so workspace packages land in the standalone output.
  output: "standalone",
  outputFileTracingRoot: path.resolve(process.cwd(), "../.."),
  turbopack: {
    root: path.resolve(process.cwd(), "../.."),
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
