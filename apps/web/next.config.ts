import path from "node:path";
import type { NextConfig } from "next";

// Docker Desktop on Windows does not forward file events into bind mounts, so dev compose
// opts into polling via NEXT_WATCH_POLL_MS. Unset everywhere else.
const pollIntervalMs = Number(process.env.NEXT_WATCH_POLL_MS) || undefined;

const nextConfig: NextConfig = {
  ...(pollIntervalMs ? { watchOptions: { pollIntervalMs } } : {}),
  cacheComponents: true,
  partialPrefetching: true,
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
