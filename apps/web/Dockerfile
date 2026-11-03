# Build context: repository root (the web app depends on workspace packages).
FROM node:22.23-slim AS base
RUN npm install -g pnpm@10.12.4
ENV NEXT_TELEMETRY_DISABLED=1
WORKDIR /repo

FROM base AS deps
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/web/package.json apps/web/
COPY packages/contracts/package.json packages/contracts/
RUN pnpm install --frozen-lockfile

FROM deps AS dev
# Source is bind-mounted; node_modules stay in anonymous volumes (Linux binaries).
ENV NEXT_WATCH_POLL_MS=1000
WORKDIR /repo/apps/web
CMD ["pnpm", "dev"]

FROM deps AS build
COPY packages ./packages
COPY apps/web ./apps/web
RUN pnpm --filter @cyberlab/web build

FROM node:22.23-slim AS prod
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=3000
WORKDIR /srv
COPY --from=build --chown=node:node /repo/apps/web/.next/standalone ./
COPY --from=build --chown=node:node /repo/apps/web/.next/static ./apps/web/.next/static
COPY --from=build --chown=node:node /repo/apps/web/public ./apps/web/public
USER node
CMD ["node", "apps/web/server.js"]
