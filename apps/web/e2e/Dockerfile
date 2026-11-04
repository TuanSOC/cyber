# Build context: repository root. Browsers come preinstalled in the Playwright image.
FROM mcr.microsoft.com/playwright:v1.64.1-noble
RUN npm install -g pnpm@10.12.4
WORKDIR /repo
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/web/package.json apps/web/
COPY packages/contracts/package.json packages/contracts/
RUN pnpm install --frozen-lockfile
COPY apps/web/playwright.config.ts apps/web/
COPY apps/web/e2e apps/web/e2e
WORKDIR /repo/apps/web
CMD ["pnpm", "exec", "playwright", "test"]
