# Build context: repository root.  docker build -f deploy/server.Dockerfile .
FROM node:26-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/shared/package.json packages/shared/
COPY apps/server/package.json apps/server/
COPY apps/web/package.json apps/web/
RUN npm ci --no-audit --no-fund
COPY tsconfig.base.json ./
COPY packages packages
COPY apps/server apps/server
RUN npm run build -w @enclavier/server && npm prune --omit=dev --no-audit --no-fund

FROM node:26-alpine
WORKDIR /app
ARG ENCLAVIER_VERSION=dev
ENV NODE_ENV=production ENCLAVIER_VERSION=${ENCLAVIER_VERSION}
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/apps/server/dist ./apps/server/dist
USER node
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD wget -qO- http://127.0.0.1:8080/health || exit 1
CMD ["node", "apps/server/dist/index.js"]
