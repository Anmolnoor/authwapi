# Build stage: compiles better-sqlite3 if no prebuilt binary exists for this Node version.
FROM node:26-slim AS deps
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:26-slim
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json LICENSE ./
COPY src ./src
COPY migrations ./migrations
COPY docker/entrypoint.sh /usr/local/bin/authwapi-entrypoint
ENV NODE_ENV=production DATA_DIR=/data PORT=4000
VOLUME /data
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||4000)+'/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
ENTRYPOINT ["authwapi-entrypoint"]
