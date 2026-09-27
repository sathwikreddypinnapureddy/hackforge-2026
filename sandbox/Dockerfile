FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /scanner
COPY lib ./lib
COPY scripts ./scripts
ENV NODE_ENV=production
USER 65532:65532
ENTRYPOINT ["node", "--disable-warning=MODULE_TYPELESS_PACKAGE_JSON", "/scanner/scripts/sandbox-worker.ts"]
