# ─────────────────────────────────────────────────────────────────────────────
# 1) Build VSCode extension (Node/TypeScript) in isolation
# ─────────────────────────────────────────────────────────────────────────────
FROM node:20-bullseye AS ext-builder

WORKDIR /workspace/extension

# Copy dependency files first for better caching
COPY extension/package.json extension/package-lock.json ./
RUN npm install --quiet

# Copy remaining source and build
COPY extension/ ./
RUN npm run compile

# ─────────────────────────────────────────────────────────────────────────────
# 2) Install CASR from crates.io with dojo feature
# ─────────────────────────────────────────────────────────────────────────────
FROM rust:1.75-slim AS casr-builder

RUN rustup default nightly && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# Install casr with dojo feature
RUN cargo install casr --features dojo

# ─────────────────────────────────────────────────────────────────────────────
# 3) Final runtime image: .NET + tools + AFL++ + CASR + extension server
# ─────────────────────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/runtime:6.0-focal

# install system deps
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential clang llvm cmake git unzip sudo \
      python3 python3-pip libssl-dev pkg-config \
      afl++ curl gnupg ca-certificates && \
    # Node 20 setup
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# copy CASR from builder
COPY --from=casr-builder /usr/local/cargo/bin/casr-* /usr/local/bin/

# create app dir
WORKDIR /app

# copy in your .env (make sure it's gitignored locally)
COPY .env* ./
# copy ssl certs so your code can do fs.readFileSync('ssl/cert.pem')
COPY ssl/ ./ssl/
COPY Fuzzers/ ./Fuzzers/
# copy the extension server bits
COPY --from=ext-builder /workspace/extension/package.json   ./package.json
COPY --from=ext-builder /workspace/extension/package-lock.json ./package-lock.json
COPY --from=ext-builder /workspace/extension/out             ./out

# install production deps
RUN npm install --omit=dev --quiet && \
    npm install chokidar --quiet && \
    npm install -g node-inspect --quiet

# make non-root
RUN groupadd -r appuser && useradd -r -g appuser appuser && \
    chown -R appuser:appuser /app
USER appuser

# ports
EXPOSE 3000 9229

# start with inspector + your api
ENTRYPOINT ["node", "--inspect=0.0.0.0", "out/api/server.js"]
