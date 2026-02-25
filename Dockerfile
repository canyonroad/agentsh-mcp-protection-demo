# Multi-stage build:
#   1. Build the two fake MCP servers
#   2. Install agentsh + servers + demo script into a slim runtime image

# --- Stage 1: Build MCP servers ---
FROM golang:1.25-bookworm AS builder

WORKDIR /src/notes-server
COPY servers/notes-server/ .
RUN go build -o /out/mcp-server-notes .

WORKDIR /src/web-server
COPY servers/web-server/ .
RUN go build -o /out/mcp-server-web .

# --- Stage 2: Runtime ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl jq && \
    rm -rf /var/lib/apt/lists/*

# Install agentsh from .deb (mount or download at build time).
# For local builds: docker build --build-arg AGENTSH_DEB=./agentsh.deb .
ARG AGENTSH_DEB=""
ARG AGENTSH_VERSION=latest
ARG AGENTSH_ARCH=amd64

# If a local .deb is provided, use it; otherwise download from GitHub releases.
COPY ${AGENTSH_DEB:-.dockerignore} /tmp/agentsh-maybe.deb
RUN if [ -s /tmp/agentsh-maybe.deb ] && dpkg-deb --info /tmp/agentsh-maybe.deb >/dev/null 2>&1; then \
        dpkg -i /tmp/agentsh-maybe.deb; \
    else \
        echo "No local agentsh .deb provided — install agentsh manually or rebuild with AGENTSH_DEB"; \
    fi && \
    rm -f /tmp/agentsh-maybe.deb

# Copy MCP server binaries.
COPY --from=builder /out/mcp-server-notes /usr/local/bin/mcp-server-notes
COPY --from=builder /out/mcp-server-web   /usr/local/bin/mcp-server-web

# Copy configs.
COPY agentsh-config.yaml /etc/agentsh/config.yaml
COPY policy.yaml         /etc/agentsh/policies/demo-permissive.yaml

# Copy demo script.
COPY run-demo.sh /usr/local/bin/run-demo.sh
RUN chmod +x /usr/local/bin/run-demo.sh

# Prepare agentsh data dirs.
RUN mkdir -p /var/lib/agentsh/sessions /var/lib/agentsh

WORKDIR /demo
ENTRYPOINT ["/usr/local/bin/run-demo.sh"]
