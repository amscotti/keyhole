# Keyhole — multi-stage container image.
#
# Two runtime targets:
#   - full (default): debian-slim with pandoc, so the office transform works
#     out of the box.
#   - minimal: distroless/cc with only the binary — smallest attack surface,
#     but office returns "unsupported" without pandoc. YouTube needs no
#     external binary, so it works in both images.
#
# Build:
#   docker build -t keyhole .                          # full (default)
#   docker build --target minimal -t keyhole:minimal . # minimal
#
# Run:
#   docker run -p 8080:8080 \
#     -v "$PWD/config.toml:/etc/keyhole/config.toml:ro" \
#     keyhole --config /etc/keyhole/config.toml
#
# No placeholder secret env vars are baked in: the example config's auth
# profiles reference ${KEYHOLE_*}, and an unset value fails config load loudly
# (mount your own config and set real env vars).

# ---- Builder ---------------------------------------------------------------
FROM golang:1.26.5-bookworm AS builder

WORKDIR /src

# Cache module downloads: copy manifests first.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source and build a static binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/keyhole ./cmd/keyhole


# ---- Runtime: minimal (distroless, no pandoc) -------------------------------
# Smallest image for the statically-linked Go binary. Office returns
# "unsupported" (no pandoc); raw/markdown/article/youtube and all policy
# enforcement work.
#
# No HEALTHCHECK: distroless has no shell, curl, or wget, and shipping a helper
# binary would grow the attack surface this target exists to shrink. Probe
# /healthz from outside the container (orchestrator/K8s probe) instead.
FROM gcr.io/distroless/cc-debian12:nonroot AS minimal

COPY --from=builder /out/keyhole /keyhole
COPY config.example.toml /etc/keyhole/config.example.toml

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/keyhole"]
CMD ["--config", "/etc/keyhole/config.example.toml"]


# ---- Runtime: full (debian-slim, with pandoc) ------------------------------
# Default target. Includes pandoc (office→markdown) so every transform works.
# ca-certificates enables HTTPS. Runs as non-root (uid 65532) to match the
# minimal target's threat posture: a compromised pandoc or transform path must
# not have root.
FROM debian:bookworm-slim AS full

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        pandoc \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 keyhole \
    && useradd --uid 65532 --gid 65532 --shell /usr/sbin/nologin --create-home keyhole

COPY --from=builder /out/keyhole /usr/local/bin/keyhole
COPY config.example.toml /etc/keyhole/config.example.toml

USER keyhole:keyhole
EXPOSE 8080
ENTRYPOINT ["keyhole"]
CMD ["--config", "/etc/keyhole/config.example.toml"]

# HTTP probe without curl/wget: bash's /dev/tcp + grep, both essential in
# debian-slim. Assumes REST mode on the default listen (:8080); override or
# disable when running MCP mode or a different port.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/bin/bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8080 && printf 'GET /healthz HTTP/1.0\\n\\n' >&3 && head -n 1 <&3 | grep -q ' 200 '"]
