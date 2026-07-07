# syntax=docker/dockerfile:1.7
# Multi-stage build: compile a fully static binary then copy it into distroless.
#
# Build reproducibility:
#   docker buildx build \
#     --platform linux/amd64,linux/arm64 \
#     --build-arg BUILD_VERSION=$(git describe --tags --always) \
#     -t ghcr.io/operitas-eu/collector:$(git describe --tags --always) \
#     collector/

ARG GO_VERSION=1.25
ARG DISTROLESS_TAG=nonroot

# ---- build stage ----
FROM golang:${GO_VERSION}-alpine AS build

# Must match the build-arg name passed by .github/workflows/release.yml and
# .github/workflows/ci.yml (BUILD_VERSION) — a name mismatch here silently
# drops the arg and every image reports main.version=dev regardless of the
# tag it was built from. Verified empirically before this fix landed; see
# CHANGELOG.md [0.2.0].
ARG BUILD_VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src

# Copy dependency files first so Docker layer cache survives code-only changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${BUILD_VERSION} \
                -extldflags '-static'" \
      -o /out/collector \
      ./cmd/collector

# ---- final stage ----
# gcr.io/distroless/static-debian12:nonroot provides:
#   - no shell (attack surface reduction)
#   - nonroot UID 65532 by default
#   - no package manager
#   - read-only root filesystem compatible (no /tmp, no /var writeable)
FROM gcr.io/distroless/static-debian12:${DISTROLESS_TAG}

LABEL org.opencontainers.image.title="collector" \
      org.opencontainers.image.description="Read-only DORA evidence collector" \
      org.opencontainers.image.vendor="ReOps Tech S.R.L." \
      org.opencontainers.image.url="https://operitas.eu" \
      org.opencontainers.image.source="https://github.com/operitas-eu/collector" \
      org.opencontainers.image.licenses="MIT"

# Run as the distroless nonroot user (UID 65532). Never root.
USER nonroot:nonroot

# The collector writes WAL and state to /var/lib/operitas/ which is mounted as
# a PVC in the Helm chart. The root filesystem is mounted read-only.
COPY --from=build /out/collector /collector

EXPOSE 8081 8082 9090

ENTRYPOINT ["/collector"]
