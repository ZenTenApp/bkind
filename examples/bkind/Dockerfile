# syntax=docker/dockerfile:1
#
# A static image for the kind-4 DM relay in this directory.
#
# Build from the repository root (the module boundary):
#
#   docker build -f examples/bkind/Dockerfile -t bkind .
#
# or just use docker-compose.yml next to this file.

FROM golang:1.24-alpine AS build

# never download a toolchain at build time: the image's Go is the one we test with
ENV GOTOOLCHAIN=local \
    CGO_ENABLED=0

WORKDIR /src

# dependencies first, so editing the relay does not re-resolve the module graph
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

# CGO off is what makes the scratch stage possible: badger and the relay are pure
# Go, so the result has no libc and no dynamic loader
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o /out/bkind ./examples/bkind \
 && mkdir -p /out/data

# ---------------------------------------------------------------- runtime
FROM scratch

# numeric id: scratch has no /etc/passwd, and "nobody" is 65534 on every distro
USER 65534:65534

COPY --from=build /out/bkind /usr/local/bin/bkind

# badger needs a writable directory, and it has to be owned by 65534 *in the image*:
# an empty named volume inherits the ownership of the image directory it mounts
# over. WORKDIR alone would create /data root-owned and the relay would fail to
# open its database.
COPY --from=build --chown=65534:65534 /out/data /data
WORKDIR /data

# only the process settings live here. The policy set (kinds, limits, rate limits)
# is policies.DefaultConfig inside the binary, overridden by BKIND_CONFIG /
# BKIND_CONFIG_JSON / BKIND_* — see docs/cookbook/configuration.md. Duplicating the
# limits here would be a second source of truth that silently drifts.
ENV BKIND_ADDR=:3334 \
    BKIND_DB=/data \
    BKIND_SWEEP_INTERVAL=5m

# BKIND_URL has no default on purpose: NIP-42 auth events and NIP-62 vanish
# requests are both matched against it, so a wrong value breaks writes silently.
# Set it to the exact URL clients connect to, for example wss://dm.example.com

VOLUME ["/data"]
EXPOSE 3334

# the relay drains in-flight requests and closes the store on SIGTERM; keep
# docker's grace period longer than the 15s shutdown timeout (see docker-compose)
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/bkind"]
