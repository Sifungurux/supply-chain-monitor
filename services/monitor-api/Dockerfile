# --- monitor-api build stage ---
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
# go.sum isn't committed (see go.mod's comment: it was written in a
# sandbox with no Go toolchain, so real checksums couldn't be
# generated there). `go mod tidy` resolves the dependency graph and
# writes a correct go.sum here, at build time, against the real module
# proxy/checksum database -- this build stage needs network access the
# first time an image is built or a dependency changes. Once someone
# runs `go mod tidy` locally and commits go.sum, this becomes a no-op
# verification step instead of a resolution step.
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o /out/monitor-api .

# --- umoci build stage ---
# Built from source rather than pulling the project's release binary
# (which only ships amd64), so this also works on Apple Silicon Macs
# (arm64 Colima/Podman VMs) without emulation. If this stage fails
# because umoci's go.mod wants a newer toolchain, bump the golang tag
# here.
FROM golang:1.22-alpine AS umoci-build
ARG UMOCI_VERSION=0.4.7
RUN apk add --no-cache git
WORKDIR /src/umoci
RUN git clone --depth 1 --branch "v${UMOCI_VERSION}" https://github.com/opencontainers/umoci.git .
RUN CGO_ENABLED=0 go build -o /out/umoci ./cmd/umoci

# --- runtime stage ---
FROM alpine:3.21
# TARGETARCH is set automatically by BuildKit (amd64/arm64) -- used
# below to pick the right oras/unpacker release tarball. umoci (its own
# build stage above) is the one holdout still built from source: its
# upstream releases only ship an amd64 binary, the reason this project
# ever started building anything from source in the first place.
ARG TARGETARCH
# oras (github.com/oras-project/oras) fetches file/sbom/sarif artifacts
# from an OCI registry so their `ref` can be a real registry reference
# instead of assuming the artifact is already a path inside this pod --
# see internal/scanner/fetch.go. Official release tarballs cover both
# amd64 and arm64 directly, so no build-from-source needed here (unlike
# umoci above).
ARG ORAS_VERSION=1.3.2
# github.com/Sifungurux/unpacker: pulls an image/OCI artifact from a
# registry and unpacks it to a plain directory (oras-go / crane +
# umoci), so ClamAV can scan a container image's actual file contents
# instead of just its compressed layers. Used to be built from source
# here (pinned to a commit SHA, no tagged releases existed yet) -- now
# that v0.5.1 ships real linux_amd64/linux_arm64 release tarballs
# (goreleaser), it moves into this same download-a-release-tarball
# pattern as oras, dropping an entire build stage (and that stage's own
# network/module-proxy dependency) in the process. Bump UNPACKER_VERSION
# to update; no commit SHA to track anymore.
ARG UNPACKER_VERSION=0.5.1
RUN apk add --no-cache ca-certificates curl tar \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && ARCH="${TARGETARCH:-$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')}" \
    && curl -sSL -o /tmp/oras.tar.gz "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_${ARCH}.tar.gz" \
    && tar -zxf /tmp/oras.tar.gz -C /usr/local/bin oras \
    && rm -f /tmp/oras.tar.gz \
    && curl -sSL -o /tmp/unpacker.tar.gz "https://github.com/Sifungurux/unpacker/releases/download/v${UNPACKER_VERSION}/unpacker_${UNPACKER_VERSION}_linux_${ARCH}.tar.gz" \
    && tar -zxf /tmp/unpacker.tar.gz -C /usr/local/bin unpacker \
    && rm -f /tmp/unpacker.tar.gz \
    && apk del curl

COPY --from=build       /out/monitor-api /usr/local/bin/monitor-api
COPY --from=umoci-build /out/umoci       /usr/local/bin/umoci

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/monitor-api"]
