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

# --- unpacker build stage ---
# github.com/Sifungurux/unpacker: pulls an image/OCI artifact from a
# registry and unpacks it to a plain directory (oras-go / crane +
# umoci), so ClamAV can scan a container image's actual file contents
# instead of just its compressed layers. Pinned to a specific commit
# since the project has no tagged releases yet -- bump UNPACKER_COMMIT
# to update.
FROM golang:1.25-alpine AS unpacker-build
ARG UNPACKER_COMMIT=df8cdd2c6f070de034612e7d244cffd460ca1454
RUN apk add --no-cache git
WORKDIR /src/unpacker
RUN git init . \
    && git remote add origin https://github.com/Sifungurux/unpacker.git \
    && git fetch --depth 1 origin "${UNPACKER_COMMIT}" \
    && git checkout FETCH_HEAD
RUN CGO_ENABLED=0 go build -o /out/unpacker ./cmd/unpacker

# --- runtime stage ---
FROM alpine:3.21
# TARGETARCH is set automatically by BuildKit (amd64/arm64) -- used
# below to pick the right oras release tarball, the same arm64
# portability concern that made umoci/unpacker get built from source
# above rather than downloaded as prebuilt binaries.
ARG TARGETARCH
# oras (github.com/oras-project/oras) fetches file/sbom/sarif artifacts
# from an OCI registry so their `ref` can be a real registry reference
# instead of assuming the artifact is already a path inside this pod --
# see internal/scanner/fetch.go. Official release tarballs cover both
# amd64 and arm64 directly, so no build-from-source needed here (unlike
# umoci/unpacker above).
ARG ORAS_VERSION=1.3.2
RUN apk add --no-cache ca-certificates curl tar \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && ORAS_ARCH="${TARGETARCH:-$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')}" \
    && curl -sSL -o /tmp/oras.tar.gz "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_${ORAS_ARCH}.tar.gz" \
    && tar -zxf /tmp/oras.tar.gz -C /usr/local/bin oras \
    && rm -f /tmp/oras.tar.gz \
    && apk del curl

COPY --from=build          /out/monitor-api /usr/local/bin/monitor-api
COPY --from=umoci-build    /out/umoci       /usr/local/bin/umoci
COPY --from=unpacker-build /out/unpacker    /usr/local/bin/unpacker

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/monitor-api"]
