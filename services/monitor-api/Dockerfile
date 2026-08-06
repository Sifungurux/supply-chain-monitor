# --- monitor-api build stage ---
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY . .
# go.sum is committed (see go.mod's comment) -- `go mod download`
# verifies the module graph against it and populates the local module
# cache, rather than `go mod tidy`, which can silently rewrite go.sum
# (re-resolving versions) instead of just checking it. `go mod verify`
# then double-checks every downloaded module's content against go.sum's
# checksums before anything is compiled against it -- exactly the
# reproducible-build guarantee committing go.sum exists for. Network
# access is only actually needed the first time an image is built on a
# machine with an empty module cache, or after go.mod/go.sum change.
RUN go mod download && go mod verify
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
# trivy's own install.sh (contrib/install.sh, godownloader-generated)
# takes a version tag as its trailing positional arg -- omitting it
# (as this used to) makes it resolve whatever GitHub currently reports
# as "latest" via `github_release`, at build time. That's an unpinned
# dependency in a project that pins everything else it downloads
# (ORAS_VERSION/UNPACKER_VERSION/UMOCI_VERSION below), and means two
# `docker build`s a week apart can silently end up running different
# trivy versions -- undesirable for a supply-chain-security tool whose
# whole job depends on a specific scanner's specific behavior. Bump
# TRIVY_VERSION deliberately (or pass --build-arg TRIVY_VERSION=...) to
# update; nothing updates it on its own anymore.
ARG TRIVY_VERSION=0.72.0
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
# github.com/anchore/grype: alternative CVE scanner to trivy, selectable
# via monitorApi.cveScanner (internal/scanner/grype.go). Ships
# goreleaser tarballs named exactly like oras/unpacker's above
# (grype_<version>_linux_<arch>.tar.gz -- confirmed against a real
# release asset listing, not assumed), so it joins the same
# download-a-release-tarball pattern rather than trivy's installer
# script. Bump GRYPE_VERSION to update.
ARG GRYPE_VERSION=0.116.1
RUN apk add --no-cache ca-certificates curl tar \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}" \
    && ARCH="${TARGETARCH:-$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')}" \
    && curl -sSL -o /tmp/oras.tar.gz "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_${ARCH}.tar.gz" \
    && tar -zxf /tmp/oras.tar.gz -C /usr/local/bin oras \
    && rm -f /tmp/oras.tar.gz \
    && curl -sSL -o /tmp/unpacker.tar.gz "https://github.com/Sifungurux/unpacker/releases/download/v${UNPACKER_VERSION}/unpacker_${UNPACKER_VERSION}_linux_${ARCH}.tar.gz" \
    && tar -zxf /tmp/unpacker.tar.gz -C /usr/local/bin unpacker \
    && rm -f /tmp/unpacker.tar.gz \
    && curl -sSL -o /tmp/grype.tar.gz "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${ARCH}.tar.gz" \
    && tar -zxf /tmp/grype.tar.gz -C /usr/local/bin grype \
    && rm -f /tmp/grype.tar.gz \
    && apk del curl

COPY --from=build       /out/monitor-api /usr/local/bin/monitor-api
COPY --from=umoci-build /out/umoci       /usr/local/bin/umoci

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/monitor-api"]
