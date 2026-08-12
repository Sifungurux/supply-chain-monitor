# Every base image here is pinned by DIGEST as well as tag. A tag is a
# mutable pointer -- "alpine:3.21" a month from now is not the filesystem
# this was built and tested against -- and for a supply-chain scanner,
# "we don't know exactly what we shipped" is the one answer that can't
# stand. The tag is kept alongside the digest purely so a human can read
# what it is; the digest is what actually resolves.
#
# Both digests are multi-arch image INDEXES (amd64 and arm64/v8 both
# present -- confirmed against the registry, not assumed), so this still
# builds on an Apple Silicon Colima/Podman VM and on amd64 CI alike.
# To bump: `docker buildx imagetools inspect <image>:<tag>` and take the
# top-level digest it prints, not a per-platform one.

# --- monitor-api build stage ---
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
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
# CGO_ENABLED=0 makes this a static binary: it needs nothing from the
# runtime image but a kernel, which is what keeps the runtime stage free
# to be as bare as its own comment allows.
RUN CGO_ENABLED=0 go build -o /out/monitor-api .

# --- umoci build stage ---
# Built from source rather than pulling the project's release binary
# (which only ships amd64), so this also works on Apple Silicon Macs
# (arm64 Colima/Podman VMs) without emulation. If this stage fails
# because umoci's go.mod wants a newer toolchain, bump the golang tag
# here. (v0.4.7 is old and still builds clean under Go 1.26 -- verified,
# not assumed, when this was bumped off 1.22.)
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS umoci-build
# Pinned to a COMMIT, not a tag. `--branch v0.4.7` (what this used to
# do) looked exactly as pinned as this does while guaranteeing nothing:
# a tag is a mutable ref the upstream repo can move, or anyone with push
# access can re-point, and the build would follow it silently. This is
# the commit v0.4.7 resolved to when it was verified.
#
# The rev-parse check is what makes the pin real rather than merely
# stated -- if the fetch ever lands somewhere else, the build fails
# instead of shipping a different umoci under the same version comment.
ARG UMOCI_COMMIT=17f38511d61846e2fb8ec01a1532f3ef5525e71d
RUN apk add --no-cache git
WORKDIR /src/umoci
RUN set -eux; \
    git init -q; \
    git remote add origin https://github.com/opencontainers/umoci.git; \
    git fetch -q --depth 1 origin "${UMOCI_COMMIT}"; \
    git checkout -q FETCH_HEAD; \
    test "$(git rev-parse HEAD)" = "${UMOCI_COMMIT}"
RUN CGO_ENABLED=0 go build -o /out/umoci ./cmd/umoci

# --- tool download + verification stage ---
# Downloading happens in its own stage so that curl and GNU tar exist
# only here and never in the shipped image: the runtime stage below
# copies four already-verified binaries out of /out and carries no
# downloader of its own.
#
# Every tarball is checked against a checksum pinned in this file before
# it is unpacked. Pinning the version alone is not enough -- a release
# asset can be replaced under an unchanged tag, and this project's whole
# job is to notice exactly that class of thing happening to somebody
# else. The checksums come from each release's own published
# checksums.txt:
#   curl -sSL https://github.com/<org>/<repo>/releases/download/v<ver>/<..>checksums.txt
# so bumping a version means replacing the version AND its two digests
# together.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS tools
# TARGETARCH is set automatically by BuildKit (amd64/arm64) -- used below
# to pick the right release tarball and the checksum that goes with it.
ARG TARGETARCH

# trivy used to be installed by piping contrib/install.sh from the tip
# of trivy's main branch straight into sh. That fetched an unpinned
# script over the network and executed it as root at build time, so
# every build trusted whatever that file said today -- for a scanner
# whose findings this project reports as fact. It is now the same
# pinned-tarball-plus-checksum path as everything else here. Note
# trivy's asset naming differs from the goreleaser convention the other
# three use: Linux-64bit / Linux-ARM64, not linux_amd64 / linux_arm64.
ARG TRIVY_VERSION=0.72.0
ARG TRIVY_SHA256_AMD64=bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea
ARG TRIVY_SHA256_ARM64=2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467

# oras (github.com/oras-project/oras) fetches file/sbom/sarif artifacts
# from an OCI registry so their `ref` can be a real registry reference
# instead of assuming the artifact is already a path inside this pod --
# see internal/scanner/fetch.go.
ARG ORAS_VERSION=1.3.2
ARG ORAS_SHA256_AMD64=9229ccc6d17bb282039ad4a69abb16dcb887a5bce567c075d731d9b3c7ad8eaf
ARG ORAS_SHA256_ARM64=8db4a223bd6034deff198e791ea7cb3af0840df25b7e9f370e2f1f3fd20d389b

# github.com/Sifungurux/unpacker: pulls an image/OCI artifact from a
# registry and unpacks it to a plain directory (oras-go / crane + umoci),
# so ClamAV can scan a container image's actual file contents instead of
# just its compressed layers.
ARG UNPACKER_VERSION=0.5.1
ARG UNPACKER_SHA256_AMD64=446f0c31380fcd499ed85710f68fd19422068ac1c7266347c374058117299d73
ARG UNPACKER_SHA256_ARM64=f5d5aa3da862ab71df2ec750de813b70e4ef143329612bbc6dbce01193f5047c

# github.com/anchore/grype: alternative CVE scanner to trivy, selectable
# via monitorApi.cveScanner (internal/scanner/grype.go).
ARG GRYPE_VERSION=0.116.1
ARG GRYPE_SHA256_AMD64=0122df7b655981abe547ad3d2190d65551dac6a2bfc80b4dc2a989b5d0587458
ARG GRYPE_SHA256_ARM64=a8d7504a149629324eb5f4ce3dc25dfd211bbfe047e64ee2bf7844b466c3d84d

RUN apk add --no-cache curl tar
# CURL_OPTS: -f so an HTTP error is a failed build rather than an error
# page saved as a .tar.gz, and --retry so a connection that dies
# mid-transfer is retried instead of failing the whole build. That is not
# hypothetical -- this stage makes four release downloads in a row, and
# CI has now hit two different transient failures on these downloads on
# two separate days -- `curl: (56) Connection died` mid-transfer, and a
# straight `503` from GitHub's release CDN that outlasted a 3x2s retry
# budget. Hence 5 retries at 5s rather than 3 at 2s: the failure mode is
# GitHub being briefly unavailable, which lasts longer than a couple of
# seconds. --retry-all-errors is what
# makes --retry cover a mid-transfer receive failure; without it curl
# only retries a narrower set (timeouts, 5xx, 429).
#
# Retrying is safe precisely because of the sha256 check below: a
# corrupt or truncated retry cannot pass unnoticed, it fails the build.
ARG CURL_OPTS="-fsSL --retry 5 --retry-delay 5 --retry-all-errors"
# Two guards inside the script below are worth naming, since neither is
# obvious from the code:
#
#   - the empty-checksum loop. An empty expected checksum is not a
#     checksum: busybox sha256sum can be talked into accepting a blank
#     digest line, which would turn this entire stage into theatre. A
#     missing per-arch ARG fails the build instead.
#   - CURL_OPTS (see just above) -- -f and the retry flags.
#
# (Both live in the comment rather than inline: a comment line inside a
# RUN continuation is stripped by BuildKit but is not portable across
# every Dockerfile parser, and this file has to build under podman/
# buildah too.)
RUN set -eux; \
    ARCH="${TARGETARCH:-$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')}"; \
    case "$ARCH" in \
      amd64) TRIVY_ASSET="Linux-64bit"; \
             TRIVY_SHA="${TRIVY_SHA256_AMD64}"; ORAS_SHA="${ORAS_SHA256_AMD64}"; \
             UNPACKER_SHA="${UNPACKER_SHA256_AMD64}"; GRYPE_SHA="${GRYPE_SHA256_AMD64}" ;; \
      arm64) TRIVY_ASSET="Linux-ARM64"; \
             TRIVY_SHA="${TRIVY_SHA256_ARM64}"; ORAS_SHA="${ORAS_SHA256_ARM64}"; \
             UNPACKER_SHA="${UNPACKER_SHA256_ARM64}"; GRYPE_SHA="${GRYPE_SHA256_ARM64}" ;; \
      *) echo "unsupported architecture: ${ARCH} -- add its release checksums above before building for it" >&2; exit 1 ;; \
    esac; \
    for sum in "$TRIVY_SHA" "$ORAS_SHA" "$UNPACKER_SHA" "$GRYPE_SHA"; do \
      [ -n "$sum" ] || { echo "empty expected checksum for ${ARCH}" >&2; exit 1; }; \
    done; \
    mkdir -p /out; \
    curl ${CURL_OPTS} -o /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ASSET}.tar.gz"; \
    echo "${TRIVY_SHA}  /tmp/trivy.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/trivy.tar.gz -C /out trivy; \
    curl ${CURL_OPTS} -o /tmp/oras.tar.gz "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_${ARCH}.tar.gz"; \
    echo "${ORAS_SHA}  /tmp/oras.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/oras.tar.gz -C /out oras; \
    curl ${CURL_OPTS} -o /tmp/unpacker.tar.gz "https://github.com/Sifungurux/unpacker/releases/download/v${UNPACKER_VERSION}/unpacker_${UNPACKER_VERSION}_linux_${ARCH}.tar.gz"; \
    echo "${UNPACKER_SHA}  /tmp/unpacker.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/unpacker.tar.gz -C /out unpacker; \
    curl ${CURL_OPTS} -o /tmp/grype.tar.gz "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${ARCH}.tar.gz"; \
    echo "${GRYPE_SHA}  /tmp/grype.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/grype.tar.gz -C /out grype; \
    rm -f /tmp/*.tar.gz; \
    chmod 0755 /out/trivy /out/oras /out/unpacker /out/grype

# --- runtime stage ---
# Alpine, not distroless, and that is a checked decision rather than an
# omission: four of this chart's own workloads run `sh -c` from THIS
# image -- the trivy/grype DB primer Jobs and refresh CronJobs (see
# charts/supply-chain-monitor/templates/monitor-api/) -- so a base
# without a shell breaks the vulnerability-DB pipeline every scan
# depends on. The monitor-api binary is static (CGO_ENABLED=0) and would
# drop into gcr.io/distroless/static unchanged the day those four stop
# needing a shell; nothing else here is in the way.
#
# What did go: curl and GNU tar, which existed only to fetch the tools
# above and now live in the `tools` stage instead, so the shipped image
# carries no downloader. busybox still provides sh, tar and wget --
# that is alpine, and the shell is load-bearing per the paragraph above.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
# ca-certificates is the one genuine runtime dependency: trivy, grype
# and oras all make TLS calls to registries and DB mirrors.
RUN apk add --no-cache ca-certificates

COPY --from=tools       /out/trivy       /usr/local/bin/trivy
COPY --from=tools       /out/oras        /usr/local/bin/oras
COPY --from=tools       /out/unpacker    /usr/local/bin/unpacker
COPY --from=tools       /out/grype       /usr/local/bin/grype
COPY --from=build       /out/monitor-api /usr/local/bin/monitor-api
COPY --from=umoci-build /out/umoci       /usr/local/bin/umoci

# nobody:nobody, alpine's built-in 65534 -- the same uid
# k8sjob.NewScanJob hardcodes for scan-worker pods. Every workload in
# this chart already pins runAsUser: 65534 explicitly, so this changes
# nothing in-cluster; it is here so that a bare `docker run`, or any
# future manifest that forgets, doesn't quietly get root. Set after the
# COPYs so those still run as root and land root-owned 0755 -- readable
# and executable by 65534, writable by nobody.
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/monitor-api"]
