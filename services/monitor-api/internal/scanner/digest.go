package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// DigestResolver resolves an OCI ref to its content digest via a
// registry manifest call, without pulling any blob content -- cheap
// enough to run synchronously during artifact registration (see
// internal/api/artifacts.go's duplicate-registration check).
//
// An interface (rather than calling OrasDigestResolver directly) so
// handler tests can inject a fake instead of shelling out to a real
// `oras` binary against a real registry, the same reason Fetcher above
// is an interface.
type DigestResolver interface {
	// Resolve returns the resolved digest (e.g. "sha256:...") for ref,
	// or "" (not an error) for anything Resolve doesn't consider a
	// registry reference at all (see looksLikeLocalPath) -- callers
	// should treat an empty result as "no digest available," not a
	// failure. A non-nil error means resolution was attempted against a
	// real registry and failed (unreachable, rate-limited, ref doesn't
	// exist) -- callers should treat this as best-effort too (see
	// Artifact.Digest's comment): log it, don't block registration on
	// it.
	Resolve(ctx context.Context, ref string, plainHTTP bool) (string, error)
}

// OrasDigestResolver resolves via `oras manifest fetch --descriptor`
// (oras is already baked into the monitor-api image, see Dockerfile --
// the same binary RegistryFetcher above already shells out to) -- the
// lightest oras command that returns a digest without pulling any blob
// content, unlike `oras pull` (RegistryFetcher.Fetch) which downloads
// the whole artifact. `oras resolve` also exists and is arguably a
// better name match, but is marked "[Preview]" in oras's own docs as of
// v1.3 -- `manifest fetch --descriptor` is the stable command.
type OrasDigestResolver struct{}

func NewOrasDigestResolver() *OrasDigestResolver {
	return &OrasDigestResolver{}
}

// orasDescriptor is the subset of `oras manifest fetch --descriptor`'s
// JSON output this cares about -- mediaType/size are part of the same
// descriptor but unused today.
type orasDescriptor struct {
	Digest string `json:"digest"`
}

// qualifyDockerHubRef prefixes ref with "docker.io/" (and "library/" for
// a single-segment official-image name) when it has no explicit registry
// host component -- the same reference-normalization Docker itself (and,
// transitively, trivy's go-containerregistry-based image scanning, which
// is why *scanning* e.g. "nginx:alpine" has always worked even though
// *resolving its digest* here never did) applies before ever reaching a
// registry. oras has no such default: `oras manifest fetch nginx:alpine`
// parses "nginx" itself as the registry host and fails a DNS lookup for
// it, deterministically, for every single unqualified Docker Hub ref --
// confirmed live: `oras manifest fetch bitnami/redis:7.2.5` tried to
// resolve a registry literally named "bitnami" and failed
// ("lookup bitnami ...: no such host") before this existed.
//
// The rule (matching Docker's own reference-parsing convention): a ref
// with no "/" at all is a single-segment official-image name
// ("nginx:alpine" -> "docker.io/library/nginx:alpine"). A ref with a "/"
// is already qualified if its first segment looks like a host (contains
// "." or ":", or is exactly "localhost") -- e.g. "ghcr.io/org/app:tag",
// "localhost:5000/app:tag" -- and is left untouched. Otherwise the first
// segment is a Docker Hub user/org name ("bitnami/redis:7.2.5" ->
// "docker.io/bitnami/redis:7.2.5") -- no "library/" needed, it already
// names an owner.
func qualifyDockerHubRef(ref string) string {
	first, rest, hasSlash := strings.Cut(ref, "/")
	if !hasSlash {
		return "docker.io/library/" + ref
	}
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return ref // already has an explicit registry host
	}
	return "docker.io/" + first + "/" + rest
}

func (r *OrasDigestResolver) Resolve(ctx context.Context, ref string, plainHTTP bool) (string, error) {
	if looksLikeLocalPath(ref) {
		return "", nil
	}
	// Defense in depth: internal/api/artifacts.go already validates the
	// ref before it ever gets here, but this is the function that turns
	// a ref into an outbound request, so it validates its own input
	// rather than trusting every present and future caller to have done
	// it (scan.go's digest backfill is already a second caller).
	if err := ValidateRef(ctx, ref); err != nil {
		return "", err
	}

	args := []string{"manifest", "fetch", "--descriptor"}
	if plainHTTP {
		args = append(args, "--plain-http")
	}
	args = append(args, qualifyDockerHubRef(ref))

	cmd := exec.CommandContext(ctx, "oras", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// oras's stderr is logged, never returned: it is raw CLI output
		// (resolved registry URLs, auth/token hints, whatever internal
		// hostname the ref pointed at) and the errors this returns can
		// reach an API response -- LastScanErrors classifies scan errors
		// into safe messages today, but that is one function away from
		// this one, and "the raw text simply never leaves the process"
		// is the version that stays true. An operator loses nothing:
		// the full stderr is in this pod's logs.
		slog.Warn("oras manifest fetch --descriptor failed",
			"ref", ref, "stderr", strings.TrimSpace(stderr.String()), "err", err)
		return "", fmt.Errorf("oras manifest fetch --descriptor %q failed: %w", ref, err)
	}

	var desc orasDescriptor
	if err := json.Unmarshal(stdout.Bytes(), &desc); err != nil {
		return "", fmt.Errorf("parse oras descriptor for %q: %w", ref, err)
	}
	if desc.Digest == "" {
		return "", fmt.Errorf("oras returned no digest for %q", ref)
	}
	return desc.Digest, nil
}
