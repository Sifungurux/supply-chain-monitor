package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

// DigestResolver resolves an OCI ref to its content digest via a
// registry manifest call, without pulling any blob content -- cheap
// enough to run synchronously during artifact registration (see
// internal/api/handlers.go's duplicate-registration check).
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

func (r *OrasDigestResolver) Resolve(ctx context.Context, ref string, plainHTTP bool) (string, error) {
	if looksLikeLocalPath(ref) {
		return "", nil
	}

	args := []string{"manifest", "fetch", "--descriptor"}
	if plainHTTP {
		args = append(args, "--plain-http")
	}
	args = append(args, ref)

	cmd := exec.CommandContext(ctx, "oras", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("oras manifest fetch --descriptor %q failed: %w (%s)", ref, err, stderr.String())
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
