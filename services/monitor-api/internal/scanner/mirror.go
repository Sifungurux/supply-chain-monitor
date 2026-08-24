package scanner

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strings"
)

// Mirror copies an artifact into this deployment's own registry and
// returns the ref of the copy.
//
// The point is what happens AFTER registration: every scan of a mirrored
// artifact pulls from scm-registry instead of docker.io/ghcr.io. That
// removes the public registry from the scanning path entirely -- no
// anonymous pull rate limits (the single most common cause of a scan
// failing here), no dependency on an upstream tag still existing or
// still meaning the same thing, and the bytes that get scanned on every
// later re-scan are provably the bytes that were registered.
//
// An interface, like Fetcher and DigestResolver above, so the handler
// can be tested without a real `oras` binary and two real registries.
type Mirror interface {
	// Mirror copies ref into the local registry and returns the local
	// ref to use in its place. srcDigest is the already-resolved digest
	// of ref when the caller has one ("" if not) -- it is what the copy
	// is verified against, see OrasMirror.Mirror.
	//
	// Returns ("", nil) -- no error -- for a ref there is nothing to do
	// for: a local filesystem path, or a ref already pointing at the
	// local registry. Callers treat that the same as a failure (keep the
	// original ref) but must not log it as one.
	Mirror(ctx context.Context, ref, srcDigest string) (localRef string, err error)
}

// OrasMirror mirrors via `oras copy`, the same binary already baked into
// the monitor-api image for RegistryFetcher and OrasDigestResolver (see
// Dockerfile) -- and the same command cluster/seed-trivy-db.sh already
// uses for registry-to-registry copies.
type OrasMirror struct {
	// RegistryAddr is the destination registry, host:port -- the same
	// REGISTRY_ADDR every other registry-facing path here reads.
	RegistryAddr string
	// RepoPrefix namespaces every mirrored artifact under one repository
	// path ("mirror" by default), so the copies are trivially
	// distinguishable from anything an operator pushed to this registry
	// themselves, and deletable as a group.
	RepoPrefix string
	// PlainHTTP is the deployment's "the local registry has no TLS"
	// switch (FETCH_PLAIN_HTTP). Only ever applied to the DESTINATION,
	// and only after InsecureTransportAllowed agrees the destination is
	// in fact this deployment's own registry -- the source is a public
	// registry and keeps TLS regardless. See insecuretransport.go.
	PlainHTTP bool
	// RegistryConfigPath is the merged docker config (main.go's
	// writeDockerConfig) holding credentials for every configured
	// registry keyed by host. Passed as BOTH --from-registry-config and
	// --to-registry-config: one file already covers the public source
	// and the local destination, and the alternative
	// (--from-password/--to-password) would put both in argv.
	RegistryConfigPath string
	// Resolver verifies the copy landed -- see Mirror. Required: a nil
	// resolver means the copy cannot be checked, and an unverified
	// rewrite is worse than no rewrite.
	Resolver DigestResolver
}

// NewOrasMirror builds a Mirror writing into registryAddr. Returns nil
// when registryAddr is empty -- there is no local registry to mirror
// into, which is exactly how every deployment behaved before this
// existed, and a nil Mirror is what the handler treats as "off".
func NewOrasMirror(registryAddr, repoPrefix string, plainHTTP bool, registryConfigPath string, resolver DigestResolver) *OrasMirror {
	if registryAddr == "" || resolver == nil {
		return nil
	}
	if repoPrefix == "" {
		repoPrefix = DefaultMirrorRepoPrefix
	}
	return &OrasMirror{
		RegistryAddr:       registryAddr,
		RepoPrefix:         repoPrefix,
		PlainHTTP:          plainHTTP,
		RegistryConfigPath: registryConfigPath,
		Resolver:           resolver,
	}
}

// DefaultMirrorRepoPrefix is where mirrored copies land inside the local
// registry: scm-registry:5000/mirror/<original repo path>:<tag>.
const DefaultMirrorRepoPrefix = "mirror"

// repoSeparators are the characters an OCI repository path component may
// contain besides [a-z0-9] -- but only BETWEEN alphanumerics and never
// doubled (".." and "-_" are both invalid). mirrorRepoPath keeps the
// rule simple by collapsing any run of them to a single "-".
var repoSeparators = regexp.MustCompile(`[._-]{2,}`)

// disallowedInRepo is everything else: uppercase (repository paths are
// lowercase-only), the ":" in a "host:port" registry, and anything a
// registry would reject outright.
var disallowedInRepo = regexp.MustCompile(`[^a-z0-9._-]`)

// mirrorRepoPath turns a source repository path into one path under the
// local registry, preserving enough of the original to be readable:
//
//	docker.io/library/nginx     -> docker.io/library/nginx
//	ghcr.io/Org/App             -> ghcr.io/org/app
//	localhost:5000/app          -> localhost-5000/app
//
// Component by component, because "/" is the one character that must
// survive: flattening the path would collide "org/app" with "org-app".
func mirrorRepoPath(repo string) string {
	parts := strings.Split(strings.ToLower(repo), "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = disallowedInRepo.ReplaceAllString(p, "-")
		p = repoSeparators.ReplaceAllString(p, "-")
		p = strings.Trim(p, "._-")
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, "/")
}

// splitRefTag splits a ref into its repository path and the tag or
// digest identifying which thing in it -- BEFORE any sanitizing, which
// is the whole reason it is its own function. A digest run through
// mirrorRepoPath comes back looking like a perfectly valid ref that
// resolves to nothing ("sha256:ab..." -> "sha256-ab..."), and that is
// the kind of wrong that only shows up as a scan failure days later.
//
// Returns tag == "" when ref names a digest, and digest == "" when it
// names a tag. A ref with neither gets the "latest" tag, the same
// default every registry client applies.
func splitRefTag(ref string) (repo, tag, digest string) {
	if i := strings.Index(ref, "@"); i >= 0 {
		return ref[:i], "", ref[i+1:]
	}
	// Only a ":" AFTER the last "/" is a tag -- the one in
	// "localhost:5000/app" is a port.
	slash := strings.LastIndex(ref, "/")
	if i := strings.LastIndex(ref, ":"); i > slash {
		return ref[:i], ref[i+1:], ""
	}
	return ref, "latest", ""
}

// digestTag names the destination tag for a source ref that was pinned
// by digest and so has no tag of its own. Borrows cosign's own
// "sha256:ab..." -> "sha256-ab..." convention rather than inventing a
// second one.
//
// The destination gets a tag either way, deliberately: an untagged
// manifest is a garbage-collection candidate in a registry with
// REGISTRY_STORAGE_DELETE_ENABLED (this one), so a copy pushed by digest
// alone is a copy that can quietly disappear.
func digestTag(digest string) string {
	return strings.ReplaceAll(digest, ":", "-")
}

// MirrorRef computes where ref will be mirrored to, with no I/O. Split
// out from Mirror so the naming rules are testable without a registry,
// and so a caller can ask "is this already mirrored?" (see AlreadyMirrored)
// using the same rules the copy itself uses.
//
// Returns "" for anything that must not be mirrored: a local filesystem
// path, a ref already in the local registry, or a digest-pinned ref with
// no digest to name the copy after.
func (m *OrasMirror) MirrorRef(ref string) string {
	if looksLikeLocalPath(ref) || m.AlreadyMirrored(ref) {
		return ""
	}
	repo, tag, digest := splitRefTag(qualifyDockerHubRef(ref))
	path := mirrorRepoPath(repo)
	if path == "" {
		return ""
	}
	if tag == "" {
		tag = digestTag(digest)
	}
	if tag == "" {
		return ""
	}
	return fmt.Sprintf("%s/%s/%s:%s", m.RegistryAddr, m.RepoPrefix, path, tag)
}

// AlreadyMirrored reports whether ref already points into the local
// registry -- either a copy this made earlier, or something an operator
// pushed there directly. Either way there is nothing to copy.
func (m *OrasMirror) AlreadyMirrored(ref string) bool {
	return strings.HasPrefix(ref, m.RegistryAddr+"/")
}

func (m *OrasMirror) Mirror(ctx context.Context, ref, srcDigest string) (string, error) {
	dst := m.MirrorRef(ref)
	if dst == "" {
		return "", nil // nothing to mirror -- see Mirror's interface doc
	}
	// The SOURCE is caller-supplied and about to become an outbound
	// request, so it gets the same validation every other outbound path
	// here applies. The destination deliberately does not: it is this
	// deployment's own in-cluster registry, which is precisely the shape
	// (RFC1918 / *.svc.cluster.local) ValidateRef exists to refuse.
	if err := ValidateRef(ctx, ref); err != nil {
		return "", err
	}

	cmd := exec.CommandContext(ctx, "oras", m.copyArgs(qualifyDockerHubRef(ref), dst)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// stderr is logged, never returned, for the same reason
		// OrasDigestResolver.Resolve does not return it: it is raw CLI
		// output naming internal hostnames and auth hints, and this
		// error can reach an API response.
		slog.Warn("oras copy failed", "ref", ref, "dst", dst,
			"stderr", strings.TrimSpace(stderr.String()), "err", err)
		return "", fmt.Errorf("oras copy %q failed", ref)
	}

	return m.verify(ctx, ref, dst, srcDigest)
}

// verify is the check that decides whether the rewrite happens. A zero
// exit from `oras copy` is not evidence the copy is usable: resolve the
// DESTINATION and require it to be the same content. OCI refs are
// content-addressed, so a digest that differs -- or will not resolve at
// all -- means a partial push, a wrong destination name, or an
// index/child mix-up, every one of which produces a ref that looks
// perfectly fine and scans as nothing.
//
// srcDigest == "" (registration could not resolve the source either)
// weakens this to "the destination exists and is readable", which is
// still the difference between a rewrite to something and a rewrite to
// a 404.
func (m *OrasMirror) verify(ctx context.Context, ref, dst, srcDigest string) (string, error) {
	dstDigest, err := m.Resolver.Resolve(ctx, dst, m.PlainHTTP && InsecureTransportAllowed(dst))
	if err != nil {
		return "", fmt.Errorf("mirrored copy of %q could not be resolved at %q: %w", ref, dst, err)
	}
	if dstDigest == "" {
		return "", fmt.Errorf("mirrored copy of %q resolved to no digest at %q", ref, dst)
	}
	if srcDigest != "" && dstDigest != srcDigest {
		return "", fmt.Errorf("mirrored copy of %q resolved to %s, expected %s -- not rewriting", ref, dstDigest, srcDigest)
	}
	return dst, nil
}

// copyArgs builds the `oras copy` invocation. Split out from Mirror so
// the flag wiring is unit-testable without the real binary or a
// registry, the same reason RegistryFetcher.pullArgs is.
//
// Flag names verified against oras 1.3.2 (the version the Dockerfile
// pins): copy takes --from-*/--to-* variants of the flags the single-
// target commands spell plainly, so the same file/switch has to be
// passed twice under two different names.
func (m *OrasMirror) copyArgs(src, dst string) []string {
	// --recursive copies the artifact's OCI referrers (attestations,
	// SBOMs attached via the Referrers API) along with it. It does NOT
	// follow cosign's classic `sha256-<digest>.sig` sibling TAG, which
	// is not a referrer -- which is why signature verification keeps
	// running against the original ref, see internal/api/scan.go's
	// provenanceRef.
	args := []string{"copy", "--recursive"}
	if m.PlainHTTP && InsecureTransportAllowed(dst) {
		args = append(args, "--to-plain-http")
	}
	if m.RegistryConfigPath != "" {
		args = append(args,
			"--from-registry-config", m.RegistryConfigPath,
			"--to-registry-config", m.RegistryConfigPath)
	}
	// "--" ends flag parsing, so a ref that somehow reached here without
	// passing ValidateRef is a positional argument rather than a flag --
	// the same belt-and-braces every other exec path in this package
	// uses.
	return append(args, "--", src, dst)
}
