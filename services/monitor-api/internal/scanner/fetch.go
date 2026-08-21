package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// Fetcher resolves an artifact ref into a local filesystem path ready
// to scan, downloading it first if it isn't one already.
type Fetcher interface {
	// Fetch returns the local path to scan and a cleanup func that
	// removes any temporary files it created (a no-op if nothing was
	// downloaded). Callers must always call cleanup -- including when
	// err != nil, in case Fetch partially succeeded before failing.
	Fetch(ctx context.Context, ref string) (path string, cleanup func(), err error)
}

// RegistryFetcher fetches `file`/`sbom`/`sarif` artifacts pushed to an
// OCI registry (scm-registry by default) via the `oras` CLI (baked
// into the monitor-api image, see Dockerfile) -- the same tool
// cluster/seed-trivy-db.sh already uses for OCI-to-OCI copies.
//
// If ref looks like a filesystem path already (see looksLikeLocalPath)
// rather than a registry reference, Fetch is a no-op passthrough --
// this preserves the original v1 convention (ref is already a path
// inside the pod, e.g. a shared volume) for anyone still relying on
// it, rather than silently changing what ref means.
type RegistryFetcher struct {
	// PlainHTTP matches scm-registry's own setup: a local, plain-HTTP
	// registry -- the same assumption UnpackerScanner's --insecure/
	// --public flags already make for image artifacts. Tighten before
	// pointing this at a real, TLS-terminated registry.
	PlainHTTP bool
	// Username/Password authenticate `oras pull` against scm-registry's
	// token-auth (see docs/architecture.md's registry-auth section) --
	// empty means no credentials, the original behavior from before
	// registry auth existed.
	Username, Password string
	// RegistryConfigPath, when set, is the merged docker config file
	// (main.go's writeDockerConfig) passed to oras via
	// --registry-config, and supersedes Username/Password: it carries
	// the same credentials keyed by host, which is what makes more than
	// one registry possible at all.
	RegistryConfigPath string
}

func NewRegistryFetcher(plainHTTP bool, username, password string) *RegistryFetcher {
	return &RegistryFetcher{PlainHTTP: plainHTTP, Username: username, Password: password}
}

// NewRegistryFetcherWithConfig builds a fetcher that authenticates from
// a merged docker config rather than one credential pair.
func NewRegistryFetcherWithConfig(plainHTTP bool, registryConfigPath string) *RegistryFetcher {
	return &RegistryFetcher{PlainHTTP: plainHTTP, RegistryConfigPath: registryConfigPath}
}

// looksLikeLocalPath distinguishes "ref is meant as a path inside the
// pod" (the original v1 convention) from "ref is an OCI registry
// reference to fetch". Registry refs (scm-registry:5000/sboms/app:1.0,
// ghcr.io/org/app-sbom:latest) never start with /, ., or ~ the way a
// real filesystem path handed to this API would.
//
// This only classifies intent. Whether such a path may be opened at all
// is localpath.go's question, and the answer is no unless an operator
// has explicitly said otherwise -- it used to be an unconditional yes,
// which made any readable file on the pod a valid artifact.
func looksLikeLocalPath(ref string) bool {
	return strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, ".") || strings.HasPrefix(ref, "~")
}

// fetchScratchDir is the one directory Fetch downloads into, so that
// "this path came out of a fetch" is a property a scanner can check
// (see ensureScannablePath) instead of a claim it has to take on faith.
// A fixed subdirectory of TMPDIR rather than TMPDIR itself, which is
// world-writable in a container and shared with the unpacker's own
// extraction dirs.
func fetchScratchDir() string {
	return filepath.Join(os.TempDir(), "scm-fetch")
}

func (f *RegistryFetcher) Fetch(ctx context.Context, ref string) (string, func(), error) {
	noop := func() {}
	if looksLikeLocalPath(ref) {
		// No longer a passthrough: the path is checked against the
		// operator-declared root (off by default) and the RESOLVED path
		// is what gets returned, so the file that was validated is the
		// file the scanner opens. See localpath.go.
		path, err := resolveLocalArtifactPath(ref)
		if err != nil {
			return "", noop, err
		}
		return path, noop, nil
	}
	// Defense in depth, same reasoning as OrasDigestResolver.Resolve's
	// own call: this runs in the scan-worker Job too (see main.go's
	// "sbom" branches), a process the API's registration-time check
	// never touched -- REF_HOST_ALLOWLIST is forwarded into that Job's
	// env for exactly this call.
	if err := ValidateRef(ctx, ref); err != nil {
		return "", noop, err
	}

	if err := os.MkdirAll(fetchScratchDir(), 0o700); err != nil {
		return "", noop, fmt.Errorf("create fetch scratch dir: %w", err)
	}
	dir, err := os.MkdirTemp(fetchScratchDir(), "artifact-*")
	if err != nil {
		return "", noop, fmt.Errorf("create fetch temp dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	cmd := exec.CommandContext(ctx, "oras", f.pullArgs(ref, dir)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		cleanup()
		return "", noop, fmt.Errorf("oras pull %q failed: %w (%s)", ref, err, stderr.String())
	}

	path, err := singleFileIn(dir)
	if err != nil {
		cleanup()
		return "", noop, err
	}
	return path, cleanup, nil
}

// singleFileIn returns the one regular file oras pull wrote into dir.
// file/sbom/sarif artifacts are expected to be single-blob OCI
// artifacts (one arbitrary file, one SBOM document, one SARIF file) --
// if oras pull produced anything other than exactly one file, that's
// surfaced as an error rather than guessing which one to scan.
func singleFileIn(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read fetched artifact dir: %w", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	switch len(files) {
	case 0:
		return "", fmt.Errorf("oras pull produced no files -- expected exactly one blob for a file/sbom/sarif artifact")
	case 1:
		return files[0], nil
	default:
		return "", fmt.Errorf("oras pull produced %d files, expected exactly 1 for a file/sbom/sarif artifact: %v", len(files), files)
	}
}

// FetchingScanner wraps another Scanner, resolving ref to a local path
// via a Fetcher first and cleaning up any temporary files afterward,
// regardless of the inner scan's outcome. Used to add registry-fetch
// support to ClamAVScanner/SBOMScanner/SARIFScanner (see main.go)
// without changing any of their own Scan implementations -- they still
// just receive a local path, exactly as before.
type FetchingScanner struct {
	fetcher Fetcher
	inner   Scanner
}

func NewFetchingScanner(fetcher Fetcher, inner Scanner) *FetchingScanner {
	return &FetchingScanner{fetcher: fetcher, inner: inner}
}

func (f *FetchingScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	path, cleanup, err := f.fetcher.Fetch(ctx, ref)
	defer cleanup()
	if err != nil {
		return nil, fmt.Errorf("fetch artifact %q: %w", ref, err)
	}
	return f.inner.Scan(ctx, path)
}

// Bucket forwards to the wrapped scanner's own BucketAffinity, so
// wrapping a scanner here (for file/sbom/sarif registry-fetch support)
// doesn't lose the per-bucket fix-detection precision the inner
// scanner already declared. Returns "" (meaning "unknown, could be any
// bucket" -- see BucketAffinity's own doc comment) when inner doesn't
// implement BucketAffinity at all, which is exactly what
// FetchingScanner wraps SARIFScanner as today: no false claim either
// way, just an honest "don't know."
// Kind forwards the wrapped scanner's own ScanKind, for exactly the
// reason Bucket below forwards BucketAffinity: this wrapper is what
// file/sbom/sarif scanners are registered as, so without forwarding,
// every one of them would report no kind and be counted only against
// the global cap -- silently escaping whatever per-kind cap an operator
// configured for the tool inside.
func (f *FetchingScanner) Kind() string {
	if k, ok := f.inner.(ScanKind); ok {
		return k.Kind()
	}
	return ""
}

func (f *FetchingScanner) Bucket() string {
	if ba, ok := f.inner.(BucketAffinity); ok {
		return ba.Bucket()
	}
	return ""
}

// Buckets forwards the wrapped scanner's MultiBucketAffinity, for the
// same reason Bucket forwards the single-bucket one: without it, a
// wrapped multi-bucket scanner would fall back to Bucket() (or to no
// affinity at all) and silently under-declare what it produces --
// which for a failing scanner means a bucket it feeds is left
// unblocked and its findings get marked "fixed".
//
// Nothing wraps TrivyScanner today (the image path registers it
// directly), so this is forwarding for the general case rather than a
// live one -- but the registration at main.go's pluggable-scanner path
// wraps whatever it is handed, and a wrapper that quietly drops a
// safety declaration is exactly the kind of thing nobody re-checks.
func (f *FetchingScanner) Buckets() []string {
	if mba, ok := f.inner.(MultiBucketAffinity); ok {
		return mba.Buckets()
	}
	return nil
}

// pullArgs builds the `oras pull` invocation. Split out from Fetch so
// the flag wiring is unit-testable without the real oras binary or a
// registry -- the same reason TrivyScanner.args is split out.
func (f *RegistryFetcher) pullArgs(ref, dir string) []string {
	args := []string{"pull", "--output", dir}
	// Scoped per-ref -- see InsecureTransportAllowed. FETCH_PLAIN_HTTP
	// is about scm-registry serving plain HTTP in-cluster, not about
	// speaking plain HTTP to whatever host a ref happens to name.
	if f.PlainHTTP && InsecureTransportAllowed(ref) {
		args = append(args, "--plain-http")
	}
	// One docker-shaped file covers every configured registry, each
	// credential scoped to its own host -- and keeps the password out
	// of argv, which is visible in the pod's process list. See
	// OrasDigestResolver.args for the same switch and why the pair
	// stays behind it.
	switch {
	case f.RegistryConfigPath != "":
		args = append(args, "--registry-config", f.RegistryConfigPath)
	case f.Username != "":
		args = append(args, "--username", f.Username, "--password", f.Password)
	}
	// "--" ends flag parsing, so even a ref that somehow reached here
	// without passing ValidateRef is treated as a positional argument
	// rather than a flag. Belt and braces: the actual fix is the
	// leading-"-" rejection in refvalidate.go. Verified this tool
	// accepts the separator before adding it.
	return append(args, "--", ref)
}
