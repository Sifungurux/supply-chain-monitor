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
	// PlainHTTP matches scm-registry's own setup: a local,
	// unauthenticated, plain-HTTP registry -- the same assumption
	// UnpackerScanner's --insecure/--public flags already make for
	// image artifacts. Tighten before pointing this at a real,
	// TLS-terminated, authenticated registry (see docs/architecture.md's
	// Roadmap).
	PlainHTTP bool
}

func NewRegistryFetcher(plainHTTP bool) *RegistryFetcher {
	return &RegistryFetcher{PlainHTTP: plainHTTP}
}

// looksLikeLocalPath distinguishes "ref is already a path inside the
// pod" (the original v1 convention) from "ref is an OCI registry
// reference to fetch" (the new capability). Registry refs
// (scm-registry:5000/sboms/app:1.0, ghcr.io/org/app-sbom:latest) never
// start with /, ., or ~ the way a real filesystem path handed to this
// API would.
func looksLikeLocalPath(ref string) bool {
	return strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, ".") || strings.HasPrefix(ref, "~")
}

func (f *RegistryFetcher) Fetch(ctx context.Context, ref string) (string, func(), error) {
	noop := func() {}
	if looksLikeLocalPath(ref) {
		return ref, noop, nil
	}

	dir, err := os.MkdirTemp("", "scm-fetch-*")
	if err != nil {
		return "", noop, fmt.Errorf("create fetch temp dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	args := []string{"pull", "--output", dir}
	if f.PlainHTTP {
		args = append(args, "--plain-http")
	}
	args = append(args, ref)

	cmd := exec.CommandContext(ctx, "oras", args...)
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
