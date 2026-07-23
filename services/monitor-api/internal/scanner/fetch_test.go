package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

func TestLooksLikeLocalPath(t *testing.T) {
	cases := map[string]bool{
		"/tmp/suspicious.bin":             true,
		"/tmp/results.sarif":              true,
		"./relative.json":                 true,
		"~/in-home-dir.txt":               true,
		"scm-registry:5000/sboms/app:1.0": false,
		"ghcr.io/org/app-sbom:latest":     false,
		"alpine:3.19":                     false,
		"myfile.txt":                      false, // ambiguous relative name -- treated as a registry ref, not a path
	}
	for ref, want := range cases {
		if got := looksLikeLocalPath(ref); got != want {
			t.Errorf("looksLikeLocalPath(%q) = %v, want %v", ref, got, want)
		}
	}
}

func TestSingleFileIn(t *testing.T) {
	t.Run("exactly one file", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "app.cdx.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := singleFileIn(dir)
		if err != nil {
			t.Fatalf("singleFileIn: %v", err)
		}
		if got != filepath.Join(dir, "app.cdx.json") {
			t.Fatalf("got %q, want the one file in dir", got)
		}
	})

	t.Run("no files is an error", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := singleFileIn(dir); err == nil {
			t.Fatal("expected an error for an empty directory")
		}
	})

	t.Run("multiple files is an error, not a guess", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{"a.json", "b.json"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := singleFileIn(dir); err == nil {
			t.Fatal("expected an error when oras pull produces more than one file")
		}
	})

	t.Run("subdirectories are ignored, not mistaken for files", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "app.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := singleFileIn(dir)
		if err != nil {
			t.Fatalf("singleFileIn: %v", err)
		}
		if got != filepath.Join(dir, "app.json") {
			t.Fatalf("got %q, want app.json (subdir should be skipped)", got)
		}
	})
}

// TestRegistryFetcher_Fetch_LocalPathPassthrough exercises the one
// branch of RegistryFetcher.Fetch that doesn't need the real `oras`
// binary or a registry -- unlike Scan() in every other file in this
// package, this can run in any Go environment.
func TestRegistryFetcher_Fetch_LocalPathPassthrough(t *testing.T) {
	f := NewRegistryFetcher(true)
	path, cleanup, err := f.Fetch(context.Background(), "/tmp/suspicious.bin")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if path != "/tmp/suspicious.bin" {
		t.Fatalf("path = %q, want the ref returned unchanged", path)
	}
	cleanup() // must be safe to call even though nothing was downloaded
}

type fakeFetcher struct {
	path          string
	err           error
	gotRef        string
	calledCleanup bool
}

func (f *fakeFetcher) Fetch(_ context.Context, ref string) (string, func(), error) {
	f.gotRef = ref
	return f.path, func() { f.calledCleanup = true }, f.err
}

type spyScanner struct {
	gotRef   string
	findings []artifact.Finding
	err      error
	// bucket, if set, makes spyScanner implement BucketAffinity (see
	// TestFetchingScanner_Bucket) -- unset by every other test using
	// this double, which correctly reports "" (unknown) then.
	bucket string
}

func (s *spyScanner) Scan(_ context.Context, ref string) ([]artifact.Finding, error) {
	s.gotRef = ref
	return s.findings, s.err
}

func (s *spyScanner) Bucket() string { return s.bucket }

// plainScanner implements Scanner and nothing else -- used to prove
// FetchingScanner.Bucket() degrades gracefully (returns "", not a
// panic or a wrong guess) when the inner scanner doesn't implement
// BucketAffinity at all, which is exactly SARIFScanner's real situation
// today.
type plainScanner struct{}

func (plainScanner) Scan(context.Context, string) ([]artifact.Finding, error) { return nil, nil }

func TestFetchingScanner_Bucket(t *testing.T) {
	t.Run("forwards the inner scanner's declared bucket", func(t *testing.T) {
		fs := NewFetchingScanner(&fakeFetcher{}, &spyScanner{bucket: "cve"})
		if got := fs.Bucket(); got != "cve" {
			t.Errorf("Bucket() = %q, want %q", got, "cve")
		}
	})

	t.Run("returns empty (unknown) when the inner scanner has no declared bucket", func(t *testing.T) {
		fs := NewFetchingScanner(&fakeFetcher{}, plainScanner{})
		if got := fs.Bucket(); got != "" {
			t.Errorf("Bucket() = %q, want \"\" (unknown)", got)
		}
	})
}

func TestFetchingScanner_Scan(t *testing.T) {
	t.Run("passes the fetched local path to the inner scanner, not the original ref", func(t *testing.T) {
		fetcher := &fakeFetcher{path: "/tmp/scm-fetch-123/app.cdx.json"}
		inner := &spyScanner{findings: []artifact.Finding{{ID: "CVE-1", Source: "trivy"}}}
		fs := NewFetchingScanner(fetcher, inner)

		findings, err := fs.Scan(context.Background(), "scm-registry:5000/sboms/app:1.0")
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if fetcher.gotRef != "scm-registry:5000/sboms/app:1.0" {
			t.Fatalf("fetcher saw ref %q, want the original artifact ref", fetcher.gotRef)
		}
		if inner.gotRef != "/tmp/scm-fetch-123/app.cdx.json" {
			t.Fatalf("inner scanner saw ref %q, want the fetched local path", inner.gotRef)
		}
		if len(findings) != 1 || findings[0].ID != "CVE-1" {
			t.Fatalf("findings = %+v, want the inner scanner's findings passed through", findings)
		}
		if !fetcher.calledCleanup {
			t.Fatal("expected cleanup to be called after a successful scan")
		}
	})

	t.Run("fetch failure is surfaced and the inner scanner is never called", func(t *testing.T) {
		fetcher := &fakeFetcher{err: errors.New("oras pull failed: connection refused")}
		inner := &spyScanner{}
		fs := NewFetchingScanner(fetcher, inner)

		_, err := fs.Scan(context.Background(), "scm-registry:5000/sboms/app:1.0")
		if err == nil {
			t.Fatal("expected an error when fetching fails")
		}
		if inner.gotRef != "" {
			t.Fatal("inner scanner should never be called when the fetch itself fails")
		}
		if !fetcher.calledCleanup {
			t.Fatal("cleanup must still be called even when fetch returns an error")
		}
	})

	t.Run("cleanup runs even when the inner scanner itself errors", func(t *testing.T) {
		fetcher := &fakeFetcher{path: "/tmp/scm-fetch-123/app.cdx.json"}
		inner := &spyScanner{err: errors.New("trivy sbom scan failed")}
		fs := NewFetchingScanner(fetcher, inner)

		_, err := fs.Scan(context.Background(), "scm-registry:5000/sboms/app:1.0")
		if err == nil {
			t.Fatal("expected the inner scanner's error to propagate")
		}
		if !fetcher.calledCleanup {
			t.Fatal("cleanup must run even when the inner scan fails")
		}
	})
}
