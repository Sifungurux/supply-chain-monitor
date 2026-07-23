package main

import (
	"context"
	"strings"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// buildPostgresDSN is the one piece of the Postgres wiring that's pure
// string logic and cheap to test without a real database -- everything
// else (NewPostgresStore, connectStoreWithRetry) needs an actual
// Postgres to say anything meaningful about, which is what
// internal/artifact/postgres_store_integration_test.go and `make
// test-postgres` are for.
func TestBuildPostgresDSN(t *testing.T) {
	t.Run("POSTGRES_DSN wins outright", func(t *testing.T) {
		t.Setenv("POSTGRES_DSN", "postgres://custom/whatever")
		t.Setenv("POSTGRES_HOST", "should-be-ignored")
		if got := buildPostgresDSN(); got != "postgres://custom/whatever" {
			t.Fatalf("dsn = %q, want the POSTGRES_DSN override verbatim", got)
		}
	})

	t.Run("assembled from individual env vars with defaults", func(t *testing.T) {
		t.Setenv("POSTGRES_DSN", "")
		t.Setenv("POSTGRES_HOST", "scm-postgres.supply-chain-monitor.svc.cluster.local")
		t.Setenv("POSTGRES_PORT", "5432")
		t.Setenv("POSTGRES_USER", "monitor_api")
		t.Setenv("POSTGRES_PASSWORD", "s3cret")
		t.Setenv("POSTGRES_DB", "monitor_api")
		t.Setenv("POSTGRES_SSLMODE", "disable")

		got := buildPostgresDSN()
		want := "postgres://monitor_api:s3cret@scm-postgres.supply-chain-monitor.svc.cluster.local:5432/monitor_api?sslmode=disable"
		if got != want {
			t.Fatalf("dsn = %q, want %q", got, want)
		}
	})

	t.Run("password with special characters is escaped, not corrupted", func(t *testing.T) {
		t.Setenv("POSTGRES_DSN", "")
		t.Setenv("POSTGRES_HOST", "localhost")
		t.Setenv("POSTGRES_PORT", "5432")
		t.Setenv("POSTGRES_USER", "monitor_api")
		t.Setenv("POSTGRES_PASSWORD", "p@ss/word?with&chars")
		t.Setenv("POSTGRES_DB", "monitor_api")
		t.Setenv("POSTGRES_SSLMODE", "disable")

		got := buildPostgresDSN()
		// net/url.URL.String() percent-encodes the userinfo component,
		// so the raw special characters must NOT appear unescaped in
		// the result (that would produce a DSN pgx parses incorrectly).
		if strings.Contains(got, "p@ss/word?with&chars") {
			t.Fatalf("password was not escaped in dsn: %q", got)
		}
	})

	t.Run("pool settings are omitted by default (pgxpool's own default applies)", func(t *testing.T) {
		t.Setenv("POSTGRES_DSN", "")
		t.Setenv("POSTGRES_HOST", "scm-postgres.supply-chain-monitor.svc.cluster.local")
		t.Setenv("POSTGRES_PORT", "5432")
		t.Setenv("POSTGRES_USER", "monitor_api")
		t.Setenv("POSTGRES_PASSWORD", "s3cret")
		t.Setenv("POSTGRES_DB", "monitor_api")
		t.Setenv("POSTGRES_SSLMODE", "disable")
		t.Setenv("POSTGRES_POOL_MAX_CONNS", "")
		t.Setenv("POSTGRES_POOL_MIN_CONNS", "")

		got := buildPostgresDSN()
		want := "postgres://monitor_api:s3cret@scm-postgres.supply-chain-monitor.svc.cluster.local:5432/monitor_api?sslmode=disable"
		if got != want {
			t.Fatalf("dsn = %q, want %q (pool settings unset should leave the dsn unchanged from before pooling was configurable)", got, want)
		}
	})

	t.Run("pool settings are appended as query params when configured", func(t *testing.T) {
		t.Setenv("POSTGRES_DSN", "")
		t.Setenv("POSTGRES_HOST", "localhost")
		t.Setenv("POSTGRES_PORT", "5432")
		t.Setenv("POSTGRES_USER", "monitor_api")
		t.Setenv("POSTGRES_PASSWORD", "s3cret")
		t.Setenv("POSTGRES_DB", "monitor_api")
		t.Setenv("POSTGRES_SSLMODE", "disable")
		t.Setenv("POSTGRES_POOL_MAX_CONNS", "10")
		t.Setenv("POSTGRES_POOL_MIN_CONNS", "2")

		got := buildPostgresDSN()
		if !strings.Contains(got, "pool_max_conns=10") {
			t.Errorf("dsn = %q, want it to contain pool_max_conns=10", got)
		}
		if !strings.Contains(got, "pool_min_conns=2") {
			t.Errorf("dsn = %q, want it to contain pool_min_conns=2", got)
		}
	})

	t.Run("only max is set: min is omitted, not defaulted to something", func(t *testing.T) {
		t.Setenv("POSTGRES_DSN", "")
		t.Setenv("POSTGRES_HOST", "localhost")
		t.Setenv("POSTGRES_PORT", "5432")
		t.Setenv("POSTGRES_USER", "monitor_api")
		t.Setenv("POSTGRES_PASSWORD", "s3cret")
		t.Setenv("POSTGRES_DB", "monitor_api")
		t.Setenv("POSTGRES_SSLMODE", "disable")
		t.Setenv("POSTGRES_POOL_MAX_CONNS", "10")
		t.Setenv("POSTGRES_POOL_MIN_CONNS", "")

		got := buildPostgresDSN()
		if !strings.Contains(got, "pool_max_conns=10") {
			t.Errorf("dsn = %q, want it to contain pool_max_conns=10", got)
		}
		if strings.Contains(got, "pool_min_conns") {
			t.Errorf("dsn = %q, want no pool_min_conns param when POSTGRES_POOL_MIN_CONNS is unset", got)
		}
	})
}

// namedScanner is a trivial Scanner double used only so this test can
// tell, by identity, which of the two scanners buildImageScanners
// chose -- it never actually needs to run.
type namedScanner struct {
	name string
}

func (n *namedScanner) Scan(context.Context, string) ([]artifact.Finding, error) {
	return nil, nil
}

// TestBuildImageScanners pins down the one behavioral difference
// DISABLE_SCAN_ISOLATION is supposed to make: which CVE scanner and
// which malware scanner back the `image` artifact type, chosen
// consistently together. This is the only part of the
// isolation-fallback logic (see runAPIServer's comment, "Running
// monitor-api outside a Kubernetes pod") that's testable without a
// real Kubernetes API client or a real trivy binary -- deliberately
// split out of runAPIServer for exactly that reason.
func TestBuildImageScanners(t *testing.T) {
	trivyInProcess := &namedScanner{"trivy-in-process"}
	trivyIsolated := &namedScanner{"trivy-isolated"}
	inProcess := &namedScanner{"in-process-unpacker"}
	isolated := &namedScanner{"isolated-unpacker"}

	t.Run("isolation enabled (default): uses both isolated scanners", func(t *testing.T) {
		got := buildImageScanners(false, trivyInProcess, trivyIsolated, inProcess, isolated)
		if len(got) != 2 || got[0] != scanner.Scanner(trivyIsolated) || got[1] != scanner.Scanner(isolated) {
			t.Fatalf("scanners = %+v, want [trivy-isolated, isolated-unpacker]", got)
		}
	})

	t.Run("DISABLE_SCAN_ISOLATION=true: uses both in-process scanners instead", func(t *testing.T) {
		got := buildImageScanners(true, trivyInProcess, trivyIsolated, inProcess, isolated)
		if len(got) != 2 || got[0] != scanner.Scanner(trivyInProcess) || got[1] != scanner.Scanner(inProcess) {
			t.Fatalf("scanners = %+v, want [trivy-in-process, in-process-unpacker]", got)
		}
		// Neither isolated scanner (nil in runAPIServer's real
		// DISABLE_SCAN_ISOLATION=true path, since k8sjob.NewInClusterClient
		// is never even called) must ever appear in the result.
		for _, s := range got {
			if s == scanner.Scanner(isolated) || s == scanner.Scanner(trivyIsolated) {
				t.Fatal("an isolated scanner leaked into the in-process scanner list")
			}
		}
	})
}

// TestBuildSBOMScanners is buildImageScanners' own test, mirrored for
// buildSBOMScanners (see docs/architecture.md, "Isolating SBOM trivy
// scanning") -- the same DISABLE_SCAN_ISOLATION choice, just for the
// single sbom-type scanner instead of image's two.
func TestBuildSBOMScanners(t *testing.T) {
	inProcess := &namedScanner{"sbom-in-process"}
	isolated := &namedScanner{"sbom-isolated"}

	t.Run("isolation enabled (default): uses the isolated scanner", func(t *testing.T) {
		got := buildSBOMScanners(false, inProcess, isolated)
		if len(got) != 1 || got[0] != scanner.Scanner(isolated) {
			t.Fatalf("scanners = %+v, want [sbom-isolated]", got)
		}
	})

	t.Run("DISABLE_SCAN_ISOLATION=true: uses the in-process scanner instead", func(t *testing.T) {
		got := buildSBOMScanners(true, inProcess, isolated)
		if len(got) != 1 || got[0] != scanner.Scanner(inProcess) {
			t.Fatalf("scanners = %+v, want [sbom-in-process]", got)
		}
	})
}

// fakeFetcher is a trivial scanner.Fetcher double for
// TestRegisterExternalScanners -- it's never actually invoked (these
// tests only check *which* Scanner ends up registered where, never
// call Scan()), it just needs to satisfy the interface so
// registerExternalScanners has something to wrap file/sbom/sarif
// registrations in.
type fakeFetcher struct{}

func (fakeFetcher) Fetch(context.Context, string) (string, func(), error) {
	return "", func() {}, nil
}

// TestRegisterExternalScanners covers the EXTERNAL_SCANNERS wiring
// (see internal/scanner/external.go and docs/architecture.md,
// "Pluggable external scanners"): registration is additive per
// artifact type, image registrations are left unwrapped (an external
// image/CVE scanner is expected to resolve an OCI ref itself, same as
// trivy/unpacker), and file/sbom/sarif registrations get wrapped in
// FetchingScanner exactly like the built-in scanners for those types.
// Deliberately never calls Scan() on anything -- this only checks
// registry shape, not scanner behavior (that's external_test.go's job).
func TestRegisterExternalScanners(t *testing.T) {
	t.Run("registers into every listed artifact type, wrapping non-image types in FetchingScanner", func(t *testing.T) {
		reg := scanner.Registry{
			artifact.TypeImage: {&namedScanner{"trivy"}}, // pre-existing scanner must survive
		}
		specs := []scanner.ExternalScannerConfig{
			{
				Name:          "grype",
				Command:       "grype",
				Args:          []string{"{{ref}}", "-o", "json"},
				ArtifactTypes: []string{"image", "sbom"},
				Category:      "cve",
			},
		}

		if err := registerExternalScanners(reg, specs, fakeFetcher{}); err != nil {
			t.Fatalf("registerExternalScanners: %v", err)
		}

		imageScanners, _ := reg.For(artifact.TypeImage)
		if len(imageScanners) != 2 {
			t.Fatalf("image scanners = %+v, want the pre-existing trivy scanner plus the new one", imageScanners)
		}
		if _, ok := imageScanners[0].(*namedScanner); !ok {
			t.Errorf("pre-existing image scanner appears to have been replaced, not appended to: %+v", imageScanners[0])
		}
		if _, ok := imageScanners[1].(*scanner.ExternalScanner); !ok {
			t.Errorf("image scanner[1] = %T, want a raw *scanner.ExternalScanner (unwrapped -- image scanners resolve their own ref)", imageScanners[1])
		}

		sbomScanners, _ := reg.For(artifact.TypeSBOM)
		if len(sbomScanners) != 1 {
			t.Fatalf("sbom scanners = %+v, want exactly 1", sbomScanners)
		}
		if _, ok := sbomScanners[0].(*scanner.FetchingScanner); !ok {
			t.Errorf("sbom scanner = %T, want it wrapped in *scanner.FetchingScanner (sbom refs may be OCI registry references)", sbomScanners[0])
		}
	})

	t.Run("empty EXTERNAL_SCANNERS is a no-op", func(t *testing.T) {
		reg := scanner.Registry{artifact.TypeImage: {&namedScanner{"trivy"}}}
		if err := registerExternalScanners(reg, nil, fakeFetcher{}); err != nil {
			t.Fatalf("registerExternalScanners: %v", err)
		}
		got, _ := reg.For(artifact.TypeImage)
		if len(got) != 1 {
			t.Fatalf("expected the registry to be untouched, got %+v", got)
		}
	})

	t.Run("rejects a spec missing name", func(t *testing.T) {
		err := registerExternalScanners(scanner.Registry{}, []scanner.ExternalScannerConfig{
			{Command: "grype", ArtifactTypes: []string{"image"}},
		}, fakeFetcher{})
		if err == nil {
			t.Fatal("expected an error for a spec with no name")
		}
	})

	t.Run("rejects a spec missing command", func(t *testing.T) {
		err := registerExternalScanners(scanner.Registry{}, []scanner.ExternalScannerConfig{
			{Name: "grype", ArtifactTypes: []string{"image"}},
		}, fakeFetcher{})
		if err == nil {
			t.Fatal("expected an error for a spec with no command")
		}
	})

	t.Run("rejects a spec with no artifactTypes", func(t *testing.T) {
		err := registerExternalScanners(scanner.Registry{}, []scanner.ExternalScannerConfig{
			{Name: "grype", Command: "grype"},
		}, fakeFetcher{})
		if err == nil {
			t.Fatal("expected an error for a spec with no artifactTypes")
		}
	})

	t.Run("rejects an unrecognized artifactType", func(t *testing.T) {
		err := registerExternalScanners(scanner.Registry{}, []scanner.ExternalScannerConfig{
			{Name: "grype", Command: "grype", ArtifactTypes: []string{"container"}},
		}, fakeFetcher{})
		if err == nil {
			t.Fatal("expected an error for an unrecognized artifactType (\"container\" isn't image/file/sbom/sarif)")
		}
	})
}
