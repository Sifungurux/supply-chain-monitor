package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

	t.Run("sslrootcert is emitted only when set", func(t *testing.T) {
		// An empty sslrootcert= is NOT ignored -- it reads as "the CA
		// bundle is at the empty path", which makes verify-full
		// unable to connect at all. Absent is the only correct
		// representation of "not configured", so both directions are
		// asserted here.
		base := func() {
			t.Setenv("POSTGRES_DSN", "")
			t.Setenv("POSTGRES_HOST", "db")
			t.Setenv("POSTGRES_PORT", "5432")
			t.Setenv("POSTGRES_USER", "u")
			t.Setenv("POSTGRES_PASSWORD", "p")
			t.Setenv("POSTGRES_DB", "d")
			t.Setenv("POSTGRES_SSLMODE", "verify-full")
		}

		base()
		t.Setenv("POSTGRES_SSLROOTCERT", "")
		if got := buildPostgresDSN(); strings.Contains(got, "sslrootcert") {
			t.Fatalf("dsn = %q, want no sslrootcert param when the env var is empty", got)
		}

		base()
		t.Setenv("POSTGRES_SSLROOTCERT", "/postgres-ca/ca.crt")
		want := "postgres://u:p@db:5432/d?sslmode=verify-full&sslrootcert=/postgres-ca/ca.crt"
		if got := buildPostgresDSN(); got != want {
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

// TestBuildImageScanners pins down the behavioral differences
// DISABLE_SCAN_ISOLATION and cveScanner are supposed to make: which
// CVE scanner(s) and which malware scanner back the `image` artifact
// type, chosen consistently together. This is the only part of the
// isolation-fallback logic (see runAPIServer's comment, "Running
// monitor-api outside a Kubernetes pod") that's testable without a
// real Kubernetes API client or real trivy/grype binaries --
// deliberately split out of runAPIServer for exactly that reason.
func TestBuildImageScanners(t *testing.T) {
	trivyInProcess := &namedScanner{"trivy-in-process"}
	trivyIsolated := &namedScanner{"trivy-isolated"}
	grypeInProcess := &namedScanner{"grype-in-process"}
	grypeIsolated := &namedScanner{"grype-isolated"}
	inProcess := &namedScanner{"in-process-unpacker"}
	isolated := &namedScanner{"isolated-unpacker"}
	malcontentInProcess := &namedScanner{"in-process-malcontent"}
	malcontentIsolated := &namedScanner{"isolated-malcontent"}

	t.Run("isolation enabled (default): uses the isolated CVE scanner(s)", func(t *testing.T) {
		got := buildImageScanners(false, "trivy", "clamav", trivyInProcess, trivyIsolated, grypeInProcess, grypeIsolated, inProcess, isolated, malcontentInProcess, malcontentIsolated)
		if len(got) != 2 || got[0] != scanner.Scanner(trivyIsolated) || got[1] != scanner.Scanner(isolated) {
			t.Fatalf("scanners = %+v, want [trivy-isolated, isolated-unpacker]", got)
		}
	})

	t.Run("DISABLE_SCAN_ISOLATION=true: uses both in-process scanners instead", func(t *testing.T) {
		got := buildImageScanners(true, "trivy", "clamav", trivyInProcess, trivyIsolated, grypeInProcess, grypeIsolated, inProcess, isolated, malcontentInProcess, malcontentIsolated)
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

	t.Run(`cveScanner="grype": trivy is dropped entirely`, func(t *testing.T) {
		got := buildImageScanners(false, "grype", "clamav", trivyInProcess, trivyIsolated, grypeInProcess, grypeIsolated, inProcess, isolated, malcontentInProcess, malcontentIsolated)
		if len(got) != 2 || got[0] != scanner.Scanner(grypeIsolated) || got[1] != scanner.Scanner(isolated) {
			t.Fatalf("scanners = %+v, want [grype-isolated, isolated-unpacker]", got)
		}
	})

	t.Run(`cveScanner="both": both CVE scanners run alongside the malware scanner`, func(t *testing.T) {
		got := buildImageScanners(false, "both", "clamav", trivyInProcess, trivyIsolated, grypeInProcess, grypeIsolated, inProcess, isolated, malcontentInProcess, malcontentIsolated)
		if len(got) != 3 || got[0] != scanner.Scanner(trivyIsolated) || got[1] != scanner.Scanner(grypeIsolated) || got[2] != scanner.Scanner(isolated) {
			t.Fatalf("scanners = %+v, want [trivy-isolated, grype-isolated, isolated-unpacker]", got)
		}
	})
}

// TestBuildImageScanners_CVEScannerTrivyIsUnchanged is the regression
// test the plan for adding grype explicitly called for: cveScanner
// unset/"trivy" must produce the exact same scanner list
// buildImageScanners returned before grype existed at all (a bare
// [trivy, unpacker] pair, isolated or in-process together) --
// confirmed here by asserting the length and identity of every
// element, not just that grype is merely "absent somewhere."
func TestBuildImageScanners_CVEScannerTrivyIsUnchanged(t *testing.T) {
	trivyInProcess := &namedScanner{"trivy-in-process"}
	trivyIsolated := &namedScanner{"trivy-isolated"}
	grypeInProcess := &namedScanner{"grype-in-process"}
	grypeIsolated := &namedScanner{"grype-isolated"}
	inProcess := &namedScanner{"in-process-unpacker"}
	isolated := &namedScanner{"isolated-unpacker"}
	malcontentInProcess := &namedScanner{"in-process-malcontent"}
	malcontentIsolated := &namedScanner{"isolated-malcontent"}

	for _, isolationDisabled := range []bool{false, true} {
		got := buildImageScanners(isolationDisabled, "trivy", "clamav", trivyInProcess, trivyIsolated, grypeInProcess, grypeIsolated, inProcess, isolated, malcontentInProcess, malcontentIsolated)
		want := []scanner.Scanner{trivyIsolated, isolated}
		if isolationDisabled {
			want = []scanner.Scanner{trivyInProcess, inProcess}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("disableScanIsolation=%v: scanners = %+v, want %+v", isolationDisabled, got, want)
		}
	}
}

// TestBuildSBOMScanners is buildImageScanners' own test, mirrored for
// buildSBOMScanners (see docs/architecture.md, "Isolating SBOM trivy
// scanning") -- the same DISABLE_SCAN_ISOLATION/cveScanner choices,
// just for the sbom-type scanner list (no malware scanner) instead of
// image's.
func TestBuildSBOMScanners(t *testing.T) {
	trivyInProcess := &namedScanner{"trivy-sbom-in-process"}
	trivyIsolated := &namedScanner{"trivy-sbom-isolated"}
	grypeInProcess := &namedScanner{"grype-sbom-in-process"}
	grypeIsolated := &namedScanner{"grype-sbom-isolated"}

	t.Run("isolation enabled (default): uses the isolated scanner", func(t *testing.T) {
		got := buildSBOMScanners(false, "trivy", trivyInProcess, trivyIsolated, grypeInProcess, grypeIsolated)
		if len(got) != 1 || got[0] != scanner.Scanner(trivyIsolated) {
			t.Fatalf("scanners = %+v, want [trivy-sbom-isolated]", got)
		}
	})

	t.Run("DISABLE_SCAN_ISOLATION=true: uses the in-process scanner instead", func(t *testing.T) {
		got := buildSBOMScanners(true, "trivy", trivyInProcess, trivyIsolated, grypeInProcess, grypeIsolated)
		if len(got) != 1 || got[0] != scanner.Scanner(trivyInProcess) {
			t.Fatalf("scanners = %+v, want [trivy-sbom-in-process]", got)
		}
	})

	t.Run(`cveScanner="both": both scanners run`, func(t *testing.T) {
		got := buildSBOMScanners(false, "both", trivyInProcess, trivyIsolated, grypeInProcess, grypeIsolated)
		if len(got) != 2 || got[0] != scanner.Scanner(trivyIsolated) || got[1] != scanner.Scanner(grypeIsolated) {
			t.Fatalf("scanners = %+v, want [trivy-sbom-isolated, grype-sbom-isolated]", got)
		}
	})
}

// fakeFetcher is a trivial scanner.Fetcher double for
// TestRegisterPluggableScanners -- it's never actually invoked (these
// tests only check *which* Scanner ends up registered where, never
// call Scan()), it just needs to satisfy the interface so
// registerPluggableScanners has something to wrap file/sbom/sarif
// registrations in.
type fakeFetcher struct{}

func (fakeFetcher) Fetch(context.Context, string) (string, func(), error) {
	return "", func() {}, nil
}

// TestRegisterPluggableScanners covers the PLUGGABLE_SCANNERS wiring
// (see internal/scanner/pluggable.go and docs/architecture.md,
// "Pluggable scanners"): registration is additive per artifact type,
// image registrations are left unwrapped (a pluggable image/CVE
// scanner is expected to resolve an OCI ref itself, same as
// trivy/unpacker), and file/sbom/sarif registrations get wrapped in
// FetchingScanner exactly like the built-in scanners for those types.
// Deliberately never calls Scan() on anything -- this only checks
// registry shape, not scanner behavior (that's pluggable_test.go's job).
func TestRegisterPluggableScanners(t *testing.T) {
	t.Run("registers into every listed artifact type, wrapping non-image types in FetchingScanner", func(t *testing.T) {
		reg := scanner.Registry{
			artifact.TypeImage: {&namedScanner{"trivy"}}, // pre-existing scanner must survive
		}
		specs := []scanner.PluggableScannerConfig{
			{
				Name:          "grype",
				Command:       "grype",
				Args:          []string{"{{ref}}", "-o", "json"},
				ArtifactTypes: []string{"image", "sbom"},
				Category:      "cve",
			},
		}

		if err := registerPluggableScanners(reg, specs, fakeFetcher{}); err != nil {
			t.Fatalf("registerPluggableScanners: %v", err)
		}

		imageScanners, _ := reg.For(artifact.TypeImage)
		if len(imageScanners) != 2 {
			t.Fatalf("image scanners = %+v, want the pre-existing trivy scanner plus the new one", imageScanners)
		}
		if _, ok := imageScanners[0].(*namedScanner); !ok {
			t.Errorf("pre-existing image scanner appears to have been replaced, not appended to: %+v", imageScanners[0])
		}
		if _, ok := imageScanners[1].(*scanner.PluggableScanner); !ok {
			t.Errorf("image scanner[1] = %T, want a raw *scanner.PluggableScanner (unwrapped -- image scanners resolve their own ref)", imageScanners[1])
		}

		sbomScanners, _ := reg.For(artifact.TypeSBOM)
		if len(sbomScanners) != 1 {
			t.Fatalf("sbom scanners = %+v, want exactly 1", sbomScanners)
		}
		if _, ok := sbomScanners[0].(*scanner.FetchingScanner); !ok {
			t.Errorf("sbom scanner = %T, want it wrapped in *scanner.FetchingScanner (sbom refs may be OCI registry references)", sbomScanners[0])
		}
	})

	t.Run("empty PLUGGABLE_SCANNERS is a no-op", func(t *testing.T) {
		reg := scanner.Registry{artifact.TypeImage: {&namedScanner{"trivy"}}}
		if err := registerPluggableScanners(reg, nil, fakeFetcher{}); err != nil {
			t.Fatalf("registerPluggableScanners: %v", err)
		}
		got, _ := reg.For(artifact.TypeImage)
		if len(got) != 1 {
			t.Fatalf("expected the registry to be untouched, got %+v", got)
		}
	})

	t.Run("rejects a spec missing name", func(t *testing.T) {
		err := registerPluggableScanners(scanner.Registry{}, []scanner.PluggableScannerConfig{
			{Command: "grype", ArtifactTypes: []string{"image"}},
		}, fakeFetcher{})
		if err == nil {
			t.Fatal("expected an error for a spec with no name")
		}
	})

	t.Run("rejects a spec missing command", func(t *testing.T) {
		err := registerPluggableScanners(scanner.Registry{}, []scanner.PluggableScannerConfig{
			{Name: "grype", ArtifactTypes: []string{"image"}},
		}, fakeFetcher{})
		if err == nil {
			t.Fatal("expected an error for a spec with no command")
		}
	})

	t.Run("rejects a spec with no artifactTypes", func(t *testing.T) {
		err := registerPluggableScanners(scanner.Registry{}, []scanner.PluggableScannerConfig{
			{Name: "grype", Command: "grype"},
		}, fakeFetcher{})
		if err == nil {
			t.Fatal("expected an error for a spec with no artifactTypes")
		}
	})

	t.Run("rejects an unrecognized artifactType", func(t *testing.T) {
		err := registerPluggableScanners(scanner.Registry{}, []scanner.PluggableScannerConfig{
			{Name: "grype", Command: "grype", ArtifactTypes: []string{"container"}},
		}, fakeFetcher{})
		if err == nil {
			t.Fatal("expected an error for an unrecognized artifactType (\"container\" isn't image/file/sbom/sarif)")
		}
	})
}

// TestPickArtifactsToSweep covers the pure selection logic
// runSweepRegistered relies on -- no HTTP involved, same as
// TestBuildImageScanners/TestBuildSBOMScanners above.
func TestPickArtifactsToSweep(t *testing.T) {
	now := time.Now().UTC()
	mk := func(id string, status artifact.Status, age time.Duration) artifact.Artifact {
		return artifact.Artifact{ID: id, Status: status, CreatedAt: now.Add(-age)}
	}

	// THE BUG THIS FUNCTION USED TO HAVE. It filtered to status
	// "registered" itself, so runSweepRegistered's reclaim of artifacts
	// stuck at "scanning" -- which lists them, logs "reclaiming by
	// re-scanning", and appends them to this very slice -- had every
	// one of them silently dropped here. The log line was the only
	// evidence anything happened, and nothing did. Eligibility is the
	// caller's now; this orders and caps.
	t.Run("returns whatever the caller deemed eligible, whatever its status", func(t *testing.T) {
		all := []artifact.Artifact{
			mk("a", artifact.StatusRegistered, time.Hour),
			mk("b", artifact.StatusScanning, time.Hour),
			mk("c", artifact.StatusScanned, time.Hour),
			mk("d", artifact.StatusFailed, time.Hour),
		}
		got := pickArtifactsToSweep(all, 10)
		if len(got) != 4 {
			t.Fatalf("got %d artifacts, want all 4 -- the caller decides eligibility, not this", len(got))
		}
		for _, a := range got {
			if a.Status == artifact.StatusScanning {
				return // the stuck-scan reclaim survives
			}
		}
		t.Fatal("a stuck-at-scanning artifact was dropped -- that is the reclaim this silently broke")
	})

	t.Run("oldest first, so a backlog works through fairly across runs", func(t *testing.T) {
		all := []artifact.Artifact{
			mk("newest", artifact.StatusRegistered, time.Minute),
			mk("oldest", artifact.StatusRegistered, 24*time.Hour),
			mk("middle", artifact.StatusRegistered, time.Hour),
		}
		got := pickArtifactsToSweep(all, 10)
		want := []string{"oldest", "middle", "newest"}
		if len(got) != len(want) {
			t.Fatalf("got %d artifacts, want %d", len(got), len(want))
		}
		for i, id := range want {
			if got[i].ID != id {
				t.Fatalf("position %d: got %q, want %q (order = %v)", i, got[i].ID, id, got)
			}
		}
	})

	// THE STARVATION THIS ORDERING EXISTS TO PREVENT. Failed artifacts
	// are now retried on every sweep run, so without this the same
	// old, permanently-broken artifact wins the same slot forever: it
	// is retried, stays failed, keeps its CreatedAt, and sorts first
	// again on the next run, while newer work behind it is never
	// reached. Ordering by last attempt sends it to the back.
	t.Run("least recently attempted first, so a broken artifact cannot hog the batch", func(t *testing.T) {
		at := func(id string, since time.Duration) artifact.Artifact {
			ts := now.Add(-since)
			// Registered long before any of them were scanned, so
			// CreatedAt alone would order these exactly backwards.
			return artifact.Artifact{ID: id, Status: artifact.StatusFailed, CreatedAt: now.Add(-99 * time.Hour), LastScanAt: &ts}
		}
		all := []artifact.Artifact{
			at("retried-just-now", time.Minute),
			at("waiting-longest", 24*time.Hour),
			at("waiting-a-while", time.Hour),
		}
		got := pickArtifactsToSweep(all, 10)
		want := []string{"waiting-longest", "waiting-a-while", "retried-just-now"}
		for i, id := range want {
			if got[i].ID != id {
				t.Fatalf("position %d: got %q, want %q -- a just-retried artifact must go to the back", i, got[i].ID, id)
			}
		}
	})

	t.Run("never attempted outranks a recent retry, however old the registration", func(t *testing.T) {
		scanned := now.Add(-time.Minute)
		all := []artifact.Artifact{
			// Failed, retried a minute ago, registered a week ago.
			{ID: "retried", Status: artifact.StatusFailed, CreatedAt: now.Add(-168 * time.Hour), LastScanAt: &scanned},
			// Registered a minute ago and never scanned once.
			{ID: "never-scanned", Status: artifact.StatusRegistered, CreatedAt: now.Add(-time.Minute)},
		}
		got := pickArtifactsToSweep(all, 10)
		if got[0].ID != "never-scanned" {
			t.Fatalf("got %q first, want \"never-scanned\" -- an artifact nobody has scanned once outranks retrying one just attempted", got[0].ID)
		}
	})

	t.Run("truncates to batchSize", func(t *testing.T) {
		all := []artifact.Artifact{
			mk("a", artifact.StatusRegistered, 3*time.Hour),
			mk("b", artifact.StatusRegistered, 2*time.Hour),
			mk("c", artifact.StatusRegistered, time.Hour),
		}
		got := pickArtifactsToSweep(all, 2)
		if len(got) != 2 {
			t.Fatalf("got %d artifacts, want exactly batchSize=2", len(got))
		}
	})

	t.Run("batchSize <= 0 means nothing to do, not unbounded", func(t *testing.T) {
		all := []artifact.Artifact{mk("a", artifact.StatusRegistered, time.Hour)}
		for _, batchSize := range []int{0, -1} {
			if got := pickArtifactsToSweep(all, batchSize); len(got) != 0 {
				t.Fatalf("batchSize=%d: got %d artifacts, want 0 (fail closed, not unbounded)", batchSize, len(got))
			}
		}
	})

	t.Run("nothing eligible", func(t *testing.T) {
		if got := pickArtifactsToSweep(nil, 10); len(got) != 0 {
			t.Fatalf("got %d artifacts, want 0", len(got))
		}
	})
}

// staleScans is the auto-rescan population: last scanned before the
// cutoff. The never-scanned exclusion is the part worth pinning, since
// the dashboard badge and Store.CountStaleScans apply the same rule and
// disagreeing would make the count and the visible badges contradict.
func TestStaleScans(t *testing.T) {
	now := time.Now().UTC()
	cutoff := now.Add(-7 * 24 * time.Hour)
	at := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }

	all := []artifact.Artifact{
		{ID: "stale", Status: artifact.StatusScanned, LastScanAt: at(30 * 24 * time.Hour)},
		{ID: "fresh", Status: artifact.StatusScanned, LastScanAt: at(time.Hour)},
		{ID: "never", Status: artifact.StatusRegistered, LastScanAt: nil},
		{ID: "just-past", Status: artifact.StatusFailed, LastScanAt: at(8 * 24 * time.Hour)},
	}

	got := staleScans(all, cutoff)
	if len(got) != 2 {
		t.Fatalf("got %d stale, want 2: %+v", len(got), got)
	}
	ids := map[string]bool{got[0].ID: true, got[1].ID: true}
	if !ids["stale"] || !ids["just-past"] {
		t.Errorf("stale set = %v, want stale and just-past", ids)
	}
	if ids["never"] {
		t.Error("a never-scanned artifact was counted stale -- it is a different state, already swept as \"registered\", and the dashboard excludes it too")
	}
}

// The scan queue wait this file used to guard against
// httpWriteTimeout is gone: scans are asynchronous now (202 + poll --
// see internal/api's scanArtifact), so no handler blocks long enough to
// race the write deadline, and a saturated cap answers 429 immediately
// instead of waiting for a slot. httpWriteTimeout still bounds how long
// a handler has to write a response; nothing in this service now takes
// anywhere near it.

// TestMalwareScannersFor_ClamAVIsUnchanged is the test that makes this
// feature safe to merge: with MALWARE_SCANNER unset (or set to anything
// unrecognized), the malware half of the image scanner list is exactly
// what it was before malcontent existed. Same guarantee, and the same
// reasoning, as TestBuildImageScanners' cveScanner="trivy" case.
func TestMalwareScannersFor_ClamAVIsUnchanged(t *testing.T) {
	clamav := &namedScanner{"clamav"}
	malcontent := &namedScanner{"malcontent"}

	for _, setting := range []string{"", "clamav", "CLAMAV", "nonsense"} {
		t.Run("setting="+setting, func(t *testing.T) {
			got := malwareScannersFor(setting, clamav, malcontent)
			if len(got) != 1 || got[0] != scanner.Scanner(clamav) {
				t.Fatalf("scanners = %+v, want ClamAV alone -- an unrecognized value must not silently enable a second scanner", got)
			}
		})
	}
}

func TestMalwareScannersFor_Selection(t *testing.T) {
	clamav := &namedScanner{"clamav"}
	malcontent := &namedScanner{"malcontent"}

	t.Run(`"malcontent" replaces ClamAV`, func(t *testing.T) {
		got := malwareScannersFor("malcontent", clamav, malcontent)
		if len(got) != 1 || got[0] != scanner.Scanner(malcontent) {
			t.Fatalf("scanners = %+v, want malcontent alone", got)
		}
	})

	t.Run(`"both" runs them together`, func(t *testing.T) {
		got := malwareScannersFor("both", clamav, malcontent)
		if len(got) != 2 || got[0] != scanner.Scanner(clamav) || got[1] != scanner.Scanner(malcontent) {
			t.Fatalf("scanners = %+v, want [clamav, malcontent]", got)
		}
	})
}

// The selector has to reach the actual image scanner list, and pick the
// isolated or in-process malcontent to match the isolation setting --
// mixing those would run an isolated CVE scan next to an in-process
// image unpack, which is the arrangement isolation exists to prevent.
func TestBuildImageScanners_MalwareSelectorReachesTheList(t *testing.T) {
	trivyInProcess := &namedScanner{"trivy-in-process"}
	trivyIsolated := &namedScanner{"trivy-isolated"}
	grypeInProcess := &namedScanner{"grype-in-process"}
	grypeIsolated := &namedScanner{"grype-isolated"}
	inProcess := &namedScanner{"in-process-unpacker"}
	isolated := &namedScanner{"isolated-unpacker"}
	malcontentInProcess := &namedScanner{"in-process-malcontent"}
	malcontentIsolated := &namedScanner{"isolated-malcontent"}

	t.Run("both, isolated", func(t *testing.T) {
		got := buildImageScanners(false, "trivy", "both",
			trivyInProcess, trivyIsolated, grypeInProcess, grypeIsolated,
			inProcess, isolated, malcontentInProcess, malcontentIsolated)
		if len(got) != 3 || got[1] != scanner.Scanner(isolated) || got[2] != scanner.Scanner(malcontentIsolated) {
			t.Fatalf("scanners = %+v, want [trivy-isolated, isolated-unpacker, isolated-malcontent]", got)
		}
	})

	t.Run("both, DISABLE_SCAN_ISOLATION", func(t *testing.T) {
		got := buildImageScanners(true, "trivy", "both",
			trivyInProcess, trivyIsolated, grypeInProcess, grypeIsolated,
			inProcess, isolated, malcontentInProcess, malcontentIsolated)
		if len(got) != 3 || got[2] != scanner.Scanner(malcontentInProcess) {
			t.Fatalf("scanners = %+v, want the in-process malcontent", got)
		}
		for _, s := range got {
			if s == scanner.Scanner(malcontentIsolated) || s == scanner.Scanner(isolated) {
				t.Fatal("an isolated scanner leaked into the in-process list")
			}
		}
	})
}

// setupLogging reads LOG_LEVEL and installs the process-wide JSON
// handler. Tested through slog.Default() rather than by exporting the
// level, because the thing that matters is whether a debug line
// actually reaches the output -- a correctly parsed level that never
// gets applied to the handler looks identical from the outside.
func TestSetupLogging_LevelFromEnv(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	cases := []struct {
		env        string
		debugShows bool
	}{
		{"", false},         // default: info
		{"info", false},     //
		{"DEBUG", true},     // case-insensitive
		{" debug ", true},   // surrounding whitespace tolerated
		{"warn", false},     //
		{"nonsense", false}, // unrecognized falls back to info, never refuses to start
	}
	for _, tc := range cases {
		t.Setenv("LOG_LEVEL", tc.env)
		setupLogging()
		if got := slog.Default().Enabled(context.Background(), slog.LevelDebug); got != tc.debugShows {
			t.Errorf("LOG_LEVEL=%q: debug enabled = %v, want %v", tc.env, got, tc.debugShows)
		}
		// Every level must still let errors through -- a log-verbosity
		// setting that could silence errors would be a foot-gun.
		if !slog.Default().Enabled(context.Background(), slog.LevelError) {
			t.Errorf("LOG_LEVEL=%q: error level is disabled, which no setting should do", tc.env)
		}
	}
}

// The handler must write to stderr, leaving stdout to `monitor-api
// scan-worker`'s WorkerResult JSON. The parent parses that back out of
// the Job pod's combined logs anchored on scanner.ResultMarker, so it
// would survive either way -- but keeping the result on its own stream
// means the two never have to be untangled.
func TestSetupLogging_WritesJSONToStderr(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	realStderr := os.Stderr
	os.Stderr = w
	t.Setenv("LOG_LEVEL", "info")
	setupLogging()
	slog.Info("a message", "artifact_id", "abc123")
	os.Stderr = realStderr
	w.Close()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	var line map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &line); err != nil {
		t.Fatalf("stderr line is not JSON: %s (%v)", out, err)
	}
	if line["msg"] != "a message" || line["artifact_id"] != "abc123" {
		t.Errorf("line = %v, want msg and artifact_id carried as fields", line)
	}
}

// The mirror backfill's whole job is to find artifacts registration
// never mirrored -- and, just as importantly, to STOP finding the ones
// that were settled as unmirrorable. Without the second half the sweep
// would rescan every local-path artifact on every run, forever, waiting
// for a copy that is never going to happen.
func TestUnmirroredArtifacts(t *testing.T) {
	list := []artifact.Artifact{
		{ID: "never-mirrored", Ref: "ghcr.io/acme/app:1.0"},
		{ID: "mirrored", Ref: "scm-registry:5000/mirror/ghcr.io/acme/app:1.0", SourceRef: "ghcr.io/acme/app:1.0"},
		// Settled as "nothing to copy": source_ref equals ref. Must not
		// come back, or the backfill never converges.
		{ID: "not-mirrorable", Ref: "/var/lib/artifacts/report.json", SourceRef: "/var/lib/artifacts/report.json"},
	}
	got := unmirroredArtifacts(list, time.Now().UTC().Add(-mirrorRetryInterval))
	if len(got) != 1 || got[0].ID != "never-mirrored" {
		ids := make([]string, len(got))
		for i, a := range got {
			ids[i] = a.ID
		}
		t.Fatalf("unmirroredArtifacts returned %v, want just [never-mirrored]", ids)
	}
	if out := unmirroredArtifacts(nil, time.Now().UTC()); len(out) != 0 {
		t.Errorf("unmirroredArtifacts(nil) = %v, want empty", out)
	}
}

// The passes feeding pickArtifactsToSweep stopped being disjoint when
// the mirror backfill started selecting on source_ref rather than on
// status: an artifact that is both stale and unmirrored arrives twice.
// A duplicate costs a batch slot AND a second POST /scan for work
// already in flight.
func TestPickArtifactsToSweepDeduplicates(t *testing.T) {
	scanned := time.Now().UTC().Add(-90 * 24 * time.Hour)
	both := artifact.Artifact{ID: "stale-and-unmirrored", Ref: "ghcr.io/acme/app:1.0", LastScanAt: &scanned}
	other := artifact.Artifact{ID: "just-registered", Ref: "ghcr.io/acme/other:1.0"}

	got := pickArtifactsToSweep([]artifact.Artifact{both, other, both}, 10)
	if len(got) != 2 {
		ids := make([]string, len(got))
		for i, a := range got {
			ids[i] = a.ID
		}
		t.Fatalf("pickArtifactsToSweep returned %v, want each artifact once", ids)
	}
	// And a duplicate must not push a distinct artifact out of a batch
	// that had room for it. Order is pickArtifactsToSweep's own
	// least-recently-attempted rule (never-scanned first), so this
	// checks membership, not position.
	got = pickArtifactsToSweep([]artifact.Artifact{both, both, other}, 2)
	ids := map[string]bool{}
	for _, a := range got {
		ids[a.ID] = true
	}
	if len(got) != 2 || !ids[both.ID] || !ids[other.ID] {
		t.Fatalf("a duplicate consumed a batch slot -- got %d artifact(s), ids %v", len(got), ids)
	}
}

// The scan Job REQUEST is what bounds achievable scan concurrency:
// Kubernetes schedules on requests, and the trivy/grype Jobs are pinned
// to one node by their ReadWriteOnce DB-cache PVCs, so the request is
// multiplied by the scan cap against a single node's memory. The
// On k3d every node advertises the WHOLE shared VM, so the request is
// the only admission control there is -- it is a concurrency brake, not a
// memory estimate. Lowering it to match measured RSS (median 31Mi) once
// took the VM to load average 174 and the API server offline. A silent
// change here is a silent change to how much work reaches the hardware.
func TestScanJobResourceDefaultsAndOverrides(t *testing.T) {
	for _, kind := range []string{"trivy", "grype", "unpacker"} {
		if got := scanJobCPU(kind); got != "200m" {
			t.Errorf("scanJobCPU(%s) = %q, want 200m", kind, got)
		}
		if got := scanJobMem(kind); got != "512Mi" {
			t.Errorf("scanJobMem(%s) = %q, want 512Mi", kind, got)
		}
		// Empty means "the scanner package's own default" -- not zero.
		if got := scanJobMemLimit(kind); got != "" {
			t.Errorf("scanJobMemLimit(%s) = %q, want empty", kind, got)
		}
	}

	// Per-kind override beats the global one, which is the whole point:
	// grype needs a bigger LIMIT than the others without changing
	// anyone's request.
	t.Setenv("SCAN_JOB_MEMORY_LIMIT", "1Gi")
	t.Setenv("SCAN_JOB_MEMORY_LIMIT_GRYPE", "1536Mi")
	if got := scanJobMemLimit("grype"); got != "1536Mi" {
		t.Errorf("per-kind limit lost: got %q, want 1536Mi", got)
	}
	if got := scanJobMemLimit("trivy"); got != "1Gi" {
		t.Errorf("global limit not applied to trivy: got %q, want 1Gi", got)
	}

	t.Setenv("SCAN_JOB_MEMORY_REQUEST", "128Mi")
	t.Setenv("SCAN_JOB_MEMORY_REQUEST_UNPACKER", "512Mi")
	if got := scanJobMem("unpacker"); got != "512Mi" {
		t.Errorf("per-kind request lost: got %q, want 512Mi", got)
	}
	if got := scanJobMem("trivy"); got != "128Mi" {
		t.Errorf("global request not applied to trivy: got %q, want 128Mi", got)
	}
}

// --- sbom-only sweep (SWEEP_MODE=sbom-only) ---

// TestSBOMReevalEligible pins the narrow population an sbom-only sweep
// may touch. Both conditions matter, and getting either wrong is a
// silent waste rather than a visible bug: an ineligible artifact is
// POSTed, takes a grype scan slot, and comes back 400/409 -- so the run
// looks busy while re-evaluating nothing.
func TestSBOMReevalEligible(t *testing.T) {
	all := []artifact.Artifact{
		{ID: "image-with-sbom", Type: artifact.TypeImage, HasSBOM: true},
		{ID: "image-without-sbom", Type: artifact.TypeImage},
		// An sbom-TYPE artifact is the document; the normal scan path
		// already scans it directly, and re-evaluation has no stored
		// document of its own to read (indexSBOMTypeComponents
		// deliberately does not save one -- see its comment).
		{ID: "sbom-type", Type: artifact.TypeSBOM, HasSBOM: true},
		{ID: "file-type", Type: artifact.TypeFile, HasSBOM: true},
		{ID: "sarif-type", Type: artifact.TypeSARIF, HasSBOM: true},
		{ID: "another-image", Type: artifact.TypeImage, HasSBOM: true},
	}

	got := sbomReevalEligible(all)
	want := []string{"image-with-sbom", "another-image"}
	if len(got) != len(want) {
		t.Fatalf("eligible = %d artifacts, want %d: %+v", len(got), len(want), got)
	}
	for i, id := range want {
		if got[i].ID != id {
			t.Errorf("eligible[%d] = %q, want %q", i, got[i].ID, id)
		}
	}
}

// TestSBOMReevalEligible_Empty covers the fleet that has never been
// fully scanned: nothing is eligible, and the sweep must produce an
// empty batch rather than falling back to "everything".
func TestSBOMReevalEligible_Empty(t *testing.T) {
	all := []artifact.Artifact{
		{ID: "a", Type: artifact.TypeImage},
		{ID: "b", Type: artifact.TypeSBOM, HasSBOM: true},
	}
	if got := sbomReevalEligible(all); len(got) != 0 {
		t.Fatalf("eligible = %+v, want none", got)
	}
}

// TestParseRetryAfter covers the header the sbom-only sweep waits on.
// An unparseable or absent value must read as 0 so the caller falls
// back to its own backoff instead of trusting something it did not
// understand -- and an absurd value must be bounded, or one artifact
// could park the whole run.
func TestParseRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{"5", 5 * time.Second},
		{" 30 ", 30 * time.Second},
		{"", 0},
		{"0", 0},
		{"-1", 0},
		{"soon", 0},
		{"Wed, 21 Oct 2026 07:28:00 GMT", 0}, // HTTP-date form: not sent by this API
		{"99999", 120 * time.Second},         // bounded
	} {
		if got := parseRetryAfter(tc.in); got != tc.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestCapSaturatedIsErrScanCapSaturated pins the sentinel relationship
// the sweep's own control flow depends on: every existing
// errors.Is(err, errScanCapSaturated) check must keep matching now that
// a struct carrying Retry-After is what actually gets returned.
func TestCapSaturatedIsErrScanCapSaturated(t *testing.T) {
	err := error(capSaturated{retryAfter: 7 * time.Second})
	if !errors.Is(err, errScanCapSaturated) {
		t.Fatal("capSaturated must satisfy errors.Is(err, errScanCapSaturated)")
	}
	var sat capSaturated
	if !errors.As(err, &sat) || sat.retryAfter != 7*time.Second {
		t.Fatalf("errors.As did not recover the Retry-After: %+v", sat)
	}
}

// --- sweep summary reporting ---

// sweepStub serves the three endpoints runSweepRegistered calls, with
// per-artifact control over what POST /scan answers. It exists because
// the sweep runs as an unattended CronJob whose single summary log line
// is the only signal anybody reads -- and that line had no test at all.
type sweepStub struct {
	// scanStatus maps artifact id -> HTTP status POST /scan returns.
	// Anything not listed answers 202 and then reports "scanned".
	scanStatus map[string]int
}

func (s *sweepStub) handler(t *testing.T, ids []string) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/artifacts", func(w http.ResponseWriter, r *http.Request) {
		var out []artifact.Artifact
		// Only the "registered" pass returns anything; the stuck/failed
		// passes return empty, keeping the batch exactly `ids`.
		if r.URL.Query().Get("status") == string(artifact.StatusRegistered) {
			for _, id := range ids {
				out = append(out, artifact.Artifact{ID: id, Ref: "example.com/" + id + ":1", Type: artifact.TypeImage, Status: artifact.StatusRegistered})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"total": len(out), "artifacts": out})
	})
	mux.HandleFunc("POST /api/v1/artifacts/{id}/scan", func(w http.ResponseWriter, r *http.Request) {
		code := http.StatusAccepted
		if c, ok := s.scanStatus[r.PathValue("id")]; ok {
			code = c
		}
		if code == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "1")
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(artifact.Artifact{ID: r.PathValue("id"), Status: artifact.StatusScanning})
	})
	mux.HandleFunc("GET /api/v1/artifacts/{id}", func(w http.ResponseWriter, r *http.Request) {
		// The poll after a 202: already finished, with a digest, so a
		// success is unambiguous in the summary.
		_ = json.NewEncoder(w).Encode(artifact.Artifact{
			ID: r.PathValue("id"), Ref: "example.com/" + r.PathValue("id") + ":1",
			Status: artifact.StatusScanned, Digest: "sha256:" + r.PathValue("id"),
		})
	})
	return mux
}

// runSweepCapturingLog runs the sweep against a stub and returns
// everything it logged.
func runSweepCapturingLog(t *testing.T, ids []string, stub *sweepStub) string {
	t.Helper()
	srv := httptest.NewServer(stub.handler(t, ids))
	defer srv.Close()

	t.Setenv("SWEEP_API_BASE_URL", srv.URL)
	t.Setenv("SWEEP_API_KEY", "test-key")
	t.Setenv("SWEEP_BATCH_SIZE", strconv.Itoa(len(ids)))
	t.Setenv("SWEEP_MODE", "full")
	t.Setenv("SWEEP_RESCAN_STALE_AFTER_DAYS", "0")
	t.Setenv("SWEEP_MIRROR_BACKFILL", "false")

	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	runSweepRegistered()
	return buf.String()
}

// TestSweepSummary_CountsWhatActuallyHappened is the regression test for
// a summary line that lied.
//
// It used to report len(toScan) as the number scanned regardless of
// outcome, so a run in which every single scan failed still signed off
// with "5 scanned" -- on an unattended CronJob whose log is the only
// thing an operator reads to decide whether the sweep is healthy.
func TestSweepSummary_CountsWhatActuallyHappened(t *testing.T) {
	ids := []string{"aaa1", "bbb2", "ccc3", "ddd4"}
	out := runSweepCapturingLog(t, ids, &sweepStub{scanStatus: map[string]int{
		"bbb2": http.StatusInternalServerError, // a real failure
		"ccc3": http.StatusInternalServerError, // another
		"ddd4": http.StatusTooManyRequests,     // cap saturated -- not a failure
	}})

	// One scanned (aaa1), two failed, one not attempted.
	want := "done -- 1 scanned, 2 failed, 1 not attempted"
	if !strings.Contains(out, want) {
		t.Errorf("summary line wrong.\nwant substring: %q\ngot log:\n%s", want, out)
	}
	// The specific historical bug: never claim the whole batch scanned.
	if strings.Contains(out, "done -- 4 scanned") {
		t.Errorf("summary reported the whole batch as scanned despite 2 failures and a 429:\n%s", out)
	}
}

// TestSweepSummary_AllFailed is the case the old line got most wrong:
// nothing worked at all, and it still read as a clean run.
func TestSweepSummary_AllFailed(t *testing.T) {
	ids := []string{"aaa1", "bbb2"}
	out := runSweepCapturingLog(t, ids, &sweepStub{scanStatus: map[string]int{
		"aaa1": http.StatusInternalServerError,
		"bbb2": http.StatusInternalServerError,
	}})

	if !strings.Contains(out, "done -- 0 scanned, 2 failed") {
		t.Errorf("a run where every scan failed must say so.\ngot log:\n%s", out)
	}
}

// TestSweepSummary_AllSucceeded keeps the happy path honest too -- a
// counter that only ever reports failures would pass the tests above.
func TestSweepSummary_AllSucceeded(t *testing.T) {
	ids := []string{"aaa1", "bbb2", "ccc3"}
	out := runSweepCapturingLog(t, ids, &sweepStub{})

	if !strings.Contains(out, "done -- 3 scanned, 0 failed, 0 not attempted") {
		t.Errorf("clean run summary wrong.\ngot log:\n%s", out)
	}
	if !strings.Contains(out, "digest resolved") {
		t.Errorf("expected per-artifact digest lines.\ngot log:\n%s", out)
	}
}

// --- sbom re-evaluation tool selection ---

// stubScanner is a bare Scanner used only to tell two instances apart.
type stubScanner struct{ name string }

func (s *stubScanner) Scan(context.Context, string) ([]artifact.Finding, error) { return nil, nil }

// TestSBOMReevalScanner_MatchesTheToolThatBuiltTheBucket pins the rule
// that makes an sbom-only round useful rather than noisy.
//
// The round merges into the cve bucket the IMAGE scan populated, and
// the two tools disagree on what a finding is CALLED: measured against
// one real SBOM from this fleet, grype reported 78 findings with zero
// CVE ids (GO-/ELSA-/GHSA-) while trivy reported 78 with 77 CVE ids.
// Mismatched ids never merge -- they pile a parallel namespace beside
// the existing findings that cannot dedupe, cannot be covered by a VEX
// statement written about a CVE, and cannot carry KEV/EPSS, which are
// keyed by CVE id.
func TestSBOMReevalScanner_MatchesTheToolThatBuiltTheBucket(t *testing.T) {
	trivySBOMDoc := &stubScanner{name: "trivy"}
	grypeSBOMDoc := &stubScanner{name: "grype"}

	for _, tc := range []struct {
		cveScanner string
		want       string
		why        string
	}{
		{"grype", "grype", "the bucket holds grype's advisory ids, so grype must re-evaluate it"},
		{"trivy", "trivy", "trivy-only deployment"},
		{"both", "trivy", "under both, trivy's ids dominate the bucket (35195 vs 4557 measured)"},
		{"", "trivy", "unset falls back to trivy, matching the chart default"},
	} {
		got := sbomReevalScanner(tc.cveScanner, trivySBOMDoc, grypeSBOMDoc)
		s, ok := got.(*stubScanner)
		if !ok || s.name != tc.want {
			t.Errorf("cveScanner=%q selected %v, want %q -- %s", tc.cveScanner, got, tc.want, tc.why)
		}
	}
}

// TestSBOMReevalScanner_NilWhenToolUnavailable covers
// DISABLE_SCAN_ISOLATION, where no isolated scanner is constructed at
// all. nil must propagate so the mode answers 501 rather than the
// handler falling back to a full scan.
func TestSBOMReevalScanner_NilWhenToolUnavailable(t *testing.T) {
	if got := sbomReevalScanner("both", nil, nil); got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got := sbomReevalScanner("grype", &stubScanner{name: "trivy"}, nil); got != nil {
		t.Errorf("cveScanner=grype with no grype scanner should be nil, got %v", got)
	}
}

// TestLogSweepProgress_HeartbeatCadence pins the heartbeat that tells a
// long run apart from a hung one.
//
// The first real fleet-wide run logged its population line and then
// nothing for fifteen minutes while working through 92 artifacts
// perfectly well; it was only confirmed healthy by querying Postgres.
// An unattended 05:00 CronJob whose output is indistinguishable from a
// hang cannot be debugged at 05:00.
func TestLogSweepProgress_HeartbeatCadence(t *testing.T) {
	capture := func(total int) []int {
		var buf bytes.Buffer
		old := log.Writer()
		log.SetOutput(&buf)
		defer log.SetOutput(old)
		for i := 1; i <= total; i++ {
			logSweepProgress(i, total, i, 0, 0)
		}
		var at []int
		for _, line := range strings.Split(buf.String(), "\n") {
			if !strings.Contains(line, "sweep-sbom: progress ") {
				continue
			}
			var done, tot int
			// "... progress 10/92 -- ..."
			frag := line[strings.Index(line, "progress ")+len("progress "):]
			if _, err := fmt.Sscanf(frag, "%d/%d", &done, &tot); err != nil {
				t.Fatalf("unparseable progress line %q", line)
			}
			at = append(at, done)
		}
		return at
	}

	// The FIRST artifact always logs, whatever the interval -- "it
	// started and something completed" is the most useful single line,
	// and waiting ten artifacts to say it defeats the point.
	got := capture(92)
	want := []int{1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 92}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("progress logged at %v, want %v", got, want)
	}

	// A run smaller than one interval must still log both ends rather
	// than going completely silent.
	if got := capture(3); !reflect.DeepEqual(got, []int{1, 3}) {
		t.Errorf("short run logged at %v, want [1 3]", got)
	}

	// A single-artifact run logs exactly once, not twice (first == last).
	if got := capture(1); !reflect.DeepEqual(got, []int{1}) {
		t.Errorf("single-artifact run logged at %v, want [1]", got)
	}
}

// TestUnmirroredArtifacts_BacksOffAfterAFailedAttempt covers the one
// artifact the "this pass converges" reasoning does not cover: one
// whose copy fails for a reason the UPSTREAM owns.
//
// gcr.io/google-samples/hello-app:1.0 returns a Content-Length mismatch
// from inside this cluster, so source_ref never gets settled, so the
// backfill selected it again every fifteen minutes -- forever, burning
// a scan slot each time. Observed doing exactly that on this project's
// own cluster before the backoff existed.
func TestUnmirroredArtifacts_BacksOffAfterAFailedAttempt(t *testing.T) {
	now := time.Now().UTC()
	recent := now.Add(-1 * time.Hour)
	old := now.Add(-12 * time.Hour)
	cutoff := now.Add(-mirrorRetryInterval)

	list := []artifact.Artifact{
		// Tried an hour ago and still unmirrored -- wait.
		{ID: "just-tried", LastScanAt: &recent},
		// Tried twelve hours ago -- worth another attempt, in case the
		// upstream was only transiently broken.
		{ID: "tried-long-ago", LastScanAt: &old},
		// Never scanned at all: a newly registered artifact must be
		// picked up immediately, never delayed by this backoff.
		{ID: "never-scanned"},
	}

	got := unmirroredArtifacts(list, cutoff)
	ids := make([]string, len(got))
	for i, a := range got {
		ids[i] = a.ID
	}
	if len(got) != 2 {
		t.Fatalf("selected %v, want [tried-long-ago never-scanned]", ids)
	}
	for _, want := range []string{"tried-long-ago", "never-scanned"} {
		found := false
		for _, id := range ids {
			if id == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q was not selected (got %v)", want, ids)
		}
	}
	for _, id := range ids {
		if id == "just-tried" {
			t.Errorf("just-tried was selected again after 1h -- the backoff is not holding (got %v)", ids)
		}
	}
}

// TestListWithRetry covers the wrapper that keeps one transient failure
// from throwing away a whole sweep run.
//
// Fataling on the initial listing costs the full sweep fifteen minutes
// and sweep-sbom a full DAY -- and transient is the common case. This
// was not hypothetical: enabling in-cluster TLS rolled monitor-api
// while a sweep was starting, and the run died with "server gave HTTP
// response to HTTPS client", a condition already resolved by the time
// anyone read the log.
func TestListWithRetry(t *testing.T) {
	// Shrunk so the retry paths do not cost 30 seconds of real
	// sleeping. Restored after, since this is package-level state
	// other tests could inherit.
	prev := sweepListRetryDelay
	sweepListRetryDelay = time.Millisecond
	defer func() { sweepListRetryDelay = prev }()

	t.Run("succeeds on a later attempt", func(t *testing.T) {
		calls := 0
		got, err := listWithRetry(context.Background(), "test", func() ([]artifact.Artifact, error) {
			calls++
			if calls < 3 {
				return nil, errors.New("server gave HTTP response to HTTPS client")
			}
			return []artifact.Artifact{{ID: "a"}}, nil
		})
		if err != nil {
			t.Fatalf("err = %v, want nil after a recovering failure", err)
		}
		if len(got) != 1 || calls != 3 {
			t.Errorf("got %d artifacts after %d calls, want 1 after 3", len(got), calls)
		}
	})

	t.Run("gives up and reports the last error", func(t *testing.T) {
		calls := 0
		_, err := listWithRetry(context.Background(), "test", func() ([]artifact.Artifact, error) {
			calls++
			return nil, errors.New("connection refused")
		})
		if err == nil {
			t.Fatal("want an error once the attempts are exhausted")
		}
		if calls != sweepListAttempts {
			t.Errorf("called %d times, want %d", calls, sweepListAttempts)
		}
	})

	t.Run("no retry on the first success", func(t *testing.T) {
		calls := 0
		if _, err := listWithRetry(context.Background(), "test", func() ([]artifact.Artifact, error) {
			calls++
			return nil, nil
		}); err != nil {
			t.Fatalf("err = %v", err)
		}
		if calls != 1 {
			t.Errorf("called %d times, want 1 -- a healthy listing must not be delayed", calls)
		}
	})

	// The run's own budget is the outer bound. Retrying past a
	// cancelled context would spend a sweep's whole window failing to
	// start, which is worse than failing fast.
	t.Run("stops when the run budget is gone", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		calls := 0
		if _, err := listWithRetry(ctx, "test", func() ([]artifact.Artifact, error) {
			calls++
			return nil, errors.New("nope")
		}); err == nil {
			t.Fatal("want the error surfaced")
		}
		if calls != 1 {
			t.Errorf("called %d times with a cancelled context, want 1", calls)
		}
	})
}

// TestSweepConcurrency is the check on the worker pool that replaced the
// sweep's fire-one-and-poll loop.
//
// WHY IT MEASURES OVERLAP RATHER THAN ELAPSED TIME. A faster wall clock
// would also be produced by the scans simply being quick, so it proves
// nothing about concurrency. This holds each scan open until the test
// releases it and records how many were in flight at once, which is the
// property the change is actually about: POST /scan answers 202 and the
// API enforces its own cap, so the sweep's job is to keep that queue
// full rather than to hold it at one.
//
// The default case matters as much as the concurrent one. SWEEP_CONCURRENCY
// defaults to 1, so an existing deployment must behave exactly as before
// until it opts in -- a regression there would change every cluster's
// scan load silently on upgrade.
func TestSweepConcurrency(t *testing.T) {
	for _, tc := range []struct {
		name        string
		concurrency string
		wantMax     int32
	}{
		{"default is sequential", "", 1},
		{"opted in runs scans in parallel", "4", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ids := []string{"a1", "b2", "c3", "d4", "e5", "f6", "g7", "h8"}

			var inFlight, maxInFlight int32
			release := make(chan struct{})

			mux := http.NewServeMux()
			mux.HandleFunc("GET /api/v1/artifacts", func(w http.ResponseWriter, r *http.Request) {
				var out []artifact.Artifact
				if r.URL.Query().Get("status") == string(artifact.StatusRegistered) {
					for _, id := range ids {
						out = append(out, artifact.Artifact{ID: id, Ref: "example.com/" + id + ":1", Type: artifact.TypeImage, Status: artifact.StatusRegistered})
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"total": len(out), "artifacts": out})
			})
			mux.HandleFunc("POST /api/v1/artifacts/{id}/scan", func(w http.ResponseWriter, r *http.Request) {
				n := atomic.AddInt32(&inFlight, 1)
				for {
					m := atomic.LoadInt32(&maxInFlight)
					if n <= m || atomic.CompareAndSwapInt32(&maxInFlight, m, n) {
						break
					}
				}
				// Hold the scan open. With a pool of 4 the fourth
				// arrival closes the gate and lets everyone go; with a
				// pool of 1 nobody else can arrive, so the timeout is
				// what releases it -- which is the sequential case
				// proving itself.
				if n >= int32(4) {
					select {
					case <-release:
					default:
						close(release)
					}
				}
				select {
				case <-release:
				case <-time.After(300 * time.Millisecond):
				}
				atomic.AddInt32(&inFlight, -1)
				w.WriteHeader(http.StatusAccepted)
				_ = json.NewEncoder(w).Encode(artifact.Artifact{ID: r.PathValue("id"), Status: artifact.StatusScanning})
			})
			mux.HandleFunc("GET /api/v1/artifacts/{id}", func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(artifact.Artifact{
					ID: r.PathValue("id"), Ref: "example.com/" + r.PathValue("id") + ":1",
					Status: artifact.StatusScanned, Digest: "sha256:" + r.PathValue("id"),
				})
			})

			srv := httptest.NewServer(mux)
			defer srv.Close()

			t.Setenv("SWEEP_API_BASE_URL", srv.URL)
			t.Setenv("SWEEP_API_KEY", "test-key")
			t.Setenv("SWEEP_BATCH_SIZE", strconv.Itoa(len(ids)))
			t.Setenv("SWEEP_MODE", "full")
			t.Setenv("SWEEP_RESCAN_STALE_AFTER_DAYS", "0")
			t.Setenv("SWEEP_MIRROR_BACKFILL", "false")
			if tc.concurrency != "" {
				t.Setenv("SWEEP_CONCURRENCY", tc.concurrency)
			}

			var buf bytes.Buffer
			old := log.Writer()
			log.SetOutput(&buf)
			defer log.SetOutput(old)
			runSweepRegistered()

			if got := atomic.LoadInt32(&maxInFlight); got != tc.wantMax {
				t.Errorf("peak scans in flight = %d, want %d\nlog:\n%s", got, tc.wantMax, buf.String())
			}
			// However they were scheduled, every artifact must still be
			// accounted for exactly once.
			if want := "done -- 8 scanned, 0 failed, 0 not attempted"; !strings.Contains(buf.String(), want) {
				t.Errorf("summary wrong.\nwant substring: %q\ngot:\n%s", want, buf.String())
			}
		})
	}
}
