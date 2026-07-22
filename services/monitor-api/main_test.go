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
