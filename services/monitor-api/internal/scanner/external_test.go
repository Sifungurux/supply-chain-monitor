package scanner

import (
	"context"
	"strings"
	"testing"
)

func TestExternalScanner_BuildArgs(t *testing.T) {
	e := NewExternalScanner(ExternalScannerConfig{
		Args: []string{"scan", "{{ref}}", "--tag={{ref}}", "--format", "json"},
	})

	got := e.buildArgs("alpine:3.19")
	want := []string{"scan", "alpine:3.19", "--tag=alpine:3.19", "--format", "json"}
	if len(got) != len(want) {
		t.Fatalf("buildArgs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("buildArgs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestExternalScanner_BuildArgs_NoPlaceholderLeavesArgUntouched(t *testing.T) {
	e := NewExternalScanner(ExternalScannerConfig{Args: []string{"--quiet"}})
	got := e.buildArgs("whatever")
	if len(got) != 1 || got[0] != "--quiet" {
		t.Fatalf("buildArgs = %v, want [--quiet] unchanged", got)
	}
}

// TestExternalScanner_Scan_HappyPath exercises the full contract: a
// command's stdout, interpreted as a JSON array of findings, becomes
// []artifact.Finding -- using `sh -c` as the "external scanner" so this
// runs without any real third-party binary installed.
func TestExternalScanner_Scan_HappyPath(t *testing.T) {
	e := NewExternalScanner(ExternalScannerConfig{
		Name:    "fake-cve-scanner",
		Command: "sh",
		Args: []string{"-c", `echo '[
			{"id":"CVE-2024-1","severity":"high","title":"a real vuln","source":"grype"},
			{"id":"CVE-2024-2","severity":"medium","title":"another vuln"}
		]'`},
		Category: "cve",
	})

	findings, err := e.Scan(context.Background(), "alpine:3.19")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %+v", findings)
	}

	f0 := findings[0]
	if f0.ID != "CVE-2024-1" || f0.Severity != "high" || f0.Title != "a real vuln" {
		t.Errorf("finding[0] = %+v, unexpected fields", f0)
	}
	if f0.Source != "grype" {
		t.Errorf("finding[0].Source = %q, want the wire-supplied %q to win over the configured default", f0.Source, "grype")
	}
	if f0.Category != "cve" {
		t.Errorf("finding[0].Category = %q, want the configured default %q since the wire JSON didn't set one", f0.Category, "cve")
	}

	f1 := findings[1]
	if f1.Source != "fake-cve-scanner" {
		t.Errorf("finding[1].Source = %q, want it to fall back to the configured Name %q since the wire JSON omitted source", f1.Source, "fake-cve-scanner")
	}
	if f1.Category != "cve" {
		t.Errorf("finding[1].Category = %q, want the configured default %q", f1.Category, "cve")
	}
}

func TestExternalScanner_Scan_NoFindingsIsNotAnError(t *testing.T) {
	e := NewExternalScanner(ExternalScannerConfig{Command: "sh", Args: []string{"-c", "echo '[]'"}})
	findings, err := e.Scan(context.Background(), "alpine:3.19")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
}

func TestExternalScanner_Scan_CommandFailureIncludesStderr(t *testing.T) {
	e := NewExternalScanner(ExternalScannerConfig{
		Name:    "broken-scanner",
		Command: "sh",
		Args:    []string{"-c", "echo 'auth failed: bad token' >&2; exit 1"},
	})

	_, err := e.Scan(context.Background(), "alpine:3.19")
	if err == nil {
		t.Fatal("expected an error for a nonzero exit code")
	}
	if !strings.Contains(err.Error(), "auth failed: bad token") {
		t.Errorf("error %q doesn't include the command's stderr", err.Error())
	}
	if !strings.Contains(err.Error(), "broken-scanner") {
		t.Errorf("error %q doesn't name the configured scanner", err.Error())
	}
}

func TestExternalScanner_Scan_MalformedOutputIsAnError(t *testing.T) {
	e := NewExternalScanner(ExternalScannerConfig{
		Name:    "chatty-scanner",
		Command: "sh",
		Args:    []string{"-c", "echo 'not json, some log line instead'"},
	})

	_, err := e.Scan(context.Background(), "alpine:3.19")
	if err == nil {
		t.Fatal("expected an error for output that isn't a JSON array of findings")
	}
	if !strings.Contains(err.Error(), "chatty-scanner") {
		t.Errorf("error %q doesn't name the configured scanner", err.Error())
	}
}

// TestExternalScanner_Scan_RefSubstitution confirms the actual ref
// passed to Scan reaches the exec'd command, not just a literal
// "{{ref}}" placeholder string -- using sh's own positional-parameter
// substitution ($1) to surface whatever buildArgs produced back out
// through the command's own output.
func TestExternalScanner_Scan_RefSubstitution(t *testing.T) {
	e := NewExternalScanner(ExternalScannerConfig{
		Command: "sh",
		Args:    []string{"-c", `echo "[{\"id\":\"$1\",\"severity\":\"high\",\"title\":\"t\"}]"`, "sh", "{{ref}}"},
	})

	findings, err := e.Scan(context.Background(), "ghcr.io/example/app:1.0")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "ghcr.io/example/app:1.0" {
		t.Fatalf("expected the real ref substituted into the command's args, got %+v", findings)
	}
}

func TestExternalScanner_Scan_TimeoutKillsALongRunningCommand(t *testing.T) {
	e := NewExternalScanner(ExternalScannerConfig{
		Name:           "slow-scanner",
		Command:        "sh",
		Args:           []string{"-c", "sleep 5 && echo '[]'"},
		TimeoutSeconds: 1,
	})

	_, err := e.Scan(context.Background(), "alpine:3.19")
	if err == nil {
		t.Fatal("expected an error from a command that outlives its configured timeout")
	}
}

func TestExternalScanner_Timeout_DefaultsWhenUnset(t *testing.T) {
	e := NewExternalScanner(ExternalScannerConfig{})
	if got := e.timeout(); got != defaultExternalScannerTimeout {
		t.Errorf("timeout() = %v, want the default %v", got, defaultExternalScannerTimeout)
	}
}

func TestExternalScanner_Timeout_UsesConfiguredSeconds(t *testing.T) {
	e := NewExternalScanner(ExternalScannerConfig{TimeoutSeconds: 42})
	if got := e.timeout(); got.Seconds() != 42 {
		t.Errorf("timeout() = %v, want 42s", got)
	}
}
