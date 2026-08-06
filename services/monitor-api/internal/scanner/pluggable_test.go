package scanner

import (
	"context"
	"strings"
	"testing"
)

func TestLimitedBuffer_Write(t *testing.T) {
	t.Run("writes under the limit accumulate normally", func(t *testing.T) {
		b := &limitedBuffer{limit: 10}
		if _, err := b.Write([]byte("hello")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if _, err := b.Write([]byte("world")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if b.String() != "helloworld" {
			t.Fatalf("String() = %q, want %q", b.String(), "helloworld")
		}
	})

	t.Run("a write that would exceed the limit is rejected", func(t *testing.T) {
		b := &limitedBuffer{limit: 5}
		if _, err := b.Write([]byte("hello")); err != nil {
			t.Fatalf("Write up to the limit exactly: %v", err)
		}
		if _, err := b.Write([]byte("x")); err == nil {
			t.Fatal("expected an error writing past the limit")
		}
		// The rejected write must not have partially landed.
		if b.String() != "hello" {
			t.Fatalf("String() = %q, want %q (rejected write should not partially append)", b.String(), "hello")
		}
	})
}

// TestPluggableScanner_Scan_OutputExceedingLimitIsAnError proves the
// 10MiB cap is actually wired into Scan, not just the limitedBuffer
// type in isolation -- `yes | head -c 11000000` cheaply produces just
// over the limit without the test itself needing to build/hold an
// 11MB string.
func TestPluggableScanner_Scan_OutputExceedingLimitIsAnError(t *testing.T) {
	e := NewPluggableScanner(PluggableScannerConfig{
		Name:    "firehose-scanner",
		Command: "sh",
		Args:    []string{"-c", "yes | head -c 11000000"},
	})

	_, err := e.Scan(context.Background(), "alpine:3.19")
	if err == nil {
		t.Fatal("expected an error for output exceeding the configured limit")
	}
}

func TestPluggableScanner_BuildArgs(t *testing.T) {
	e := NewPluggableScanner(PluggableScannerConfig{
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

func TestPluggableScanner_BuildArgs_NoPlaceholderLeavesArgUntouched(t *testing.T) {
	e := NewPluggableScanner(PluggableScannerConfig{Args: []string{"--quiet"}})
	got := e.buildArgs("whatever")
	if len(got) != 1 || got[0] != "--quiet" {
		t.Fatalf("buildArgs = %v, want [--quiet] unchanged", got)
	}
}

// TestPluggableScanner_Scan_HappyPath exercises the full contract: a
// command's stdout, interpreted as a JSON array of findings, becomes
// []artifact.Finding -- using `sh -c` as the "pluggable scanner" so this
// runs without any real third-party binary installed.
func TestPluggableScanner_Scan_HappyPath(t *testing.T) {
	e := NewPluggableScanner(PluggableScannerConfig{
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

func TestPluggableScanner_Scan_NoFindingsIsNotAnError(t *testing.T) {
	e := NewPluggableScanner(PluggableScannerConfig{Command: "sh", Args: []string{"-c", "echo '[]'"}})
	findings, err := e.Scan(context.Background(), "alpine:3.19")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
}

func TestPluggableScanner_Scan_CommandFailureIncludesStderr(t *testing.T) {
	e := NewPluggableScanner(PluggableScannerConfig{
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

func TestPluggableScanner_Scan_MalformedOutputIsAnError(t *testing.T) {
	e := NewPluggableScanner(PluggableScannerConfig{
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

// TestPluggableScanner_Scan_RefSubstitution confirms the actual ref
// passed to Scan reaches the exec'd command, not just a literal
// "{{ref}}" placeholder string -- using sh's own positional-parameter
// substitution ($1) to surface whatever buildArgs produced back out
// through the command's own output.
func TestPluggableScanner_Scan_RefSubstitution(t *testing.T) {
	e := NewPluggableScanner(PluggableScannerConfig{
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

func TestPluggableScanner_Scan_TimeoutKillsALongRunningCommand(t *testing.T) {
	e := NewPluggableScanner(PluggableScannerConfig{
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

func TestPluggableScanner_Timeout_DefaultsWhenUnset(t *testing.T) {
	e := NewPluggableScanner(PluggableScannerConfig{})
	if got := e.timeout(); got != defaultPluggableScannerTimeout {
		t.Errorf("timeout() = %v, want the default %v", got, defaultPluggableScannerTimeout)
	}
}

func TestPluggableScanner_Timeout_UsesConfiguredSeconds(t *testing.T) {
	e := NewPluggableScanner(PluggableScannerConfig{TimeoutSeconds: 42})
	if got := e.timeout(); got.Seconds() != 42 {
		t.Errorf("timeout() = %v, want 42s", got)
	}
}
