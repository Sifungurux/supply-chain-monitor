package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// writeSARIFFile is a small test helper: writes content to a temp file
// and returns its path, the same shape SARIFScanner.Scan expects for
// ref (a filesystem path).
func writeSARIFFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "results.sarif")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write sarif fixture: %v", err)
	}
	return path
}

// Unlike TrivyScanner/SBOMScanner/UnpackerScanner, SARIFScanner never
// shells out to an external binary -- it's pure file I/O + JSON
// parsing, so unlike most of this package's Scan() methods, this one
// can actually run end to end in any Go environment.
func TestSARIFScanner_Scan(t *testing.T) {
	s := NewSARIFScanner()

	t.Run("results with matching rule descriptions", func(t *testing.T) {
		path := writeSARIFFile(t, `{
			"runs": [
				{
					"tool": {"driver": {"rules": [
						{"id": "no-hardcoded-secret", "shortDescription": {"text": "Hardcoded secret detected"}}
					]}},
					"results": [
						{"ruleId": "no-hardcoded-secret", "level": "error", "message": {"text": "found in config.go:42"}}
					]
				}
			]
		}`)

		findings, err := s.Scan(context.Background(), path)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %+v", findings)
		}
		f := findings[0]
		if f.ID != "no-hardcoded-secret" {
			t.Errorf("ID = %q, want %q", f.ID, "no-hardcoded-secret")
		}
		if f.Title != "Hardcoded secret detected" {
			t.Errorf("Title = %q, want the rule's shortDescription, not the raw message", f.Title)
		}
		if f.Severity != "high" {
			t.Errorf("Severity = %q, want %q (level=error)", f.Severity, "high")
		}
		if f.Source != "sarif" {
			t.Errorf("Source = %q, want %q", f.Source, "sarif")
		}
	})

	t.Run("result with no matching rule falls back to the message text", func(t *testing.T) {
		path := writeSARIFFile(t, `{
			"runs": [
				{
					"tool": {"driver": {"rules": []}},
					"results": [
						{"ruleId": "some-unknown-rule", "level": "warning", "message": {"text": "raw message text"}}
					]
				}
			]
		}`)

		findings, err := s.Scan(context.Background(), path)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if len(findings) != 1 || findings[0].Title != "raw message text" {
			t.Fatalf("expected the message text as a fallback title, got %+v", findings)
		}
		if findings[0].Severity != "medium" {
			t.Errorf("Severity = %q, want %q (level=warning)", findings[0].Severity, "medium")
		}
	})

	t.Run("result with no ruleId gets a placeholder id, not an empty one", func(t *testing.T) {
		path := writeSARIFFile(t, `{
			"runs": [{"tool": {"driver": {"rules": []}}, "results": [{"level": "note", "message": {"text": "x"}}]}]
		}`)
		findings, err := s.Scan(context.Background(), path)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if len(findings) != 1 || findings[0].ID == "" {
			t.Fatalf("expected a non-empty placeholder id, got %+v", findings)
		}
		if findings[0].Severity != "low" {
			t.Errorf("Severity = %q, want %q (level=note)", findings[0].Severity, "low")
		}
	})

	t.Run("prefers a rule's security-severity score over its level", func(t *testing.T) {
		path := writeSARIFFile(t, `{
			"runs": [
				{
					"tool": {"driver": {"rules": [
						{"id": "sql-injection", "shortDescription": {"text": "SQL injection"}, "properties": {"security-severity": "9.8"}}
					]}},
					"results": [
						{"ruleId": "sql-injection", "level": "warning", "message": {"text": "found in db.go:10"}}
					]
				}
			]
		}`)

		findings, err := s.Scan(context.Background(), path)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		// level=warning alone would map to "medium" -- the numeric
		// score (9.8) should win and produce "critical" instead.
		if len(findings) != 1 || findings[0].Severity != "critical" {
			t.Fatalf("Severity = %+v, want critical (security-severity should override level)", findings)
		}
	})

	t.Run("falls back to level when security-severity is absent or unparseable", func(t *testing.T) {
		path := writeSARIFFile(t, `{
			"runs": [
				{
					"tool": {"driver": {"rules": [
						{"id": "bad-score", "properties": {"security-severity": "not-a-number"}}
					]}},
					"results": [
						{"ruleId": "bad-score", "level": "error", "message": {"text": "x"}}
					]
				}
			]
		}`)

		findings, err := s.Scan(context.Background(), path)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if len(findings) != 1 || findings[0].Severity != "high" {
			t.Fatalf("Severity = %+v, want high (level=error fallback since security-severity is unparseable)", findings)
		}
	})

	t.Run("no results is not an error", func(t *testing.T) {
		path := writeSARIFFile(t, `{"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]}`)
		findings, err := s.Scan(context.Background(), path)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected no findings, got %+v", findings)
		}
	})

	t.Run("missing file is an error", func(t *testing.T) {
		if _, err := s.Scan(context.Background(), "/does/not/exist.sarif"); err == nil {
			t.Fatal("expected an error for a missing file")
		}
	})

	t.Run("malformed json is an error", func(t *testing.T) {
		path := writeSARIFFile(t, `not json`)
		if _, err := s.Scan(context.Background(), path); err == nil {
			t.Fatal("expected an error for malformed json")
		}
	})
}

func TestSarifLevelToSeverity(t *testing.T) {
	cases := map[string]string{
		"error":      "high",
		"warning":    "medium",
		"":           "medium", // SARIF spec: absent level defaults to "warning"
		"note":       "low",
		"none":       "unknown",
		"garbage-in": "unknown",
	}
	for level, want := range cases {
		if got := sarifLevelToSeverity(level); got != want {
			t.Errorf("sarifLevelToSeverity(%q) = %q, want %q", level, got, want)
		}
	}
}

func TestSeverityFromSecuritySeverity(t *testing.T) {
	cases := []struct {
		raw      string
		wantSev  string
		wantOK   bool
	}{
		{"9.8", "critical", true},
		{"9.0", "critical", true},
		{"8.9", "high", true},
		{"7.0", "high", true},
		{"6.9", "medium", true},
		{"4.0", "medium", true},
		{"3.9", "low", true},
		{"0", "low", true},
		{"", "", false},
		{"not-a-number", "", false},
	}
	for _, tc := range cases {
		sev, ok := severityFromSecuritySeverity(tc.raw)
		if ok != tc.wantOK || sev != tc.wantSev {
			t.Errorf("severityFromSecuritySeverity(%q) = (%q, %v), want (%q, %v)", tc.raw, sev, ok, tc.wantSev, tc.wantOK)
		}
	}
}
