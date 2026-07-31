package scanner

import (
	"context"
	"net"
	"testing"
)

func TestClamAVScanner_Bucket(t *testing.T) {
	s := NewClamAVScanner("127.0.0.1:1")
	if got := s.Bucket(); got != "malware" {
		t.Fatalf("Bucket() = %q, want %q", got, "malware")
	}
}

func TestClamAVScanner_Scan_CleanFileReturnsNoFindings(t *testing.T) {
	addr := startFakeClamd(t, func(received []byte) string {
		return "stream: OK"
	})
	path := writeTempFile(t, []byte("nothing to see here"))
	s := NewClamAVScanner(addr)

	findings, err := s.Scan(context.Background(), path)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for a clean file", findings)
	}
}

func TestClamAVScanner_Scan_MalwareMatchReturnsOneFinding(t *testing.T) {
	addr := startFakeClamd(t, func(received []byte) string {
		return "stream: Eicar-Test-Signature FOUND"
	})
	path := writeTempFile(t, []byte("fake eicar payload"))
	s := NewClamAVScanner(addr)

	findings, err := s.Scan(context.Background(), path)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", findings)
	}
	f := findings[0]
	if f.ID != "clamav-signature-match" {
		t.Errorf("ID = %q, want %q", f.ID, "clamav-signature-match")
	}
	if f.Severity != "critical" {
		t.Errorf("Severity = %q, want %q", f.Severity, "critical")
	}
	if f.Source != "clamav" {
		t.Errorf("Source = %q, want %q", f.Source, "clamav")
	}
	if f.Title == "" {
		t.Errorf("Title is empty, want clamd's reported signature")
	}
}

// Scan's own error path (as opposed to scanFileWithClamd's, already
// covered directly in clamd_client_test.go) -- a scanner-level error
// (here, nothing listening on the target address) must propagate as
// Scan's own error, not get swallowed into an empty/clean result.
func TestClamAVScanner_Scan_PropagatesConnectionError(t *testing.T) {
	path := writeTempFile(t, []byte("x"))
	// Bind then immediately close -- a real address guaranteed to have
	// nothing listening, unlike a hardcoded port that might collide
	// with something else on the test machine.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s := NewClamAVScanner(addr)

	_, err = s.Scan(context.Background(), path)
	if err == nil {
		t.Fatal("expected an error when clamd is unreachable, got nil")
	}
}
