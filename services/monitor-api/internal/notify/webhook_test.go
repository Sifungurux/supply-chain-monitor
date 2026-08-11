package notify_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/notify"
)

func testEvent() notify.ScanEvent {
	return notify.ScanEvent{
		ArtifactID:  "abc123",
		ArtifactRef: "alpine:3.19",
		Severity:    "CRITICAL",
		NewFindings: []artifact.Finding{
			{ID: "CVE-2024-1", Severity: "CRITICAL", Title: "openssl", Source: "trivy"},
		},
	}
}

func TestWebhook_PostsEventAsJSON(t *testing.T) {
	var got notify.ScanEvent
	var contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := notify.NewWebhook(srv.URL, "").Notify(context.Background(), testEvent()); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if contentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", contentType)
	}
	if got.ArtifactID != "abc123" || got.ArtifactRef != "alpine:3.19" || got.Severity != "CRITICAL" {
		t.Fatalf("delivered event = %+v", got)
	}
	if len(got.NewFindings) != 1 || got.NewFindings[0].ID != "CVE-2024-1" {
		t.Fatalf("delivered findings = %+v", got.NewFindings)
	}
}

// TestWebhook_SignsWithHMAC checks the signature a receiver would
// actually verify -- recomputed here from the raw body, so a change to
// the payload encoding or the header format fails this test rather than
// silently breaking every receiver's verification.
func TestWebhook_SignsWithHMAC(t *testing.T) {
	const secret = "s3cr3t"
	var header string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Get("X-Signature-256")
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := notify.NewWebhook(srv.URL, secret).Notify(context.Background(), testEvent()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(header), []byte(want)) {
		t.Fatalf("X-Signature-256 = %q, want %q", header, want)
	}
}

func TestWebhook_NoSignatureHeaderWithoutSecret(t *testing.T) {
	var present bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["X-Signature-256"]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_ = notify.NewWebhook(srv.URL, "").Notify(context.Background(), testEvent())
	if present {
		t.Fatal("X-Signature-256 sent even though no secret was configured")
	}
}

func TestWebhook_RetriesOnceOn5xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := notify.NewWebhook(srv.URL, "").Notify(context.Background(), testEvent()); err != nil {
		t.Fatalf("Notify: %v -- a 5xx followed by a 200 should succeed", err)
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("target was called %d time(s), want exactly 2 (one retry)", n)
	}
}

// TestWebhook_DoesNotRetryOn4xx -- a 4xx means the request itself is
// wrong (bad URL, rejected payload); repeating it just doubles the load
// on a receiver that already said no.
func TestWebhook_DoesNotRetryOn4xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	if err := notify.NewWebhook(srv.URL, "").Notify(context.Background(), testEvent()); err == nil {
		t.Fatal("expected an error for a 4xx response")
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("target was called %d time(s), want exactly 1 (no retry on 4xx)", n)
	}
}

// TestWebhook_GivesUpAfterTwoFailures pins the bound: a receiver that
// is down stays down, and this must not retry forever.
func TestWebhook_GivesUpAfterTwoFailures(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	if err := notify.NewWebhook(srv.URL, "").Notify(context.Background(), testEvent()); err == nil {
		t.Fatal("expected an error when every attempt 5xx'd")
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("target was called %d time(s), want exactly 2 attempts total", n)
	}
}

// TestWebhook_HonoursContextCancellation covers the timeout path
// without waiting out the real 10s client timeout: a hung receiver must
// return promptly rather than pinning a goroutine.
func TestWebhook_HonoursContextCancellation(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // never responds until the test releases it
	}))
	defer srv.Close()
	defer close(block)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := notify.NewWebhook(srv.URL, "").Notify(ctx, testEvent())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error when the receiver never responds")
	}
	// Two attempts, each bounded by the same context.
	if elapsed > 3*time.Second {
		t.Fatalf("took %v to give up -- a hung receiver must not pin a goroutine", elapsed)
	}
}

func TestSeverityThresholds(t *testing.T) {
	// The three spellings that actually appear in this project's
	// database: trivy UPPERCASE, grype TitleCase, clamav lowercase.
	for _, sev := range []string{"HIGH", "High", "high"} {
		if !notify.AtOrAbove(sev, "high") {
			t.Fatalf("%q should meet a 'high' threshold -- comparison must be case-insensitive", sev)
		}
	}
	if notify.AtOrAbove("MEDIUM", "high") {
		t.Fatal("medium must not meet a high threshold")
	}
	if !notify.AtOrAbove("Critical", "high") {
		t.Fatal("critical must meet a high threshold")
	}
	// An unrated finding must not trip a real threshold on its own.
	for _, sev := range []string{"UNKNOWN", "Negligible", "", "banana"} {
		if notify.AtOrAbove(sev, "high") {
			t.Fatalf("%q must not meet a 'high' threshold", sev)
		}
	}
	if got := notify.Worst([]artifact.Finding{
		{Severity: "LOW"}, {Severity: "Critical"}, {Severity: "HIGH"},
	}); got != "Critical" {
		t.Fatalf("Worst = %q, want %q (in the finding's own spelling)", got, "Critical")
	}
	if !notify.ValidSeverity("HIGH") || notify.ValidSeverity("urgent") {
		t.Fatal("ValidSeverity should accept known levels case-insensitively and reject unknown ones")
	}
}
