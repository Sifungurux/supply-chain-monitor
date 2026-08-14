package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// webhookTimeout bounds one delivery attempt. A notification is not
// worth holding a goroutine open for: the receiver is either there or
// it isn't.
const webhookTimeout = 10 * time.Second

// WebhookNotifier POSTs the event as JSON to a URL, optionally signed.
type WebhookNotifier struct {
	url    string
	secret string
	client *http.Client
}

// NewWebhook builds a notifier for url. secret may be empty (no
// signing). The client's timeout covers one attempt, so a retry gets its
// own full budget.
func NewWebhook(url, secret string) *WebhookNotifier {
	return &WebhookNotifier{
		url:    url,
		secret: secret,
		client: &http.Client{Timeout: webhookTimeout},
	}
}

// Notify POSTs event as JSON. Retries once on a 5xx (or a transport
// error), on the theory that those are the failures worth one more
// try -- a 4xx means the request itself is wrong and repeating it
// changes nothing.
//
// Errors are logged here as well as returned, because the caller
// deliberately discards them (see the Notifier interface): without this
// log, a webhook that has been failing for a week would leave no trace
// anywhere.
func (w *WebhookNotifier) Notify(ctx context.Context, event ScanEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		slog.Error("notify: could not encode event", "artifact_id", event.ArtifactID, "err", err)
		return fmt.Errorf("encode event: %w", err)
	}

	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		retryable, err := w.post(ctx, body)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retryable || attempt == 2 {
			break
		}
	}
	slog.Error("notify: webhook delivery failed", "artifact_id", event.ArtifactID, "ref", event.ArtifactRef, "err", lastErr)
	return lastErr
}

// post makes one attempt, reporting whether the failure is worth
// retrying.
func (w *WebhookNotifier) post(ctx context.Context, body []byte) (retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if w.secret != "" {
		req.Header.Set("X-Signature-256", sign(w.secret, body))
	}

	resp, err := w.client.Do(req)
	if err != nil {
		// Transport-level: unreachable, DNS, timeout. Worth one retry.
		return true, fmt.Errorf("post: %w", err)
	}
	// Drain before closing so the connection can be reused rather than
	// abandoned mid-body on every notification.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	if resp.StatusCode >= 500 {
		return true, fmt.Errorf("server returned %d", resp.StatusCode)
	}
	if resp.StatusCode >= 300 {
		return false, fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return false, nil
}

// sign returns the hex-encoded HMAC-SHA256 of body, prefixed "sha256="
// -- the same shape GitHub's X-Hub-Signature-256 uses, so a receiver
// written against that convention verifies this without translation.
//
// The prefix is part of the signed-value format, not of the signature:
// verifiers must compare with hmac.Equal (constant time) rather than
// ==, and this is written to make that easy to get right.
func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
