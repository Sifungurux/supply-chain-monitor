package notify_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/notify"
)

// A component event carries no findings and no severity. Rendered by
// the findings message it would read "0 new  finding(s)" -- true of
// nothing, and the sort of message that gets a webhook switched off.
func TestSlack_ComponentEventRendersComponents(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	err := notify.NewSlack(srv.URL).Notify(context.Background(), notify.ScanEvent{
		ArtifactID:  "a1",
		ArtifactRef: "ghcr.io/acme/app:2",
		NewComponents: []artifact.Component{
			{PURL: "pkg:npm/left-pad@1.3.0", Name: "left-pad", Version: "1.3.0", Licenses: "WTFPL"},
		},
	})
	if err != nil {
		t.Fatalf("notify: %v", err)
	}

	var msg map[string]any
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatalf("decode slack payload: %v (body=%s)", err, body)
	}
	text, _ := msg["text"].(string)
	if !strings.Contains(text, "1 new component(s)") || !strings.Contains(text, "ghcr.io/acme/app:2") {
		t.Fatalf("summary = %q, want the component count and the artifact ref", text)
	}
	if strings.Contains(text, "finding") {
		t.Fatalf("summary = %q, want no mention of findings on a component event", text)
	}
	if !strings.Contains(string(body), "pkg:npm/left-pad@1.3.0") {
		t.Fatalf("payload does not name the new component: %s", body)
	}
}
