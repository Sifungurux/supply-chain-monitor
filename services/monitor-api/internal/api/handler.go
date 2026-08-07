package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

type handler struct {
	store    artifact.Store
	tracker  *pipeline.Tracker
	scanners scanner.Registry
	// digestResolver and fetchPlainHTTP power best-effort duplicate-
	// registration detection (see resolveDigest below, and
	// createArtifact/bulkCreateArtifacts in artifacts.go) --
	// digestResolver is nil in tests that don't care about this (see
	// newTestRouter), which resolveDigest treats as "dedup disabled,"
	// not an error.
	digestResolver scanner.DigestResolver
	fetchPlainHTTP bool
	// scanTimeout bounds the shared budget scanArtifact gives every
	// scanner registered for one artifact type (see that method's own
	// comment on why it's deliberately not derived from r.Context()).
	// Must be configured >= the isolated scan-worker Jobs' own
	// ActiveDeadlineSeconds (main.go validates this at startup) --
	// otherwise this handler routinely gives up and reports "context
	// deadline exceeded" before Kubernetes' own ActiveDeadlineSeconds
	// would even have killed a genuinely stuck Job, which is exactly
	// what a heavier image (more OS packages for trivy to walk/query --
	// e.g. mysql/postgres-sized images) under concurrent scan load looks
	// like: still legitimately running, not actually stuck. Falls back
	// to 5 minutes if zero (e.g. in tests that don't care about this).
	scanTimeout time.Duration
	// requireDigest is monitorApi.requireDigest / REQUIRE_DIGEST -- see
	// NewRouter's own comment for the full behavior this gates.
	requireDigest bool
}

// digestResolveTimeout bounds how long a single registry manifest call
// can take during registration. Registration used to be instant and
// dependency-free (no network call at all -- see docs/architecture.md);
// this is what keeps a slow or hanging registry from turning that into
// a hung request instead of just skipping dedup for that one entry.
const digestResolveTimeout = 8 * time.Second

// resolveDigest is best-effort: it never returns an error. "" means "no
// digest available" -- digestResolver not configured, ref is a local
// path (not a registry reference), or resolution failed for any reason
// (unreachable/rate-limited registry, retagged or missing ref). A real
// failure is logged here and nowhere else -- callers should never treat
// an empty result as a reason to fail the registration it's part of
// (see Artifact.Digest's own comment).
func (h *handler) resolveDigest(ctx context.Context, ref string, t artifact.Type) string {
	if h.digestResolver == nil {
		return ""
	}
	// Image refs point at real, HTTPS-by-default registries (Docker
	// Hub, ghcr.io, ...). FETCH_PLAIN_HTTP only ever describes the one
	// local, unauthenticated scm-registry that file/sbom/sarif
	// registry refs point at (see RegistryFetcher's own comment) --
	// applying it to image refs too would mean trying plain HTTP
	// against a real registry and failing every single time.
	plainHTTP := t != artifact.TypeImage && h.fetchPlainHTTP

	rctx, cancel := context.WithTimeout(ctx, digestResolveTimeout)
	defer cancel()
	digest, err := h.digestResolver.Resolve(rctx, ref, plainHTTP)
	if err != nil {
		log.Printf("digest resolution failed for %q (continuing without dedup for this artifact): %v", ref, err)
		return ""
	}
	return digest
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (h *handler) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
