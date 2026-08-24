package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Per-Job upload credentials for scan workers (report S3).
//
// A scan worker exists to process UNTRUSTED content -- that is why it
// runs as a disposable pod with a zero-RBAC ServiceAccount, no service
// account token, a read-only rootfs and dropped capabilities. It was
// then handed SCM_API_KEY, the master credential, purely so it could
// post an SBOM back. A malicious image that popped trivy walked away
// with full register/scan/delete authority, and all that isolation
// bought nothing.
//
// A scan token is the same credential idea narrowed to what the worker
// actually needs: ONE artifact, ONE upload per document kind, expiring
// with the Job.

// scanTokenBytes is the entropy behind a token. 32 bytes, matching the
// API key's own floor -- these are shorter-lived but they are still
// bearer credentials on a network path.
const scanTokenBytes = 32

// NewScanToken returns a fresh token and the hash to store for it. The
// token itself is never persisted: a database dump should not yield
// usable upload credentials.
func NewScanToken() (token, hash string, err error) {
	buf := make([]byte, scanTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(buf)
	return token, HashScanToken(token), nil
}

// HashScanToken is the one-way function both sides agree on.
//
// SHA-256 rather than bcrypt/argon2, deliberately: this is a 32-byte
// random value, not a human-chosen password, so there is no dictionary
// to slow down -- and it is verified on a request path that a scan
// worker hits twice per scan. Password hashing here would buy nothing
// and cost latency.
func HashScanToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// documentUploadTarget parses POST /api/v1/artifacts/{id}/documents/{kind},
// returning the artifact id and kind, or ok=false for anything else.
//
// Parsed by hand because withAuth runs BEFORE the mux, so r.PathValue is
// not populated yet -- and it has to run before, or an unauthenticated
// request would reach the handler.
//
// Deliberately exact: a scan token is accepted on this ONE route and
// nothing else, so the match must not be a prefix test that a crafted
// path could widen.
func documentUploadTarget(method, path string) (artifactID, kind string, ok bool) {
	return documentTarget("POST", method, path)
}

// documentDownloadTarget is the read counterpart: GET
// /api/v1/artifacts/{id}/documents/{kind}.
//
// Exists for ONE caller -- the sbom re-evaluation scan worker, which
// re-runs grype against an image's already-stored SBOM and therefore
// has to read that document back out (see runScanWorker's "sbom-doc"
// mode). The document lives in Postgres, not in any registry, so the
// fetch-it-yourself shape every other isolated sbom scan uses has
// nothing to point at.
//
// A read is NOT the same authority as a write, so it consumes its own
// pseudo-kind (documentReadKind below) rather than the plain one: a
// token that downloaded the SBOM has not spent its right to upload one,
// and a token that uploaded one has not gained the right to read
// anything. Each stays single-use in its own direction.
func documentDownloadTarget(method, path string) (artifactID, kind string, ok bool) {
	return documentTarget("GET", method, path)
}

// documentReadKind namespaces the used_kinds entry a download burns, so
// it can never collide with the upload of the same kind. Stored as an
// ordinary string in the same text[] column -- no schema change.
func documentReadKind(kind string) string { return kind + ":read" }

func documentTarget(want, method, path string) (artifactID, kind string, ok bool) {
	if method != want {
		return "", "", false
	}
	rest, found := strings.CutPrefix(path, "/api/v1/artifacts/")
	if !found {
		return "", "", false
	}
	id, tail, found := strings.Cut(rest, "/")
	if !found || id == "" {
		return "", "", false
	}
	k, found := strings.CutPrefix(tail, "documents/")
	if !found || k == "" || strings.Contains(k, "/") {
		return "", "", false
	}
	return id, k, true
}
