package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

func TestFindByFindingID(t *testing.T) {
	trivyLike := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2024-9999", Severity: "high", Source: "trivy"}}}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivyLike}})

	affected := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	mustCreate(t, store, "debian:12", artifact.TypeImage) // never scanned -- must not show up below

	rec, _ := scanAndWait(t, h, store, affected.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("scan status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, http.MethodGet, "/api/v1/findings/CVE-2024-9999/artifacts", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var list []artifact.Artifact
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 1 || list[0].ID != affected.ID {
		t.Fatalf("findings-by-id list = %+v, want just %q", list, affected.ID)
	}

	rec = doJSON(t, h, http.MethodGet, "/api/v1/findings/CVE-does-not-exist/artifacts", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (empty list, not an error)", rec.Code)
	}
	var empty []artifact.Artifact
	if err := json.Unmarshal(rec.Body.Bytes(), &empty); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected an empty list for an unmatched finding id, got %+v", empty)
	}
}

func TestSubmitFindings(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "docker.io/cloudelements/eicar:latest", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/findings", map[string]any{
		"bucket": "malware",
		"findings": []map[string]string{
			{"id": "eicar-test-signature", "severity": "critical", "title": "EICAR test file detected", "source": "external-clamav"},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if len(got.MalwareFindings) != 1 || got.MalwareFindings[0].ID != "eicar-test-signature" {
		t.Fatalf("malware_findings = %+v", got.MalwareFindings)
	}
	if got.Status != artifact.StatusScanned {
		t.Fatalf("status = %q, want %q (a registered artifact that just received findings has meaningfully been scanned)", got.Status, artifact.StatusScanned)
	}
	if len(got.CVEFindings) != 0 || len(got.OtherFindings) != 0 {
		t.Fatalf("expected the other two buckets to stay untouched, got cve=%+v other=%+v", got.CVEFindings, got.OtherFindings)
	}
}

// TestSubmitFindings_LeavesOtherBucketsAlone is the specific behavior
// that makes this safe to use alongside monitor-api's own scanArtifact:
// submitting external malware results must never disturb CVE findings
// a real Trivy scan already produced (unlike scanArtifact, which
// touches all three buckets on every call).

func TestSubmitFindings_LeavesOtherBucketsAlone(t *testing.T) {
	trivyLike := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2024-1", Severity: "high", Source: "trivy"}}}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivyLike}})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec, _ := scanAndWait(t, h, store, created.ID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("scan status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/findings", map[string]any{
		"bucket": "malware",
		"findings": []map[string]string{
			{"id": "eicar-test-signature", "severity": "critical", "source": "external-clamav"},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("findings status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if len(got.MalwareFindings) != 1 {
		t.Fatalf("malware_findings = %+v", got.MalwareFindings)
	}
	if len(got.CVEFindings) != 1 || got.CVEFindings[0].ID != "CVE-2024-1" {
		t.Fatalf("expected the earlier trivy-sourced CVE finding to survive, got %+v", got.CVEFindings)
	}
	if got.Status != artifact.StatusScanned {
		t.Fatalf("status = %q, want %q (already scanned; submitFindings shouldn't change it)", got.Status, artifact.StatusScanned)
	}
}

// TestSubmitFindings_SecondCallMarksMissingFindingAsFixed proves
// /findings gets the same fixed-not-deleted behavior as /scan: an
// external pipeline reporting a clean second result (no more malware
// found) must show the earlier finding as fixed, not just erase it.

func TestSubmitFindings_SecondCallMarksMissingFindingAsFixed(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "docker.io/cloudelements/eicar:latest", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/findings", map[string]any{
		"bucket": "malware",
		"findings": []map[string]string{
			{"id": "eicar-test-signature", "severity": "critical", "source": "external-clamav"},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("first submission status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	// Re-scanned externally, clean this time.
	rec = doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/findings", map[string]any{
		"bucket":   "malware",
		"findings": []map[string]string{},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("second submission status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if len(got.MalwareFindings) != 1 {
		t.Fatalf("expected the earlier malware finding to still be present (fixed, not deleted), got %+v", got.MalwareFindings)
	}
	f := got.MalwareFindings[0]
	if f.Status != artifact.FindingStatusFixed {
		t.Fatalf("status = %q, want %q", f.Status, artifact.FindingStatusFixed)
	}
	if f.ResolvedAt == nil {
		t.Fatal("resolved_at is nil, want it set once the second submission stopped reporting it")
	}
}

// TestSubmitFindings_MisconfigurationAndSecretBuckets covers external
// submission into the two buckets added alongside the SARIF category
// classifier -- an external Checkov or Gitleaks run submitting its own
// results the same way an external malware scanner already could.

func TestSubmitFindings_MisconfigurationAndSecretBuckets(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/findings", map[string]any{
		"bucket": "misconfiguration",
		"findings": []map[string]string{
			{"id": "AVD-AWS-0001", "severity": "medium", "title": "S3 bucket is public", "source": "checkov"},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("misconfiguration submission status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)
	if len(got.MisconfigFindings) != 1 || got.MisconfigFindings[0].ID != "AVD-AWS-0001" {
		t.Fatalf("misconfiguration_findings = %+v", got.MisconfigFindings)
	}

	rec = doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/findings", map[string]any{
		"bucket": "secret",
		"findings": []map[string]string{
			{"id": "aws-access-key", "severity": "critical", "title": "AWS access key committed", "source": "gitleaks"},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("secret submission status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got = decodeArtifact(t, rec)
	if len(got.SecretFindings) != 1 || got.SecretFindings[0].ID != "aws-access-key" {
		t.Fatalf("secret_findings = %+v", got.SecretFindings)
	}
	// Neither submission should have disturbed the other, or the
	// unrelated cve/malware/other buckets.
	if len(got.MisconfigFindings) != 1 {
		t.Fatalf("expected the earlier misconfiguration finding to survive, got %+v", got.MisconfigFindings)
	}
	if len(got.CVEFindings) != 0 || len(got.MalwareFindings) != 0 || len(got.OtherFindings) != 0 {
		t.Fatalf("expected the unrelated buckets to stay untouched, got cve=%+v malware=%+v other=%+v", got.CVEFindings, got.MalwareFindings, got.OtherFindings)
	}
}

func TestSubmitFindings_InvalidBucket(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/findings", map[string]any{
		"bucket":   "not-a-real-bucket",
		"findings": []map[string]string{},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown bucket", rec.Code)
	}
}

func TestSubmitFindings_UnknownArtifact(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/does-not-exist/findings", map[string]any{
		"bucket":   "malware",
		"findings": []map[string]string{},
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

type findingSearchResult struct {
	Total    int                     `json:"total"`
	Findings []artifact.FindingMatch `json:"findings"`
}

func searchFindings(t *testing.T, h http.Handler, q string) findingSearchResult {
	t.Helper()
	rec := doJSON(t, h, http.MethodGet, "/api/v1/findings?q="+url.QueryEscape(q), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("q=%q status = %d, want 200, body=%s", q, rec.Code, rec.Body.String())
	}
	var out findingSearchResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode finding search: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

// The two-stage flow, mirroring the component one: search what you
// remember, pick the id that exists, get the artifacts.
func TestSearchFindings_DiscoverThenNarrow(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "app:1.0", artifact.TypeImage)
	b := mustCreate(t, store, "app:1.1", artifact.TypeImage)

	for _, id := range []string{a.ID, b.ID} {
		rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+id+"/findings", map[string]any{
			"bucket": "cve",
			"findings": []map[string]string{
				{"id": "CVE-2021-44228", "severity": "critical", "title": "log4j RCE via JNDI", "source": "trivy"},
				{"id": "CVE-2024-0001", "severity": "low", "title": "something else", "source": "trivy"},
			},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("submit status = %d, body=%s", rec.Code, rec.Body.String())
		}
	}

	// Stage 1: by title, which is what someone remembers.
	found := searchFindings(t, h, "log4j")
	if found.Total != 1 || len(found.Findings) != 1 {
		t.Fatalf("findings = %+v (total %d), want the one id", found.Findings, found.Total)
	}
	m := found.Findings[0]
	if m.ID != "CVE-2021-44228" || m.Artifacts != 2 || m.Severity != "critical" {
		t.Fatalf("match = %+v, want the CVE in 2 artifacts at critical", m)
	}

	// Stage 2: the id goes to the existing exact endpoint, and the count
	// it promised is the number of artifacts that come back.
	rec := doJSON(t, h, http.MethodGet, "/api/v1/findings/"+m.ID+"/artifacts", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var artifacts []artifact.Artifact
	if err := json.Unmarshal(rec.Body.Bytes(), &artifacts); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(artifacts) != m.Artifacts {
		t.Fatalf("search promised %d artifacts, the exact lookup returned %d", m.Artifacts, len(artifacts))
	}
}

// A VEX-suppressed finding drops out of both halves together. If it
// left only one of them, the picker's count and its click-through would
// disagree -- which is worse than either being wrong alone, because
// nothing tells you which to believe.
func TestSearchFindings_SuppressedDropsOutOfBothHalves(t *testing.T) {
	h, store := newTestRouter(scanner.Registry{})
	a := mustCreate(t, store, "app:1.0", artifact.TypeImage)

	if rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/findings", map[string]any{
		"bucket":   "cve",
		"findings": []map[string]string{{"id": "CVE-2024-1", "severity": "critical", "title": "openssl overflow", "source": "trivy"}},
	}); rec.Code != http.StatusOK {
		t.Fatalf("submit status = %d", rec.Code)
	}
	if got := searchFindings(t, h, "openssl"); got.Total != 1 || got.Findings[0].Artifacts != 1 {
		t.Fatalf("before suppression = %+v, want 1 artifact", got)
	}

	if rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/vex", "application/json", []byte(notAffectedVEX)); rec.Code != http.StatusOK {
		t.Fatalf("vex status = %d, body=%s", rec.Code, rec.Body.String())
	}

	if got := searchFindings(t, h, "openssl"); got.Total != 0 {
		t.Fatalf("after suppression = %+v, want it gone from search -- it is not something we are still affected by", got)
	}
	rec := doJSON(t, h, http.MethodGet, "/api/v1/findings/CVE-2024-1/artifacts", nil)
	var artifacts []artifact.Artifact
	if err := json.Unmarshal(rec.Body.Bytes(), &artifacts); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(artifacts) != 0 {
		t.Fatalf("exact lookup returned %+v, want nothing -- both halves must agree", artifacts)
	}
}

func TestSearchFindings_RequiresAQuery(t *testing.T) {
	h, _ := newTestRouter(scanner.Registry{})

	for _, path := range []string{"/api/v1/findings", "/api/v1/findings?q="} {
		if rec := doJSON(t, h, http.MethodGet, path, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("GET %s = %d, want 400", path, rec.Code)
		}
	}
	if got := searchFindings(t, h, "nothing-like-this"); got.Total != 0 || len(got.Findings) != 0 {
		t.Fatalf("no-match search = %+v, want an empty list and total 0", got)
	}
}

// acceptancePath builds the endpoint under test for one artifact and
// finding.
func acceptancePath(artifactID, findingID string) string {
	return "/api/v1/artifacts/" + artifactID + "/findings/" + findingID + "/acceptance"
}

// findingByID pulls one finding out of the CVE bucket of a response.
func findingByID(t *testing.T, a artifact.Artifact, id string) artifact.Finding {
	t.Helper()
	for _, f := range a.CVEFindings {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("no finding %q in %+v", id, a.CVEFindings)
	return artifact.Finding{}
}

// acceptedArtifact registers an artifact with one open critical CVE
// already on record, which is the state every acceptance test starts
// from.
func acceptedArtifact(t *testing.T, store *artifact.MemStore) *artifact.Artifact {
	t.Helper()
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	if _, err := store.Update(created.ID, func(a *artifact.Artifact) {
		a.CVEFindings = []artifact.Finding{{
			ID: "CVE-2024-1", Severity: "critical", Title: "very bad", Source: "trivy",
			Status: artifact.FindingStatusOpen, FirstSeenAt: time.Now().UTC().Add(-24 * time.Hour),
		}}
	}); err != nil {
		t.Fatalf("seed findings: %v", err)
	}
	return created
}

// The end-to-end shape: accept a real finding, and it drops out of the
// counts and the policy gate while staying visible on the artifact --
// then comes back when the acceptance is revoked.
func TestAcceptFinding(t *testing.T) {
	h, store := newTestRouter(nil)
	created := acceptedArtifact(t, store)
	until := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)

	rec := doJSON(t, h, http.MethodPost, acceptancePath(created.ID, "CVE-2024-1"), map[string]any{
		"until":  until.Format(time.RFC3339),
		"reason": "no upstream fix yet; mitigated by network policy",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	f := findingByID(t, decodeArtifact(t, rec), "CVE-2024-1")
	if f.AcceptedUntil == nil || !f.AcceptedUntil.Equal(until) {
		t.Fatalf("accepted_until = %v, want %v", f.AcceptedUntil, until)
	}
	if f.AcceptanceReason != "no upstream fix yet; mitigated by network policy" {
		t.Fatalf("acceptance_reason = %q", f.AcceptanceReason)
	}
	// From the authenticated client, never the body -- an accountability
	// record a caller can write is not one. The test router's single key
	// authenticates as "default" (legacyClientName).
	if f.AcceptedBy != "default" {
		t.Fatalf("accepted_by = %q, want the authenticated client name", f.AcceptedBy)
	}
	// Still open and still on the artifact: an acceptance concedes the
	// finding is real, so it must not rewrite the status or delete it.
	if f.Status != artifact.FindingStatusOpen {
		t.Fatalf("status = %q, want open", f.Status)
	}
	if f.IsActive() {
		t.Fatal("an accepted finding still counts as active")
	}

	// And it is out of the fleet counts, with no code in stats aware of
	// acceptance at all -- see Finding.IsActive.
	stats, err := store.Stats(context.Background())
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.WithFindings["cve"] != 0 {
		t.Fatalf("with_findings[cve] = %d, want 0 -- an accepted finding is still being counted", stats.WithFindings["cve"])
	}
}

func TestAcceptFinding_Validation(t *testing.T) {
	h, store := newTestRouter(nil)
	created := acceptedArtifact(t, store)
	future := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)

	cases := []struct {
		name string
		body map[string]any
		want string // a distinctive substring of the error
	}{
		{"missing reason", map[string]any{"until": future}, "reason is required"},
		{"blank reason", map[string]any{"until": future, "reason": "   "}, "reason is required"},
		{"missing until", map[string]any{"reason": "because"}, "until is required"},
		{"until is not RFC3339", map[string]any{"until": "31/12/2026", "reason": "because"}, "RFC3339"},
		// An acceptance already expired when it is recorded changes
		// nothing and reads to whoever set it as though the finding had
		// been suppressed -- the worst failure direction this has.
		{"until in the past", map[string]any{"until": time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), "reason": "because"}, "must be in the future"},
		{"until beyond the cap", map[string]any{"until": time.Now().UTC().Add(400 * 24 * time.Hour).Format(time.RFC3339), "reason": "because"}, "at most 365 days"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doJSON(t, h, http.MethodPost, acceptancePath(created.ID, "CVE-2024-1"), tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("body = %s, want it to mention %q", rec.Body.String(), tc.want)
			}
		})
	}

	// Nothing was recorded by any of the rejections above.
	got, err := store.Get(created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.CVEFindings[0].AcceptedUntil != nil {
		t.Fatalf("a rejected request still recorded an acceptance: %+v", got.CVEFindings[0])
	}
}

func TestAcceptFinding_NotFound(t *testing.T) {
	h, store := newTestRouter(nil)
	created := acceptedArtifact(t, store)
	body := map[string]any{
		"until":  time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		"reason": "because",
	}

	t.Run("unknown artifact", func(t *testing.T) {
		rec := doJSON(t, h, http.MethodPost, acceptancePath("no-such-artifact", "CVE-2024-1"), body)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
		}
	})

	// A finding id nobody ever reported for this artifact. Accepting the
	// risk of a finding that does not exist is a typo, and answering 200
	// would let it read as a successful suppression.
	t.Run("unknown finding on a real artifact", func(t *testing.T) {
		rec := doJSON(t, h, http.MethodPost, acceptancePath(created.ID, "CVE-9999-9"), body)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "CVE-9999-9") {
			t.Fatalf("body = %s, want it to name the finding", rec.Body.String())
		}
	})

	t.Run("revoking on an unknown finding", func(t *testing.T) {
		rec := doJSON(t, h, http.MethodDelete, acceptancePath(created.ID, "CVE-9999-9"), nil)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestRevokeFindingAcceptance(t *testing.T) {
	h, store := newTestRouter(nil)
	created := acceptedArtifact(t, store)

	rec := doJSON(t, h, http.MethodPost, acceptancePath(created.ID, "CVE-2024-1"), map[string]any{
		"until":  time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		"reason": "because",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("accept status = %d, body=%s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, http.MethodDelete, acceptancePath(created.ID, "CVE-2024-1"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	f := findingByID(t, decodeArtifact(t, rec), "CVE-2024-1")
	// Cleared whole: a finding showing "accepted by X because Y" with no
	// date would read as a suppression with no end.
	if f.AcceptedUntil != nil || f.AcceptedBy != "" || f.AcceptanceReason != "" {
		t.Fatalf("acceptance survived a revoke: %+v", f)
	}
	if !f.IsActive() {
		t.Fatal("a revoked finding is still suppressed")
	}

	// Idempotent: the caller asked for a state, and that state holds.
	// An acceptance that lapsed on its own between the decision to
	// revoke and the call arriving is not an error anybody can act on.
	rec = doJSON(t, h, http.MethodDelete, acceptancePath(created.ID, "CVE-2024-1"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("second revoke status = %d, want 200 (idempotent), body=%s", rec.Code, rec.Body.String())
	}
}

// Accepting risk is a decision about what the organization will
// tolerate, not a scan result -- so unlike POST /findings and /vex
// beside it, a scan-scoped key must not be able to make it. A CI
// scanner that could would be able to silence whatever it found.
func TestAcceptFinding_RequiresAdminScope(t *testing.T) {
	h, store := newScopedRouter(t, scopedKeys, "reader=read;scanner=scan;boss=admin")
	created := acceptedArtifact(t, store)
	path := acceptancePath(created.ID, "CVE-2024-1")
	body := `{"until":"` + time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339) + `","reason":"because"}`

	for _, tc := range []struct {
		name, key string
		want      int
	}{
		{"a read-only key may not accept", readerKey, http.StatusForbidden},
		// The one that matters: submitting findings and uploading VEX
		// are both ScopeScan, so this is the boundary that separates
		// reporting a result from deciding to live with it.
		{"a scan key may not accept", scanKey, http.StatusForbidden},
		{"an admin key may", adminKey, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := callWithKey(t, h, http.MethodPost, path, tc.key, body); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}

	t.Run("revoking is admin-only too", func(t *testing.T) {
		if got := callWithKey(t, h, http.MethodDelete, path, scanKey, ""); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
		if got := callWithKey(t, h, http.MethodDelete, path, adminKey, ""); got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
	})
}

// An acceptance is recorded against a finding on record, and a scanner
// re-reporting that finding is not new information about the decision.
// The API-level mirror of TestMergeFindings_AcceptanceSurvivesRescan --
// this is the path that actually runs in production.
func TestAcceptFinding_SurvivesTheNextScan(t *testing.T) {
	trivyLike := &fakeScanner{findings: []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "critical", Source: "trivy"},
	}}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivyLike}})
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	if _, scanned := scanAndWait(t, h, store, created.ID); len(scanned.CVEFindings) != 1 {
		t.Fatalf("cve findings after first scan = %+v, want 1", scanned.CVEFindings)
	}

	until := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
	rec := doJSON(t, h, http.MethodPost, acceptancePath(created.ID, "CVE-2024-1"), map[string]any{
		"until": until.Format(time.RFC3339), "reason": "no upstream fix yet",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("accept status = %d, body=%s", rec.Code, rec.Body.String())
	}

	// The image hasn't changed, so the next scan reports it again.
	_, rescanned := scanAndWait(t, h, store, created.ID)
	f := findingByID(t, *rescanned, "CVE-2024-1")
	if f.AcceptedUntil == nil || !f.AcceptedUntil.Equal(until) {
		t.Fatalf("accepted_until = %v after a rescan, want %v", f.AcceptedUntil, until)
	}
	if f.AcceptedBy != "default" || f.AcceptanceReason != "no upstream fix yet" {
		t.Fatalf("acceptance metadata lost in a rescan: %+v", f)
	}
	if f.IsActive() {
		t.Fatal("a rescan reopened an accepted finding")
	}
}

// One finding id legitimately lives in more than one bucket -- a CVE
// reported by trivy lands in "cve", and the same CVE arriving inside a
// SARIF import lands in "other" (see classifyBucket). An acceptance
// that silenced one while the other kept failing the policy gate would
// look like the endpoint had simply not worked, so applyToFindingID
// applies to every bucket carrying the id. Nothing else in this file
// seeds a bucket other than CVEFindings, so without this the
// cross-bucket promise in the handler comment and the OpenAPI
// description is untested.
func TestAcceptFinding_AppliesToEveryBucketCarryingTheID(t *testing.T) {
	h, store := newTestRouter(nil)
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	seen := time.Now().UTC().Add(-24 * time.Hour)
	if _, err := store.Update(created.ID, func(a *artifact.Artifact) {
		a.CVEFindings = []artifact.Finding{
			{ID: "CVE-2024-1", Severity: "critical", Source: "trivy", Status: artifact.FindingStatusOpen, FirstSeenAt: seen},
		}
		// The same id, from a SARIF import.
		a.OtherFindings = []artifact.Finding{
			{ID: "CVE-2024-1", Severity: "critical", Source: "sarif", Status: artifact.FindingStatusOpen, FirstSeenAt: seen},
		}
		// A different id in a third bucket, which must be left alone.
		a.SecretFindings = []artifact.Finding{
			{ID: "secret:/app/.env:aws-key:3", Severity: "high", Source: "trivy", Status: artifact.FindingStatusOpen, FirstSeenAt: seen},
		}
	}); err != nil {
		t.Fatalf("seed findings: %v", err)
	}

	rec := doJSON(t, h, http.MethodPost, acceptancePath(created.ID, "CVE-2024-1"), map[string]any{
		"until":  time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		"reason": "no upstream fix yet",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeArtifact(t, rec)

	for _, b := range []struct {
		name     string
		findings []artifact.Finding
	}{{"cve", got.CVEFindings}, {"other", got.OtherFindings}} {
		if len(b.findings) != 1 {
			t.Fatalf("%s bucket = %+v, want 1", b.name, b.findings)
		}
		if b.findings[0].AcceptedUntil == nil {
			t.Errorf("the %s bucket's copy of the finding was not accepted: %+v", b.name, b.findings[0])
		}
		if b.findings[0].IsActive() {
			t.Errorf("the %s bucket's copy still counts as active", b.name)
		}
	}

	// A finding the caller did not name is untouched -- an acceptance
	// applies to one id, not to the artifact.
	if got.SecretFindings[0].AcceptedUntil != nil {
		t.Fatalf("accepting one finding accepted an unrelated one: %+v", got.SecretFindings[0])
	}

	// Revoking clears every copy too, for the same reason.
	rec = doJSON(t, h, http.MethodDelete, acceptancePath(created.ID, "CVE-2024-1"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, body=%s", rec.Code, rec.Body.String())
	}
	got = decodeArtifact(t, rec)
	if got.CVEFindings[0].AcceptedUntil != nil || got.OtherFindings[0].AcceptedUntil != nil {
		t.Fatalf("a revoke left one bucket's copy accepted: cve=%+v other=%+v", got.CVEFindings[0], got.OtherFindings[0])
	}
}

// A finding that lives ONLY in a non-CVE bucket must be acceptable too
// -- the handler walks all five, and a malware or secret finding is a
// legitimate thing to decide to live with (a test fixture image that
// really does ship EICAR, say).
func TestAcceptFinding_NonCVEBucket(t *testing.T) {
	h, store := newTestRouter(nil)
	created := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	if _, err := store.Update(created.ID, func(a *artifact.Artifact) {
		a.MalwareFindings = []artifact.Finding{
			{ID: "clamav-signature-match", Severity: "critical", Title: "Eicar-Test-Signature",
				Source: "clamav", Status: artifact.FindingStatusOpen, FirstSeenAt: time.Now().UTC()},
		}
	}); err != nil {
		t.Fatalf("seed findings: %v", err)
	}

	rec := doJSON(t, h, http.MethodPost, acceptancePath(created.ID, "clamav-signature-match"), map[string]any{
		"until":  time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		"reason": "deliberate EICAR test fixture",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	f := decodeArtifact(t, rec).MalwareFindings[0]
	if f.AcceptedUntil == nil || f.AcceptedBy != "default" {
		t.Fatalf("a malware finding was not accepted: %+v", f)
	}

	stats, err := store.Stats(context.Background())
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.WithFindings["malware"] != 0 {
		t.Fatalf("with_findings[malware] = %d, want 0", stats.WithFindings["malware"])
	}
}
