package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

func TestFindByFindingID(t *testing.T) {
	trivyLike := &fakeScanner{findings: []artifact.Finding{{ID: "CVE-2024-9999", Severity: "high", Source: "trivy"}}}
	h, store := newTestRouter(scanner.Registry{artifact.TypeImage: {trivyLike}})

	affected := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)
	mustCreate(t, store, "debian:12", artifact.TypeImage) // never scanned -- must not show up below

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+affected.ID+"/scan", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("scan status = %d, want 200, body=%s", rec.Code, rec.Body.String())
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

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+created.ID+"/scan", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("scan status = %d, want 200, body=%s", rec.Code, rec.Body.String())
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
