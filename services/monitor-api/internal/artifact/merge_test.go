package artifact_test

import (
	"testing"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

var mergeNow = time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)

func TestMergeFindings_NewFindingIsOpenWithFirstSeenNow(t *testing.T) {
	merged := artifact.MergeFindings(nil, []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "high", Source: "trivy"},
	}, mergeNow, true)

	if len(merged) != 1 {
		t.Fatalf("merged = %+v, want 1 finding", merged)
	}
	f := merged[0]
	if f.Status != artifact.FindingStatusOpen {
		t.Fatalf("status = %q, want %q", f.Status, artifact.FindingStatusOpen)
	}
	if !f.FirstSeenAt.Equal(mergeNow) {
		t.Fatalf("first_seen_at = %v, want %v", f.FirstSeenAt, mergeNow)
	}
	if f.ResolvedAt != nil {
		t.Fatalf("resolved_at = %v, want nil", f.ResolvedAt)
	}
}

func TestMergeFindings_StillReportedStaysOpenAndKeepsFirstSeen(t *testing.T) {
	firstSeen := mergeNow.Add(-48 * time.Hour)
	existing := []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "high", Source: "trivy", Status: artifact.FindingStatusOpen, FirstSeenAt: firstSeen},
	}
	// Reported again, severity revised upstream.
	reported := []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "critical", Title: "revised", Source: "trivy"},
	}

	merged := artifact.MergeFindings(existing, reported, mergeNow, true)
	if len(merged) != 1 {
		t.Fatalf("merged = %+v, want 1 finding", merged)
	}
	f := merged[0]
	if f.Status != artifact.FindingStatusOpen {
		t.Fatalf("status = %q, want %q", f.Status, artifact.FindingStatusOpen)
	}
	if !f.FirstSeenAt.Equal(firstSeen) {
		t.Fatalf("first_seen_at = %v, want original %v (should not reset just because it was reported again)", f.FirstSeenAt, firstSeen)
	}
	if f.Severity != "critical" || f.Title != "revised" {
		t.Fatalf("expected refreshed severity/title, got %+v", f)
	}
}

func TestMergeFindings_MissingBecomesFixedWhenDetectFixedTrue(t *testing.T) {
	firstSeen := mergeNow.Add(-24 * time.Hour)
	existing := []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "high", Source: "trivy", Status: artifact.FindingStatusOpen, FirstSeenAt: firstSeen},
	}

	merged := artifact.MergeFindings(existing, nil, mergeNow, true)
	if len(merged) != 1 {
		t.Fatalf("merged = %+v, want the fixed finding to still be present, not deleted", merged)
	}
	f := merged[0]
	if f.Status != artifact.FindingStatusFixed {
		t.Fatalf("status = %q, want %q", f.Status, artifact.FindingStatusFixed)
	}
	if f.ResolvedAt == nil || !f.ResolvedAt.Equal(mergeNow) {
		t.Fatalf("resolved_at = %v, want %v", f.ResolvedAt, mergeNow)
	}
	if !f.FirstSeenAt.Equal(firstSeen) {
		t.Fatalf("first_seen_at should be untouched by becoming fixed, got %v want %v", f.FirstSeenAt, firstSeen)
	}
}

func TestMergeFindings_AlreadyFixedStaysUntouched(t *testing.T) {
	firstSeen := mergeNow.Add(-72 * time.Hour)
	resolvedAt := mergeNow.Add(-24 * time.Hour)
	existing := []artifact.Finding{
		{ID: "CVE-2024-1", Source: "trivy", Status: artifact.FindingStatusFixed, FirstSeenAt: firstSeen, ResolvedAt: &resolvedAt},
	}

	merged := artifact.MergeFindings(existing, nil, mergeNow, true)
	if len(merged) != 1 {
		t.Fatalf("merged = %+v", merged)
	}
	f := merged[0]
	if f.Status != artifact.FindingStatusFixed {
		t.Fatalf("status = %q, want %q", f.Status, artifact.FindingStatusFixed)
	}
	if f.ResolvedAt == nil || !f.ResolvedAt.Equal(resolvedAt) {
		t.Fatalf("resolved_at = %v, want the original %v unchanged (shouldn't bump forward every scan)", f.ResolvedAt, resolvedAt)
	}
}

func TestMergeFindings_RegressionReopensAndClearsResolvedAt(t *testing.T) {
	firstSeen := mergeNow.Add(-72 * time.Hour)
	resolvedAt := mergeNow.Add(-24 * time.Hour)
	existing := []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "high", Source: "trivy", Status: artifact.FindingStatusFixed, FirstSeenAt: firstSeen, ResolvedAt: &resolvedAt},
	}
	reported := []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "high", Source: "trivy"},
	}

	merged := artifact.MergeFindings(existing, reported, mergeNow, true)
	if len(merged) != 1 {
		t.Fatalf("merged = %+v", merged)
	}
	f := merged[0]
	if f.Status != artifact.FindingStatusOpen {
		t.Fatalf("status = %q, want %q (a regression should reopen)", f.Status, artifact.FindingStatusOpen)
	}
	if f.ResolvedAt != nil {
		t.Fatalf("resolved_at = %v, want nil after reopening", f.ResolvedAt)
	}
	if !f.FirstSeenAt.Equal(firstSeen) {
		t.Fatalf("first_seen_at = %v, want original discovery date %v preserved through the regression", f.FirstSeenAt, firstSeen)
	}
}

func TestMergeFindings_DetectFixedFalseLeavesMissingFindingsAlone(t *testing.T) {
	firstSeen := mergeNow.Add(-24 * time.Hour)
	existing := []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "high", Source: "trivy", Status: artifact.FindingStatusOpen, FirstSeenAt: firstSeen},
	}

	// Simulates a scan round where the scanner covering this bucket
	// errored -- reported is empty, but that must NOT be read as
	// "everything got fixed."
	merged := artifact.MergeFindings(existing, nil, mergeNow, false)
	if len(merged) != 1 {
		t.Fatalf("merged = %+v, want the finding preserved untouched", merged)
	}
	f := merged[0]
	if f.Status != artifact.FindingStatusOpen {
		t.Fatalf("status = %q, want %q (a failed scan round must not mark findings fixed)", f.Status, artifact.FindingStatusOpen)
	}
	if f.ResolvedAt != nil {
		t.Fatalf("resolved_at = %v, want nil", f.ResolvedAt)
	}
	if !f.FirstSeenAt.Equal(firstSeen) {
		t.Fatalf("first_seen_at = %v, want unchanged %v", f.FirstSeenAt, firstSeen)
	}
}

func TestMergeFindings_MixOfNewStillOpenAndFixed(t *testing.T) {
	firstSeenA := mergeNow.Add(-48 * time.Hour)
	firstSeenB := mergeNow.Add(-96 * time.Hour)
	existing := []artifact.Finding{
		{ID: "CVE-A", Source: "trivy", Status: artifact.FindingStatusOpen, FirstSeenAt: firstSeenA}, // still reported below
		{ID: "CVE-B", Source: "trivy", Status: artifact.FindingStatusOpen, FirstSeenAt: firstSeenB}, // missing this round -> fixed
	}
	reported := []artifact.Finding{
		{ID: "CVE-A", Source: "trivy"},
		{ID: "CVE-C", Source: "trivy"}, // brand new
	}

	merged := artifact.MergeFindings(existing, reported, mergeNow, true)
	byID := make(map[string]artifact.Finding, len(merged))
	for _, f := range merged {
		byID[f.ID] = f
	}
	if len(merged) != 3 {
		t.Fatalf("merged = %+v, want 3 findings (A still open, B fixed, C new)", merged)
	}
	if byID["CVE-A"].Status != artifact.FindingStatusOpen {
		t.Fatalf("CVE-A status = %q, want open", byID["CVE-A"].Status)
	}
	if byID["CVE-B"].Status != artifact.FindingStatusFixed {
		t.Fatalf("CVE-B status = %q, want fixed", byID["CVE-B"].Status)
	}
	if byID["CVE-C"].Status != artifact.FindingStatusOpen || !byID["CVE-C"].FirstSeenAt.Equal(mergeNow) {
		t.Fatalf("CVE-C = %+v, want new+open+first_seen=now", byID["CVE-C"])
	}
}
