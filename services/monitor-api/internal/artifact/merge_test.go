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
	}, mergeNow, true, nil)

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

	merged := artifact.MergeFindings(existing, reported, mergeNow, true, nil)
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

	merged := artifact.MergeFindings(existing, nil, mergeNow, true, nil)
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

	merged := artifact.MergeFindings(existing, nil, mergeNow, true, nil)
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

	merged := artifact.MergeFindings(existing, reported, mergeNow, true, nil)
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
	merged := artifact.MergeFindings(existing, nil, mergeNow, false, nil)
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

	merged := artifact.MergeFindings(existing, reported, mergeNow, true, nil)
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

// notAffected is the VEX overlay MergeFindings takes, for one
// vulnerability, as internal/api/vex.go builds it from a parsed
// document.
func notAffected(id, justification string) map[string]artifact.VEXStatement {
	return artifact.VEXByID([]artifact.VEXStatement{
		{VulnID: id, Status: artifact.FindingStatusNotAffected, Justification: justification},
	})
}

// TestMergeFindings_VEXSuppressesAndSurvivesLaterScans is the whole
// point of VEX support: an operator suppresses a finding once, and it
// stays suppressed through every subsequent scan that keeps reporting
// it -- without the VEX document being consulted again. If the
// suppression only held while the document was being re-read, every
// scan that couldn't load it would reopen findings somebody already
// assessed.
func TestMergeFindings_VEXSuppressesAndSurvivesLaterScans(t *testing.T) {
	firstSeen := mergeNow.Add(-72 * time.Hour)
	existing := []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "high", Source: "trivy", Status: artifact.FindingStatusOpen, FirstSeenAt: firstSeen},
	}

	// Upload: a merge with nothing reported at all (detectFixed false,
	// exactly how uploadVEX applies a freshly uploaded document).
	suppressed := artifact.MergeFindings(existing, nil, mergeNow, false,
		notAffected("CVE-2024-1", "vulnerable_code_not_in_execute_path"))
	if len(suppressed) != 1 {
		t.Fatalf("merged = %+v, want 1 finding", suppressed)
	}
	if suppressed[0].Status != artifact.FindingStatusNotAffected {
		t.Fatalf("status after VEX upload = %q, want %q", suppressed[0].Status, artifact.FindingStatusNotAffected)
	}
	if suppressed[0].Justification != "vulnerable_code_not_in_execute_path" {
		t.Fatalf("justification = %q, want the statement's own", suppressed[0].Justification)
	}
	if suppressed[0].ResolvedAt != nil {
		t.Fatalf("resolved_at = %v, want nil -- not_affected means it never applied, nothing was resolved", suppressed[0].ResolvedAt)
	}
	if !suppressed[0].FirstSeenAt.Equal(firstSeen) {
		t.Fatalf("first_seen_at = %v, want original %v", suppressed[0].FirstSeenAt, firstSeen)
	}

	// Next scan: trivy reports it again (it always will -- VEX is an
	// assertion about reachability, not a change to the image), and no
	// VEX overlay is passed at all this round.
	secondScan := mergeNow.Add(24 * time.Hour)
	rescanned := artifact.MergeFindings(suppressed, []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "critical", Title: "revised upstream", Source: "trivy"},
	}, secondScan, true, nil)
	if len(rescanned) != 1 {
		t.Fatalf("merged = %+v, want 1 finding", rescanned)
	}
	f := rescanned[0]
	if f.Status != artifact.FindingStatusNotAffected {
		t.Fatalf("status after rescan = %q, want %q (a re-report must not reopen a VEX-suppressed finding)", f.Status, artifact.FindingStatusNotAffected)
	}
	if f.Justification != "vulnerable_code_not_in_execute_path" {
		t.Fatalf("justification after rescan = %q, want it carried over like first_seen_at", f.Justification)
	}
	if f.Severity != "critical" || f.Title != "revised upstream" {
		t.Fatalf("expected refreshed severity/title from the new report, got %+v", f)
	}
	if !f.FirstSeenAt.Equal(firstSeen) {
		t.Fatalf("first_seen_at = %v, want original %v", f.FirstSeenAt, firstSeen)
	}

	// Third scan, still no overlay, and this time the scanner stops
	// reporting it with detectFixed true. It must stay "not affected"
	// rather than being relabelled "fixed" -- a human's assessment
	// outranks an inference from a scanner going quiet.
	thirdScan := secondScan.Add(24 * time.Hour)
	quiet := artifact.MergeFindings(rescanned, nil, thirdScan, true, nil)
	if len(quiet) != 1 {
		t.Fatalf("merged = %+v, want 1 finding", quiet)
	}
	if quiet[0].Status != artifact.FindingStatusNotAffected {
		t.Fatalf("status = %q, want %q", quiet[0].Status, artifact.FindingStatusNotAffected)
	}
	if quiet[0].Justification != "vulnerable_code_not_in_execute_path" {
		t.Fatalf("justification = %q, want it preserved", quiet[0].Justification)
	}
}

// An assessment that turns out to be wrong has to be retractable, or
// the only way back is editing the database by hand.
func TestMergeFindings_VEXAffectedRevokesAnEarlierSuppression(t *testing.T) {
	firstSeen := mergeNow.Add(-72 * time.Hour)
	suppressed := artifact.MergeFindings([]artifact.Finding{
		{ID: "CVE-2024-1", Severity: "high", Source: "trivy", Status: artifact.FindingStatusOpen, FirstSeenAt: firstSeen},
	}, nil, mergeNow, false, notAffected("CVE-2024-1", "assessed in error"))
	if suppressed[0].Status != artifact.FindingStatusNotAffected {
		t.Fatalf("setup: status = %q, want it suppressed first", suppressed[0].Status)
	}

	// Corrected document: it IS affected after all.
	corrected := artifact.VEXByID([]artifact.VEXStatement{
		{VulnID: "CVE-2024-1", Status: artifact.VEXStatusAffected},
	})
	reopened := artifact.MergeFindings(suppressed, []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "high", Source: "trivy"},
	}, mergeNow, true, corrected)

	f := reopened[0]
	if f.Status != artifact.FindingStatusOpen {
		t.Fatalf("status = %q, want %q -- an explicit 'affected' must revoke the suppression", f.Status, artifact.FindingStatusOpen)
	}
	if f.Justification != "" {
		t.Fatalf("justification = %q, want cleared with the suppression it explained", f.Justification)
	}
	if !f.FirstSeenAt.Equal(firstSeen) {
		t.Fatalf("first_seen_at = %v, want original %v", f.FirstSeenAt, firstSeen)
	}

	// A later document that simply doesn't mention it must NOT revoke
	// anything -- silence is not an assertion.
	stillSuppressed := artifact.MergeFindings(suppressed, []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "high", Source: "trivy"},
	}, mergeNow, true, notAffected("CVE-2024-OTHER", "unrelated"))
	if stillSuppressed[0].Status != artifact.FindingStatusNotAffected {
		t.Fatalf("status = %q, want it still suppressed -- a document that says nothing about it changes nothing", stillSuppressed[0].Status)
	}
}

func TestMergeFindings_VEXFixedSetsResolvedAt(t *testing.T) {
	firstSeen := mergeNow.Add(-48 * time.Hour)
	existing := []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "high", Source: "trivy", Status: artifact.FindingStatusOpen, FirstSeenAt: firstSeen},
	}
	vex := artifact.VEXByID([]artifact.VEXStatement{
		{VulnID: "CVE-2024-1", Status: artifact.FindingStatusFixed, Justification: "patched in 1.2.4"},
	})

	merged := artifact.MergeFindings(existing, []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "high", Source: "trivy"},
	}, mergeNow, true, vex)
	f := merged[0]
	if f.Status != artifact.FindingStatusFixed {
		t.Fatalf("status = %q, want %q", f.Status, artifact.FindingStatusFixed)
	}
	if f.ResolvedAt == nil || !f.ResolvedAt.Equal(mergeNow) {
		t.Fatalf("resolved_at = %v, want %v -- a VEX 'fixed' did resolve something", f.ResolvedAt, mergeNow)
	}
	if f.Justification != "patched in 1.2.4" {
		t.Fatalf("justification = %q", f.Justification)
	}

	// Next scan, same document, scanner still reporting it: the
	// resolution date must not walk forward every round -- the dashboard
	// renders "Fixed <time ago>" from it, so a drifting stamp would read
	// as "just fixed" forever. Same invariant
	// TestMergeFindings_AlreadyFixedStaysUntouched protects for
	// scan-detected fixes.
	secondScan := mergeNow.Add(24 * time.Hour)
	rescanned := artifact.MergeFindings(merged, []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "high", Source: "trivy"},
	}, secondScan, true, vex)
	if got := rescanned[0]; got.ResolvedAt == nil || !got.ResolvedAt.Equal(mergeNow) {
		t.Fatalf("resolved_at after a second scan = %v, want the original %v unchanged", got.ResolvedAt, mergeNow)
	}
}

// A VEX document can arrive before the scanner ever reports the
// vulnerability -- the finding must land suppressed on discovery rather
// than being open until some later merge notices.
func TestMergeFindings_VEXAppliesToBrandNewFinding(t *testing.T) {
	merged := artifact.MergeFindings(nil, []artifact.Finding{
		{ID: "CVE-2024-1", Severity: "high", Source: "trivy"},
	}, mergeNow, true, notAffected("CVE-2024-1", "component_not_present"))

	f := merged[0]
	if f.Status != artifact.FindingStatusNotAffected {
		t.Fatalf("status = %q, want %q", f.Status, artifact.FindingStatusNotAffected)
	}
	if f.Justification != "component_not_present" {
		t.Fatalf("justification = %q", f.Justification)
	}
	if !f.FirstSeenAt.Equal(mergeNow) {
		t.Fatalf("first_seen_at = %v, want %v -- it is still a first sighting", f.FirstSeenAt, mergeNow)
	}
}

// Statuses that assert nothing must leave a finding exactly as the scan
// found it, including a status string this service doesn't recognize at
// all (a typo, a vocabulary from tooling we've never seen) -- failing
// toward showing a real vulnerability, never toward hiding one.
func TestMergeFindings_VEXNonSuppressingStatusesChangeNothing(t *testing.T) {
	for _, status := range []string{"affected", "under_investigation", "sort_of_maybe", ""} {
		t.Run(status, func(t *testing.T) {
			vex := artifact.VEXByID([]artifact.VEXStatement{
				{VulnID: "CVE-2024-1", Status: status, Justification: "should not be applied"},
			})
			merged := artifact.MergeFindings(nil, []artifact.Finding{
				{ID: "CVE-2024-1", Severity: "high", Source: "trivy"},
			}, mergeNow, true, vex)

			f := merged[0]
			if f.Status != artifact.FindingStatusOpen {
				t.Fatalf("status = %q, want %q", f.Status, artifact.FindingStatusOpen)
			}
			if f.Justification != "" {
				t.Fatalf("justification = %q, want empty -- a non-suppressing statement attaches nothing", f.Justification)
			}
		})
	}
}

// Justification is lifecycle metadata, not caller input: submitFindings
// decodes reported findings straight from a caller's JSON, so a
// justification arriving that way must be dropped rather than persisted
// as if somebody had assessed the finding.
func TestMergeFindings_JustificationFromReportedFindingIsIgnored(t *testing.T) {
	merged := artifact.MergeFindings(nil, []artifact.Finding{
		{ID: "CVE-2024-1", Source: "external", Status: artifact.FindingStatusNotAffected, Justification: "trust me"},
	}, mergeNow, true, nil)

	f := merged[0]
	if f.Status != artifact.FindingStatusOpen {
		t.Fatalf("status = %q, want %q -- only a VEX document may suppress", f.Status, artifact.FindingStatusOpen)
	}
	if f.Justification != "" {
		t.Fatalf("justification = %q, want empty", f.Justification)
	}
}

func TestCoalesceSameIDSources(t *testing.T) {
	tests := []struct {
		name     string
		reported []artifact.Finding
		want     []artifact.Finding
	}{
		{
			name: "two scanners same ID joins sources",
			reported: []artifact.Finding{
				{ID: "CVE-1", Severity: "high", Title: "t", Source: "trivy"},
				{ID: "CVE-1", Severity: "high", Title: "t", Source: "grype"},
			},
			want: []artifact.Finding{
				{ID: "CVE-1", Severity: "high", Title: "t", Source: "grype, trivy"},
			},
		},
		{
			name: "three sources joined and deduped",
			reported: []artifact.Finding{
				{ID: "CVE-1", Source: "trivy"},
				{ID: "CVE-1", Source: "grype"},
				{ID: "CVE-1", Source: "trivy"},
			},
			want: []artifact.Finding{
				{ID: "CVE-1", Source: "grype, trivy"},
			},
		},
		{
			name: "already-joined source passed through unchanged, not doubled",
			reported: []artifact.Finding{
				{ID: "CVE-1", Source: "grype, trivy"},
			},
			want: []artifact.Finding{
				{ID: "CVE-1", Source: "grype, trivy"},
			},
		},
		{
			name: "different IDs stay independent",
			reported: []artifact.Finding{
				{ID: "CVE-1", Source: "trivy"},
				{ID: "CVE-2", Source: "grype"},
			},
			want: []artifact.Finding{
				{ID: "CVE-1", Source: "trivy"},
				{ID: "CVE-2", Source: "grype"},
			},
		},
		{
			name: "empty source doesn't produce a stray comma",
			reported: []artifact.Finding{
				{ID: "CVE-1", Source: ""},
			},
			want: []artifact.Finding{
				{ID: "CVE-1", Source: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := artifact.CoalesceSameIDSources(tt.reported)
			if len(got) != len(tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
			for i := range got {
				if got[i].ID != tt.want[i].ID || got[i].Source != tt.want[i].Source {
					t.Fatalf("got[%d] = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// Revoking has to work through the SAME path suppressing works through:
// uploadVEX merges with nothing reported and detectFixed=false (see
// internal/api/vex.go). The original revocation only took effect when a
// scanner happened to report the finding in the same round, so the
// upload that was supposed to retract an assessment silently did
// nothing until the next scan -- while the upload that APPLIED one took
// effect immediately. Same asymmetry the suppression path was
// deliberately built to avoid.
func TestMergeFindings_VEXAffectedRevokesOnUploadWithNothingReported(t *testing.T) {
	firstSeen := mergeNow.Add(-72 * time.Hour)
	suppressed := artifact.MergeFindings([]artifact.Finding{
		{ID: "CVE-2024-1", Severity: "high", Source: "trivy", Status: artifact.FindingStatusOpen, FirstSeenAt: firstSeen},
	}, nil, mergeNow, false, notAffected("CVE-2024-1", "assessed in error"))
	if suppressed[0].Status != artifact.FindingStatusNotAffected {
		t.Fatalf("setup: status = %q, want it suppressed first", suppressed[0].Status)
	}

	corrected := artifact.VEXByID([]artifact.VEXStatement{
		{VulnID: "CVE-2024-1", Status: artifact.VEXStatusAffected},
	})
	// Exactly what uploadVEX does: nothing reported, detectFixed false.
	reopened := artifact.MergeFindings(suppressed, nil, mergeNow, false, corrected)

	f := reopened[0]
	if f.Status != artifact.FindingStatusOpen {
		t.Fatalf("status = %q, want %q -- uploading an 'affected' statement must retract immediately, not at the next scan", f.Status, artifact.FindingStatusOpen)
	}
	if f.Justification != "" {
		t.Fatalf("justification = %q, want cleared with the suppression it explained", f.Justification)
	}
	if f.ResolvedAt != nil {
		t.Fatalf("resolved_at = %v, want nil", f.ResolvedAt)
	}
	if !f.FirstSeenAt.Equal(firstSeen) {
		t.Fatalf("first_seen_at = %v, want original %v", f.FirstSeenAt, firstSeen)
	}
}
