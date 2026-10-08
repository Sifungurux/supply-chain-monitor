package artifact_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// The fixture is REAL output, not hand-written: produced by
// `trivy convert --format cyclonedx --scanners vuln` (trivy 0.72.0, the
// version the Dockerfile pins) from testdata/trivy_report_sample.json.
// Asserting against a document somebody typed would prove the annotator
// agrees with my idea of CycloneDX rather than with trivy's.
func storedSBOM(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "cyclonedx_with_vulns.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	return m
}

func vulnByID(t *testing.T, doc map[string]any, id string) map[string]any {
	t.Helper()
	for _, v := range doc["vulnerabilities"].([]any) {
		m := v.(map[string]any)
		if m["id"] == id {
			return m
		}
	}
	t.Fatalf("no vulnerability %q in output", id)
	return nil
}

func TestAnnotateCycloneDX_PassesEverythingElseThrough(t *testing.T) {
	stored := storedSBOM(t)
	before := decode(t, stored)

	out, err := artifact.AnnotateCycloneDX(stored, nil, time.Now())
	if err != nil {
		t.Fatalf("annotate: %v", err)
	}
	after := decode(t, out)

	// The component tree, metadata and serial number are not ours to
	// touch. A typed CycloneDX model would have dropped whatever it had
	// not been taught; this asserts the generic-map approach actually
	// preserves them.
	for _, key := range []string{"bomFormat", "specVersion", "serialNumber", "version", "metadata", "components"} {
		b, _ := json.Marshal(before[key])
		a, _ := json.Marshal(after[key])
		if string(b) != string(a) {
			t.Errorf("%s changed:\n before %s\n after  %s", key, b, a)
		}
	}
}

func TestAnnotateCycloneDX_AddsAnalysisToKnownVulnerabilities(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	resolved := now.Add(-24 * time.Hour)
	until := now.Add(90 * 24 * time.Hour)

	for _, tc := range []struct {
		name      string
		finding   artifact.Finding
		wantState string
		wantIn    string // substring expected in analysis.detail
	}{
		{
			name:      "vex suppression carries its justification",
			finding:   artifact.Finding{ID: "CVE-2024-58251", Status: artifact.FindingStatusNotAffected, Justification: "vulnerable code is not in the execute path"},
			wantState: "not_affected",
			wantIn:    "not in the execute path",
		},
		{
			name:      "fixed says when",
			finding:   artifact.Finding{ID: "CVE-2024-58251", Status: artifact.FindingStatusFixed, ResolvedAt: &resolved},
			wantState: "resolved",
			wantIn:    "2026-05-31",
		},
		{
			// CycloneDX has no "accepted" state. Still exploitable, and
			// we have chosen not to act -- the expiry is the part that
			// makes it an acceptance rather than a dismissal.
			name: "risk acceptance keeps the expiry and the accepter",
			finding: artifact.Finding{
				ID: "CVE-2024-58251", Status: artifact.FindingStatusOpen,
				AcceptedUntil: &until, AcceptedBy: "kirk", AcceptanceReason: "no fix upstream yet",
			},
			wantState: "exploitable",
			wantIn:    "expires 2026-08-30",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := artifact.AnnotateCycloneDX(storedSBOM(t), []artifact.Finding{tc.finding}, now)
			if err != nil {
				t.Fatalf("annotate: %v", err)
			}
			a, ok := vulnByID(t, decode(t, out), "CVE-2024-58251")["analysis"].(map[string]any)
			if !ok {
				t.Fatal("no analysis block was added")
			}
			if a["state"] != tc.wantState {
				t.Errorf("state = %v, want %q", a["state"], tc.wantState)
			}
			detail, _ := a["detail"].(string)
			if !strings.Contains(detail, tc.wantIn) {
				t.Errorf("detail = %q, want it to contain %q", detail, tc.wantIn)
			}
		})
	}
}

// An open, unsuppressed, unaccepted finding must get NO analysis block.
// "in_triage" would claim somebody is looking at it; absence correctly
// means nothing has been recorded.
func TestAnnotateCycloneDX_OpenFindingGetsNoAnalysis(t *testing.T) {
	out, err := artifact.AnnotateCycloneDX(storedSBOM(t),
		[]artifact.Finding{{ID: "CVE-2024-58251", Status: artifact.FindingStatusOpen}}, time.Now())
	if err != nil {
		t.Fatalf("annotate: %v", err)
	}
	if _, has := vulnByID(t, decode(t, out), "CVE-2024-58251")["analysis"]; has {
		t.Error("an open finding was given an analysis block it has not earned")
	}
}

// A vulnerability trivy reported that this system has no record of must
// be left exactly as it is -- inventing an analysis would assert
// something nobody assessed.
func TestAnnotateCycloneDX_UnknownVulnerabilityUntouched(t *testing.T) {
	stored := storedSBOM(t)
	out, err := artifact.AnnotateCycloneDX(stored, []artifact.Finding{{ID: "CVE-9999-1", Status: artifact.FindingStatusNotAffected}}, time.Now())
	if err != nil {
		t.Fatalf("annotate: %v", err)
	}
	b, _ := json.Marshal(vulnByID(t, decode(t, stored), "CVE-2024-58251"))
	a, _ := json.Marshal(vulnByID(t, decode(t, out), "CVE-2024-58251"))
	if string(b) != string(a) {
		t.Errorf("a vulnerability with no stored finding was modified:\n before %s\n after  %s", b, a)
	}
}

// grype's findings are in no trivy document. Dropping them would lose
// 4,557 of this fleet's 46,728 open findings from the export.
func TestAnnotateCycloneDX_AddsFindingsTheDocumentDoesNotHave(t *testing.T) {
	out, err := artifact.AnnotateCycloneDX(storedSBOM(t), []artifact.Finding{
		{ID: "GHSA-aaaa-bbbb-cccc", Source: "grype", Severity: "High", Title: "something grype found"},
	}, time.Now())
	if err != nil {
		t.Fatalf("annotate: %v", err)
	}
	doc := decode(t, out)
	added := vulnByID(t, doc, "GHSA-aaaa-bbbb-cccc")

	// No `affects`: a Finding records no package, so nothing ties it to
	// a component. Asserted so that when findings DO carry a purl, this
	// test is what says the export must start using it.
	if _, has := added["affects"]; has {
		t.Error("an affects[] was invented for a finding that records no package")
	}
	ratings, _ := added["ratings"].([]any)
	if len(ratings) != 1 {
		t.Fatalf("ratings = %v, want one", ratings)
	}
	if sev := ratings[0].(map[string]any)["severity"]; sev != "high" {
		t.Errorf("severity = %v, want lowercase %q as CycloneDX requires", sev, "high")
	}
	// trivy's own vulnerability must survive alongside it.
	vulnByID(t, doc, "CVE-2024-58251")
}

func TestAnnotateCycloneDX_RefusesNonCycloneDX(t *testing.T) {
	if _, err := artifact.AnnotateCycloneDX([]byte(`{"spdxVersion":"SPDX-2.3"}`), nil, time.Now()); err == nil {
		t.Fatal("an SPDX document was annotated as though it were CycloneDX")
	}
	if _, err := artifact.AnnotateCycloneDX([]byte(`not json`), nil, time.Now()); err == nil {
		t.Fatal("invalid JSON was accepted")
	}
}
