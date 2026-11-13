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
			a, ok := vulnByID(t, decode(t, out), "ALPINE-CVE-2024-58251")["analysis"].(map[string]any)
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
	if _, has := vulnByID(t, decode(t, out), "ALPINE-CVE-2024-58251")["analysis"]; has {
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
	// trivy's own vulnerability (no finding here, so not renamed) must
	// survive alongside it.
	vulnByID(t, doc, "CVE-2024-58251")
}

// Every severity spelling the live fleet stores (taken from the findings
// CSV on 2026-11-12), plus junk. Dependency-Track rejects the WHOLE upload
// with a schema error if one rating is outside CycloneDX's enum, so a
// single grype "Negligible" used to make an artifact's export unimportable.
func TestAnnotateCycloneDX_SeverityIsAlwaysInTheCycloneDXEnum(t *testing.T) {
	for in, want := range map[string]string{
		"CRITICAL": "critical", "Critical": "critical",
		"HIGH": "high", "High": "high",
		"MEDIUM": "medium", "Medium": "medium",
		"LOW": "low", "Low": "low",
		"Negligible": "info", // grype's lowest; CycloneDX calls it info
		"UNKNOWN":    "unknown", "Unknown": "unknown",
		"bogus": "unknown",
	} {
		out, err := artifact.AnnotateCycloneDX(storedSBOM(t), []artifact.Finding{
			{ID: "GHSA-sev", Source: "grype", Severity: in},
		}, time.Now())
		if err != nil {
			t.Fatalf("%s: annotate: %v", in, err)
		}
		ratings, _ := vulnByID(t, decode(t, out), "GHSA-sev")["ratings"].([]any)
		if len(ratings) != 1 {
			t.Fatalf("%s: ratings = %v, want one", in, ratings)
		}
		if got := ratings[0].(map[string]any)["severity"]; got != want {
			t.Errorf("severity %q exported as %v, want %q", in, got, want)
		}
	}
}

func TestAnnotateCycloneDX_RefusesNonCycloneDX(t *testing.T) {
	if _, err := artifact.AnnotateCycloneDX([]byte(`{"spdxVersion":"SPDX-2.3"}`), nil, time.Now()); err == nil {
		t.Fatal("an SPDX document was annotated as though it were CycloneDX")
	}
	if _, err := artifact.AnnotateCycloneDX([]byte(`not json`), nil, time.Now()); err == nil {
		t.Fatal("invalid JSON was accepted")
	}
}

// Dependency-Track 4.14.6 applies a VEX entry only when (source, id)
// exactly matches the finding it filed, and with its OSV ecosystems on it
// files the same CVE differently per package type. Every expected pair
// below is one DT actually reported for a real fleet image on 2026-11-13.
func TestAnnotateCycloneDX_NamesVulnerabilitiesTheWayDependencyTrackFilesThem(t *testing.T) {
	doc := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6",
	 "components":[
	  {"bom-ref":"a","purl":"pkg:apk/alpine/libxslt@1.1.43-r3?distro=3.24.1"},
	  {"bom-ref":"d","purl":"pkg:deb/debian/apt@2.6.1?distro=debian-12.7",
	   "components":[{"bom-ref":"u","purl":"pkg:deb/ubuntu/apt@2.4.14?distro=ubuntu-22.04"}]},
	  {"bom-ref":"g","purl":"pkg:golang/stdlib@v1.23.12"},
	  {"bom-ref":"x","purl":"pkg:npm/left-pad@1.0.0"}],
	 "vulnerabilities":[
	  {"id":"CVE-2025-10911","source":{"name":"alpine","url":"https://secdb.alpinelinux.org/"},"affects":[{"ref":"a"}]},
	  {"id":"CVE-2011-3374","source":{"name":"debian"},"affects":[{"ref":"d"}]},
	  {"id":"DSA-5990-1","source":{"name":"debian"},"affects":[{"ref":"d"}]},
	  {"id":"CVE-2016-2781","source":{"name":"ubuntu"},"affects":[{"ref":"u"}]},
	  {"id":"CVE-2025-47912","source":{"name":"govulndb"},"affects":[{"ref":"g"}],
	   "advisories":[{"url":"https://go.dev/issue/75678"},{"url":"https://pkg.go.dev/vuln/GO-2025-4010"}]},
	  {"id":"CVE-2025-00001","source":{"name":"govulndb"},"affects":[{"ref":"g"}]},
	  {"id":"CVE-2025-00002","source":{"name":"ghsa"},"affects":[{"ref":"x"}]}]}`)
	var findings []artifact.Finding
	for _, id := range []string{"CVE-2025-10911", "CVE-2011-3374", "DSA-5990-1", "CVE-2016-2781",
		"CVE-2025-47912", "CVE-2025-00001", "CVE-2025-00002", "GHSA-only-grype"} {
		findings = append(findings, artifact.Finding{ID: id, Source: "trivy", Status: artifact.FindingStatusNotAffected})
	}
	out, err := artifact.AnnotateCycloneDX(doc, findings, time.Now())
	if err != nil {
		t.Fatalf("annotate: %v", err)
	}
	got := decode(t, out)

	for _, tc := range []struct{ was, id, source string }{
		{"CVE-2025-10911", "ALPINE-CVE-2025-10911", "OSV"},
		{"CVE-2011-3374", "DEBIAN-CVE-2011-3374", "OSV"},
		{"DSA-5990-1", "DSA-5990-1", "OSV"},
		{"CVE-2016-2781", "UBUNTU-CVE-2016-2781", "OSV"},
		{"CVE-2025-47912", "GO-2025-4010", "OSV"},
		// No ecosystem DT was checked against: left as trivy wrote it.
		{"CVE-2025-00001", "CVE-2025-00001", "govulndb"},
		{"CVE-2025-00002", "CVE-2025-00002", "ghsa"},
		// No affects: DT skips it whatever it is called.
		{"GHSA-only-grype", "GHSA-only-grype", "trivy"},
	} {
		v := vulnByID(t, got, tc.id)
		if s := v["source"].(map[string]any)["name"]; s != tc.source {
			t.Errorf("%s: source = %v, want %q", tc.id, s, tc.source)
		}
		if v["analysis"] == nil {
			t.Errorf("%s: analysis lost in the rename", tc.id)
		}
		refs, _ := v["references"].([]any)
		if tc.id == tc.was {
			if len(refs) != 0 && tc.source != "OSV" {
				t.Errorf("%s: untouched entry gained references %v", tc.id, refs)
			}
			continue
		}
		// What the scanner called it survives, source and all.
		if len(refs) != 1 || refs[0].(map[string]any)["id"] != tc.was {
			t.Errorf("%s: references = %v, want the original id %q", tc.id, refs, tc.was)
		}
	}
	if r := vulnByID(t, got, "ALPINE-CVE-2025-10911")["references"].([]any)[0].(map[string]any); r["source"].(map[string]any)["url"] != "https://secdb.alpinelinux.org/" {
		t.Errorf("original source not kept: %v", r)
	}
}
