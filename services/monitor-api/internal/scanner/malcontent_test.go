package scanner

import (
	"os"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// The fixture is real output, not hand-written:
//
//	mal --format json --min-risk medium scan --image alpine:3.19
//
// Worth knowing what that means -- a stock alpine, nobody's idea of a
// compromised image, produces four HIGH-risk behaviours. That is the
// evidence behind defaulting the chart's minRisk to "critical", and the
// reason this scanner's findings are not a like-for-like second opinion
// on ClamAV's.
func TestParseMalcontentReport_RealAlpineOutput(t *testing.T) {
	raw, err := os.ReadFile("testdata/malcontent_report_sample.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	findings, err := ParseMalcontentReport(raw)
	if err != nil {
		t.Fatalf("ParseMalcontentReport: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("findings = %+v, want 4 (one per distinct rule id, not one per file)", findings)
	}

	byID := make(map[string]artifact.Finding, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
		if f.Source != "malcontent" {
			t.Errorf("%s source = %q, want malcontent", f.ID, f.Source)
		}
		if f.Category != "malware" {
			t.Errorf("%s category = %q, want malware -- these belong in the same bucket as ClamAV's", f.ID, f.Category)
		}
		if f.Severity != "high" {
			t.Errorf("%s severity = %q, want high (every behaviour in the fixture is HIGH)", f.ID, f.Severity)
		}
	}

	// The rule id is the finding id: stable across scans, unlike a file
	// path, which changes whenever a layer does.
	busybox, ok := byID["exec/shell/busybox_exec"]
	if !ok {
		t.Fatalf("expected a finding keyed on the rule id, got %v", byID)
	}
	// That rule matched two files in the fixture -- one finding, with the
	// count in the title, not two findings.
	if busybox.Title != "small program that runs atypical busybox programs (2 files)" {
		t.Errorf("title = %q, want the description plus the file count", busybox.Title)
	}
	// A rule matching one file gets no count suffix.
	if got := byID["fs/proc/net_route"].Title; got != "gets network route information" {
		t.Errorf("single-file title = %q, want no count suffix", got)
	}
}

func TestParseMalcontentReport_SeverityMapping(t *testing.T) {
	tests := []struct {
		risk string
		want string
	}{
		{"CRITICAL", "critical"},
		{"HIGH", "high"},
		{"MEDIUM", "medium"},
		{"LOW", "low"},
		{"critical", "critical"},
		{" High ", "high"},
		// A level this parser has never seen must not be guessed upward:
		// "unknown" ranks 0 in both severity tables, so it can never trip
		// a notification threshold on its own.
		{"CATASTROPHIC", "unknown"},
		{"", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.risk, func(t *testing.T) {
			raw := []byte(`{"Files":{"/bin/x":{"Path":"/bin/x","Behaviors":[
				{"ID":"test/rule","Description":"d","RiskLevel":"` + tt.risk + `"}]}}}`)
			findings, err := ParseMalcontentReport(raw)
			if err != nil {
				t.Fatalf("ParseMalcontentReport: %v", err)
			}
			if len(findings) != 1 || findings[0].Severity != tt.want {
				t.Fatalf("findings = %+v, want severity %q", findings, tt.want)
			}
		})
	}
}

// One rule can match files at different risk levels; the finding shows
// the worst, so a critical hit is never hidden behind a medium one.
func TestParseMalcontentReport_WorstRiskWinsPerRule(t *testing.T) {
	raw := []byte(`{"Files":{
		"/a":{"Path":"/a","Behaviors":[{"ID":"r","Description":"d","RiskLevel":"MEDIUM"}]},
		"/b":{"Path":"/b","Behaviors":[{"ID":"r","Description":"d","RiskLevel":"CRITICAL"}]}}}`)

	findings, err := ParseMalcontentReport(raw)
	if err != nil {
		t.Fatalf("ParseMalcontentReport: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one per rule", findings)
	}
	if findings[0].Severity != "critical" {
		t.Fatalf("severity = %q, want the worst across matched files", findings[0].Severity)
	}
	if findings[0].Title != "d (2 files)" {
		t.Fatalf("title = %q", findings[0].Title)
	}
}

// Findings must come back in the same order for the same report --
// map iteration alone would reshuffle them between two scans of an
// unchanged image, which reads as churn on the dashboard.
func TestParseMalcontentReport_DeterministicOrder(t *testing.T) {
	raw := []byte(`{"Files":{
		"/a":{"Path":"/a","Behaviors":[
			{"ID":"low-one","Description":"d","RiskLevel":"LOW"},
			{"ID":"crit","Description":"d","RiskLevel":"CRITICAL"},
			{"ID":"low-two","Description":"d","RiskLevel":"LOW"}]}}}`)

	var first []string
	for i := 0; i < 5; i++ {
		findings, err := ParseMalcontentReport(raw)
		if err != nil {
			t.Fatalf("ParseMalcontentReport: %v", err)
		}
		ids := make([]string, 0, len(findings))
		for _, f := range findings {
			ids = append(ids, f.ID)
		}
		if i == 0 {
			first = ids
			continue
		}
		if len(ids) != len(first) {
			t.Fatalf("run %d returned %v, first run %v", i, ids, first)
		}
		for j := range ids {
			if ids[j] != first[j] {
				t.Fatalf("run %d order %v differs from %v", i, ids, first)
			}
		}
	}
	if first[0] != "crit" {
		t.Fatalf("order = %v, want the critical behaviour first", first)
	}
}

func TestParseMalcontentReport_EmptyAndInvalid(t *testing.T) {
	// A clean image: no Files at all. Not an error -- "nothing matched"
	// is the answer most scans should give.
	findings, err := ParseMalcontentReport([]byte(`{"Files":{}}`))
	if err != nil || len(findings) != 0 {
		t.Fatalf("clean report = %+v, %v, want no findings and no error", findings, err)
	}
	if _, err := ParseMalcontentReport([]byte("not json")); err == nil {
		t.Fatal("expected an error for non-JSON output")
	}
}

// Global flags precede the subcommand -- `mal [GLOBAL FLAGS] <command>`
// per the binary's own usage. Putting --format after `scan` parses
// differently and silently produces the wrong output format.
func TestMalcontentScanner_Args(t *testing.T) {
	got := NewMalcontentScanner("mal", "critical", "").args("alpine:3.19")
	want := []string{"--format", "json", "--min-risk", "critical", "scan", "--image", "alpine:3.19"}
	if len(got) != len(want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("args = %v, want %v", got, want)
		}
	}

	// No minRisk configured: the flag is omitted entirely rather than
	// passed empty, leaving the binary's own default.
	bare := NewMalcontentScanner("", "", "").args("alpine:3.19")
	for _, a := range bare {
		if a == "--min-risk" {
			t.Fatalf("args = %v, want no --min-risk when none is configured", bare)
		}
	}
}

func TestMalcontentScanner_BucketAffinity(t *testing.T) {
	var s any = NewMalcontentScanner("mal", "critical", "")
	ba, ok := s.(BucketAffinity)
	if !ok {
		t.Fatal("MalcontentScanner must declare a bucket, or a failure would block fix-detection for every bucket")
	}
	if ba.Bucket() != "malware" {
		t.Fatalf("bucket = %q, want malware", ba.Bucket())
	}
}

// The severity floor is ours, not the tool's. Measured against a real
// image, `mal --format json --min-risk {critical,high,any} scan --image
// alpine:3.19` returns byte-identical output every time -- the flag
// does not filter in scan mode. A chart default that reads like a
// filter and filters nothing is worse than no default at all, so the
// threshold is applied to the parsed findings here.
func TestFilterBySeverity(t *testing.T) {
	findings := []artifact.Finding{
		{ID: "crit", Severity: "critical"},
		{ID: "high", Severity: "high"},
		{ID: "med", Severity: "medium"},
		{ID: "none", Severity: ""},
	}

	tests := []struct {
		threshold string
		want      []string
	}{
		{"critical", []string{"crit"}},
		{"high", []string{"crit", "high"}},
		{"medium", []string{"crit", "high", "med"}},
		// Empty or unrecognized keeps everything: the safe direction for
		// a filter, and the same convention the scanner selectors use.
		{"", []string{"crit", "high", "med", "none"}},
		{"not-a-severity", []string{"crit", "high", "med", "none"}},
	}
	for _, tt := range tests {
		t.Run("threshold="+tt.threshold, func(t *testing.T) {
			got := FilterBySeverity(findings, tt.threshold)
			if len(got) != len(tt.want) {
				t.Fatalf("kept %+v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i].ID != tt.want[i] {
					t.Fatalf("kept %+v, want %v", got, tt.want)
				}
			}
		})
	}
}

// The live trial's own output, at the chart's default threshold: every
// behaviour a stock alpine reports is HIGH, so "critical" yields
// nothing -- which is what the default is FOR, and what it silently
// failed to do while the tool's flag was trusted to enforce it.
func TestFilterBySeverity_AlpineFixtureIsQuietAtCritical(t *testing.T) {
	raw, err := os.ReadFile("testdata/malcontent_report_sample.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	findings, err := ParseMalcontentReport(raw)
	if err != nil {
		t.Fatalf("ParseMalcontentReport: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("fixture should produce findings before filtering")
	}
	if kept := FilterBySeverity(findings, "critical"); len(kept) != 0 {
		t.Fatalf("kept %+v at threshold critical, want none -- a stock alpine must not grow malware findings by default", kept)
	}
	if kept := FilterBySeverity(findings, "high"); len(kept) != len(findings) {
		t.Fatalf("kept %d of %d at threshold high, want all", len(kept), len(findings))
	}
}
