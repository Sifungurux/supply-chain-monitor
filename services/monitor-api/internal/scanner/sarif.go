package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// SARIFScanner doesn't scan anything itself -- a SARIF (Static
// Analysis Results Interchange Format) document already IS a set of
// findings, produced by whatever tool generated it (CodeQL, Semgrep,
// even trivy's own --format sarif output). Its job is just to parse
// that file and expose the results it already contains, rather than
// re-running any analysis. See docs/architecture.md ("SARIF is parsed,
// not re-scanned").
//
// A single SARIF document can legitimately mix categories -- a CVE
// from trivy's own SARIF output, a hardcoded secret from Gitleaks, an
// IaC misconfiguration from Checkov, a SAST finding from CodeQL, all
// in one file. classifySarifCategory below inspects each result's
// rule name/ID/tags and sets Finding.Category accordingly, so
// internal/api/handlers.go's classifyBucket can route each finding
// into the bucket it actually belongs in (cve/misconfiguration/
// secret/other) instead of lumping everything under Source == "sarif"
// into OtherFindings. See docs/architecture.md ("Classifying SARIF
// findings into their own buckets").
//
// v1 stub: ref is assumed to already be a filesystem path reachable
// inside the monitor-api pod -- the same simplification `file`-type
// artifacts already make (see ClamAVScanner and docs/architecture.md's
// Roadmap).
type SARIFScanner struct{}

func NewSARIFScanner() *SARIFScanner {
	return &SARIFScanner{}
}

// sarifLog is the small subset of the SARIF 2.1.0 schema this needs:
// each run's rule metadata (for a human-readable title, a category
// classification hint, and severity) and its results (the actual
// findings).
type sarifLog struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID               string `json:"id"`
					// Name is a rule's short symbolic name, distinct
					// from ID. Trivy's own SARIF output (see
					// pkg/report/sarif.go's toSarifRuleName) sets this
					// to one of a small fixed set of values --
					// "OsPackageVulnerability",
					// "LanguageSpecificPackageVulnerability",
					// "Misconfiguration", "Secret", "License" --
					// exactly the category classification this
					// exists to recover. Other tools may not set it
					// at all, hence the fallbacks in
					// classifySarifCategory below.
					Name             string `json:"name"`
					ShortDescription struct {
						Text string `json:"text"`
					} `json:"shortDescription"`
					// Properties.SecuritySeverity is a de facto
					// convention (used by CodeQL, Trivy's own SARIF
					// output, and others, though not part of the core
					// SARIF 2.1.0 spec) carrying a CVSS-like 0-10
					// score. Preferred over Level below when present,
					// since it's far more precise than SARIF's own
					// three-level scale.
					Properties struct {
						SecuritySeverity string   `json:"security-severity"`
						Tags             []string `json:"tags"`
					} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
		} `json:"results"`
	} `json:"runs"`
}

// cveIDPattern matches a CVE identifier shape (CVE-YYYY-NNNN...),
// case-insensitively, wherever it appears in a rule ID -- e.g. trivy's
// own rule IDs are bare CVE numbers, but other scanners sometimes
// prefix/suffix them (e.g. "go/CVE-2023-1234").
var cveIDPattern = regexp.MustCompile(`(?i)cve-\d{4}-\d+`)

// classifySarifCategory decides which finding bucket a SARIF result
// belongs in: "cve", "misconfiguration", "secret", or "other" (never
// "malware" -- SARIF is a static-analysis format, not a signature
// scanner, so that bucket doesn't apply here). It tries progressively
// weaker signals, in order of how much they're worth trusting:
//
//  1. Trivy's own SARIF rule-name convention (toSarifRuleName in
//     trivy's pkg/report/sarif.go) -- an exact match, when present,
//     since it's a tool telling us directly what kind of result this
//     is rather than us guessing from text.
//  2. A CVE-ID-shaped rule ID -- tool-agnostic, since plenty of
//     scanners besides trivy use bare or prefixed CVE numbers as
//     their rule ID for vulnerability findings.
//  3. Tag keywords -- SARIF's own spec says tags shouldn't be used
//     for classification (a taxonomy should be used instead), but in
//     practice almost no tool follows that, and tags remain the most
//     common cross-tool signal available (e.g. Semgrep's
//     "OWASP-A05:2021-Security Misconfiguration", Gitleaks-style
//     "secret"/"credentials" tags).
//
// Anything that matches none of these falls back to "other", the
// same catch-all it would have landed in before this classifier
// existed -- this function only ever adds precision, never loses a
// finding.
func classifySarifCategory(ruleID, ruleName string, tags []string) string {
	switch ruleName {
	case "OsPackageVulnerability", "LanguageSpecificPackageVulnerability":
		return "cve"
	case "Misconfiguration":
		return "misconfiguration"
	case "Secret":
		return "secret"
	case "License":
		return "other"
	}

	if cveIDPattern.MatchString(ruleID) {
		return "cve"
	}

	for _, tag := range tags {
		lower := strings.ToLower(tag)
		switch {
		case strings.Contains(lower, "secret"), strings.Contains(lower, "credential"):
			return "secret"
		case strings.Contains(lower, "misconfig"), strings.Contains(lower, "iac"), strings.Contains(lower, "compliance"):
			return "misconfiguration"
		case strings.Contains(lower, "cve"), strings.Contains(lower, "vulnerab"):
			return "cve"
		}
	}

	return "other"
}

// severityFromSecuritySeverity converts a rule's numeric
// security-severity property (e.g. "9.8") into the same low/medium/
// high/critical vocabulary trivy findings use. Returns ok=false if raw
// is empty or not a number, so the caller can fall back to
// sarifLevelToSeverity.
func severityFromSecuritySeverity(raw string) (severity string, ok bool) {
	score, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return "", false
	}
	switch {
	case score >= 9.0:
		return "critical", true
	case score >= 7.0:
		return "high", true
	case score >= 4.0:
		return "medium", true
	default:
		return "low", true
	}
}

// sarifLevelToSeverity maps SARIF's "level" -- a diagnostic severity
// (error/warning/note/none, defaulting to "warning" per the SARIF
// spec when absent) -- onto the same rough low/medium/high vocabulary
// trivy findings use, since the dashboard renders both buckets with
// the same severity styling. Used as a fallback when a rule doesn't
// carry a security-severity score (see above). SARIF's own scale has
// no notion of "critical"; there just isn't a level that maps there.
func sarifLevelToSeverity(level string) string {
	switch level {
	case "error":
		return "high"
	case "warning", "":
		return "medium"
	case "note":
		return "low"
	default:
		return "unknown"
	}
}

func (s *SARIFScanner) Scan(_ context.Context, ref string) ([]artifact.Finding, error) {
	raw, err := os.ReadFile(ref)
	if err != nil {
		return nil, fmt.Errorf("read sarif file %q: %w", ref, err)
	}

	var log sarifLog
	if err := json.Unmarshal(raw, &log); err != nil {
		return nil, fmt.Errorf("parse sarif file %q: %w", ref, err)
	}

	var findings []artifact.Finding
	for _, run := range log.Runs {
		descByRule := make(map[string]string, len(run.Tool.Driver.Rules))
		severityByRule := make(map[string]string, len(run.Tool.Driver.Rules))
		nameByRule := make(map[string]string, len(run.Tool.Driver.Rules))
		tagsByRule := make(map[string][]string, len(run.Tool.Driver.Rules))
		for _, rule := range run.Tool.Driver.Rules {
			if rule.ShortDescription.Text != "" {
				descByRule[rule.ID] = rule.ShortDescription.Text
			}
			if sev, ok := severityFromSecuritySeverity(rule.Properties.SecuritySeverity); ok {
				severityByRule[rule.ID] = sev
			}
			nameByRule[rule.ID] = rule.Name
			tagsByRule[rule.ID] = rule.Properties.Tags
		}

		for _, result := range run.Results {
			title := result.Message.Text
			if desc, ok := descByRule[result.RuleID]; ok {
				title = desc
			}
			id := result.RuleID
			if id == "" {
				id = "sarif-finding"
			}
			severity, ok := severityByRule[result.RuleID]
			if !ok {
				severity = sarifLevelToSeverity(result.Level)
			}
			category := classifySarifCategory(result.RuleID, nameByRule[result.RuleID], tagsByRule[result.RuleID])
			findings = append(findings, artifact.Finding{
				ID:       id,
				Severity: severity,
				Title:    title,
				Source:   "sarif",
				Category: category,
			})
		}
	}
	return findings, nil
}
