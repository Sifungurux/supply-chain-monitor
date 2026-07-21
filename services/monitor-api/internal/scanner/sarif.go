package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

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
// Findings land in Finding.Source == "sarif", which
// internal/api/handlers.go buckets into Artifact.OtherFindings rather
// than CVEFindings or MalwareFindings -- SARIF is a general-purpose
// format (SAST issues, secrets, IaC misconfigurations, linting), not
// specifically CVEs or malware, so folding it into either existing
// bucket would mislabel it.
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
// each run's rule metadata (for a human-readable title) and its
// results (the actual findings).
type sarifLog struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID               string `json:"id"`
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
						SecuritySeverity string `json:"security-severity"`
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
		for _, rule := range run.Tool.Driver.Rules {
			if rule.ShortDescription.Text != "" {
				descByRule[rule.ID] = rule.ShortDescription.Text
			}
			if sev, ok := severityFromSecuritySeverity(rule.Properties.SecuritySeverity); ok {
				severityByRule[rule.ID] = sev
			}
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
			findings = append(findings, artifact.Finding{
				ID:       id,
				Severity: severity,
				Title:    title,
				Source:   "sarif",
			})
		}
	}
	return findings, nil
}
