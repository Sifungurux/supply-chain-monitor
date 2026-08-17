// Package notify delivers "a scan just introduced new findings" events
// to outbound destinations (a generic webhook, Slack). It is deliberately
// one-way and best-effort: nothing here is allowed to affect whether a
// scan succeeds -- see the call site in internal/api/scan.go's runScan.
package notify

import (
	"context"
	"strings"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// Notifier delivers one ScanEvent somewhere. Implementations must be
// safe to call concurrently.
//
// Notify returns an error so failures are testable and loggable, NOT so
// callers can act on them: a notification is not part of a scan's
// result, and the one production call site (runScan) logs and discards
// whatever comes back. A broken webhook must never turn a good scan
// into a failed one.
type Notifier interface {
	Notify(ctx context.Context, event ScanEvent) error
}

// ScanEvent is what gets delivered: which artifact, and what is newly
// wrong with it. Only findings genuinely new in this scan round are
// included -- see internal/api/scan.go for how "new" is determined
// (FirstSeenAt stamped with this round's timestamp by MergeFindings,
// which is the only place that decides it).
type ScanEvent struct {
	ArtifactID  string             `json:"artifact_id"`
	ArtifactRef string             `json:"artifact_ref"`
	NewFindings []artifact.Finding `json:"new_findings"`
	// Severity is the worst severity among NewFindings, in that
	// finding's own spelling (see severityRank on why the spelling
	// varies).
	Severity string `json:"severity"`
	// KnownExploitedCount is how many of NewFindings are in CISA's KEV
	// catalogue. The findings themselves already carry the flag (it is
	// a field on artifact.Finding), but a notifier should not have to
	// re-derive the one fact that decides whether this page is worth
	// waking someone for -- exploitation OBSERVED beats any predicted
	// severity, and it is what a message should lead with.
	KnownExploitedCount int `json:"known_exploited_count"`
}

// CountKnownExploited returns how many findings are in the KEV
// catalogue. Exported so the caller building a ScanEvent and any
// notifier agree on the count rather than each counting differently.
func CountKnownExploited(findings []artifact.Finding) int {
	n := 0
	for _, f := range findings {
		if f.KnownExploited {
			n++
		}
	}
	return n
}

// Severity ranking. Higher is worse; 0 means "unrecognized", which is
// below every real level and so never satisfies a threshold.
//
// Case-insensitive and multi-vocabulary on purpose, because scanners do
// not agree: trivy emits CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN, grype emits
// Critical/High/Medium/Low/Negligible/Unknown, and ClamAV findings are
// written "critical" in this codebase. All three land in the same
// findings table, so a comparison that assumed one spelling would
// silently never match the others -- e.g. NOTIFY_MIN_SEVERITY=high would
// ignore every grype "High" while matching every trivy "HIGH".
var severityRank = map[string]int{
	"critical":   5,
	"high":       4,
	"medium":     3,
	"low":        2,
	"negligible": 1,
	"unknown":    0,
}

// DefaultMinSeverity is the threshold used when none is configured:
// loud enough to be worth an out-of-hours page, quiet enough that a
// routine base-image bump doesn't send one. Every image scanned in this
// project's load tests carries medium/low findings by the hundred.
const DefaultMinSeverity = "high"

// SeverityRank returns the rank of a severity string, 0 if unrecognized.
func SeverityRank(severity string) int {
	return severityRank[strings.ToLower(strings.TrimSpace(severity))]
}

// ValidSeverity reports whether s names a real threshold level -- used
// by main.go to reject a misconfigured NOTIFY_MIN_SEVERITY at startup
// rather than silently notifying on everything or nothing.
func ValidSeverity(s string) bool {
	_, ok := severityRank[strings.ToLower(strings.TrimSpace(s))]
	return ok
}

// AtOrAbove reports whether severity meets threshold. An unrecognized
// severity (rank 0) only passes a threshold of "unknown", so a finding
// a scanner couldn't rate never trips a "high" alert on its own.
func AtOrAbove(severity, threshold string) bool {
	return SeverityRank(severity) >= SeverityRank(threshold)
}

// Worst returns the highest-ranked severity string among findings, in
// the spelling the finding itself used. Empty for no findings.
func Worst(findings []artifact.Finding) string {
	worst, rank := "", -1
	for _, f := range findings {
		if r := SeverityRank(f.Severity); r > rank {
			worst, rank = f.Severity, r
		}
	}
	return worst
}
