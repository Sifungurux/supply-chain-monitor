package artifact

import "time"

// Type identifies what kind of thing an artifact is. Anything that can be
// packed into an OCI artifact is representable here: container images,
// arbitrary files, SBOMs, and SARIF scan results.
type Type string

const (
	TypeImage Type = "image"
	TypeFile  Type = "file"
	TypeSBOM  Type = "sbom"
	TypeSARIF Type = "sarif"
)

func (t Type) Valid() bool {
	switch t {
	case TypeImage, TypeFile, TypeSBOM, TypeSARIF:
		return true
	default:
		return false
	}
}

type Status string

const (
	StatusRegistered Status = "registered"
	StatusScanning   Status = "scanning"
	StatusScanned    Status = "scanned"
	StatusFailed     Status = "failed"
)

// FindingStatus values track whether a finding is still present as of
// the most recent scan/submission ("open") or was present before and
// has since disappeared from a report trusted to reflect a complete
// result for its bucket ("fixed") -- see MergeFindings in merge.go,
// which is the only place that ever sets this field. Findings are never
// deleted once seen: a "fixed" finding stays in its bucket, with
// ResolvedAt set, as a visible record of what used to be there and got
// fixed -- the same "keep history, don't overwrite it" instinct as
// StageHistory, just applied to findings.
const (
	FindingStatusOpen  = "open"
	FindingStatusFixed = "fixed"
)

// Finding is a single result from a scanner (a CVE, a malware signature
// match, etc.), normalized across scanner backends.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Source   string `json:"source"` // e.g. "trivy", "clamav"
	// Status, FirstSeenAt, and ResolvedAt are lifecycle metadata managed
	// entirely by MergeFindings (merge.go) -- never set directly by a
	// Scanner implementation or trusted from an external submitFindings
	// caller (MergeFindings always recomputes these three fields itself
	// before a finding is persisted, ignoring whatever a caller supplied
	// for them). A Scanner or external system only ever reports "here's
	// what I see right now"; whether that's brand new, still open, or
	// means something else on record just got fixed is a property of
	// comparing this round's report against what's already on record,
	// computed once in one place rather than duplicated everywhere a
	// finding gets produced.
	Status string `json:"status,omitempty"`
	// FirstSeenAt is when this finding was first reported for this
	// artifact. Not tagged omitempty -- encoding/json's omitempty never
	// omits struct-typed zero values (a well-known stdlib limitation),
	// so it wouldn't do anything here anyway; a real Finding always has
	// this set by MergeFindings before it's ever persisted or returned.
	FirstSeenAt time.Time `json:"first_seen_at"`
	// ResolvedAt is nil while Status is "open", and set to when
	// MergeFindings first observed this finding stop being reported
	// while Status is "fixed".
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// StageEvent records that an artifact was observed at a given pipeline
// step (source, build, test, scan, sign, publish, deploy, ...).
type StageEvent struct {
	Stage     string    `json:"stage"`
	Timestamp time.Time `json:"timestamp"`
	Note      string    `json:"note,omitempty"`
}

// Artifact is anything being tracked as it moves through the software
// supply chain: a container image, a build output, an SBOM, or a SARIF
// report, plus whatever CVE/malware findings and pipeline history have
// accumulated against it.
type Artifact struct {
	ID              string       `json:"id"`
	Ref             string       `json:"ref"` // OCI ref, file path/URI, or SBOM/SARIF location
	Type            Type         `json:"type"`
	Status          Status       `json:"status"`
	CurrentStage    string       `json:"current_stage,omitempty"`
	StageHistory    []StageEvent `json:"stage_history,omitempty"`
	CVEFindings     []Finding    `json:"cve_findings,omitempty"`
	MalwareFindings []Finding    `json:"malware_findings,omitempty"`
	// OtherFindings holds anything that's neither a CVE nor a malware
	// match -- currently just parsed SARIF results (SAST issues,
	// secrets, IaC misconfigurations, linting; see SARIFScanner). A
	// generic bucket rather than a SARIF-specific one since other
	// non-CVE/non-malware finding sources are plausible later.
	OtherFindings []Finding `json:"other_findings,omitempty"`
	// LastScanErrors holds any per-scanner errors from the most recent
	// /scan call (e.g. one of several scanners for a type failed while
	// others succeeded). Empty on a fully clean scan.
	LastScanErrors []string  `json:"last_scan_errors,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
