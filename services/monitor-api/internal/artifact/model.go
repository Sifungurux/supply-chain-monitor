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

// Finding is a single result from a scanner (a CVE, a malware signature
// match, etc.), normalized across scanner backends.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Source   string `json:"source"` // e.g. "trivy", "clamav"
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
