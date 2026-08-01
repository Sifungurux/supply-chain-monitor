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

	// Category is a transient bucket-routing hint a Scanner may set on
	// a finding it returns -- "cve", "malware", "misconfiguration",
	// "secret", or "other" (see internal/api/handlers.go's
	// classifyBucket). It exists because a single scan of a single
	// artifact can legitimately produce findings that belong in more
	// than one bucket (SARIFScanner is the reason this exists:
	// CodeQL/Semgrep/Checkov/Gitleaks/trivy's own --format sarif output
	// can all appear in one SARIF document, and a CVE result in there
	// belongs in cve_findings, not lumped in with a hardcoded-secret
	// result). Most Scanners (TrivyScanner, ClamAVScanner, ...) don't
	// need to set this at all -- handlers.go falls back to its old
	// Source-based heuristic when Category is empty, so existing
	// scanners are unaffected.
	//
	// Never persisted and never round-tripped through the API: json:"-"
	// is deliberate. Once a finding is placed into, say,
	// Artifact.SecretFindings, which slice/DB column it lives in
	// already records its category -- keeping Category on the exported
	// struct too would just be a second, potentially-stale copy of the
	// same fact for anything read back out of the store.
	Category string `json:"-"`
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
	ID  string `json:"id"`
	Ref string `json:"ref"` // OCI ref, file path/URI, or SBOM/SARIF location
	// Digest is the ref's resolved OCI content digest (e.g.
	// "sha256:..."), best-effort resolved at registration time via a
	// registry manifest call (see scanner.DigestResolver) -- empty if
	// resolution failed (unreachable/rate-limited registry, retagged or
	// missing ref) or wasn't attempted at all (ref is a local
	// filesystem path, not a registry reference; see
	// scanner.looksLikeLocalPath). Never required for an artifact to
	// exist: this is metadata for dedup and future use, not a
	// precondition for registration succeeding, the same "best-effort,
	// don't block on it" spirit as bulkCreateArtifacts's own per-entry
	// error handling.
	Digest string `json:"digest,omitempty"`
	// MaintainerTeam and MaintainerEmail identify who's responsible for
	// this artifact -- both empty until set, either at registration or
	// via POST .../maintainer. Always set or cleared together: a team
	// name with no way to reach them, or a contact address with no team
	// context, isn't meaningful ownership info, so internal/api/handlers.go's
	// validateMaintainerPair rejects one being set without the other.
	// Free text, not validated beyond that pairing -- this records
	// organizational ownership, not an auth identity.
	MaintainerTeam  string       `json:"maintainer_team,omitempty"`
	MaintainerEmail string       `json:"maintainer_email,omitempty"`
	Type            Type         `json:"type"`
	Status          Status       `json:"status"`
	CurrentStage    string       `json:"current_stage,omitempty"`
	StageHistory    []StageEvent `json:"stage_history,omitempty"`
	CVEFindings     []Finding    `json:"cve_findings,omitempty"`
	MalwareFindings []Finding    `json:"malware_findings,omitempty"`
	// MisconfigFindings and SecretFindings split two categories out of
	// what used to all land in OtherFindings -- IaC/configuration
	// issues and hardcoded secrets/credentials respectively, both
	// common, well-known-enough categories (and common enough in SARIF
	// output specifically -- see SARIFScanner's classifySarifCategory)
	// to deserve their own bucket rather than being folded into a
	// single generic "everything else." See docs/architecture.md
	// ("Classifying SARIF findings into their own buckets").
	MisconfigFindings []Finding `json:"misconfiguration_findings,omitempty"`
	SecretFindings    []Finding `json:"secret_findings,omitempty"`
	// OtherFindings holds anything that's neither a CVE, a malware
	// match, a misconfiguration, nor a secret -- SAST/code-quality
	// issues (CodeQL, Semgrep), license findings, linting, and anything
	// else a SARIF document might carry that doesn't fit the four more
	// specific buckets. A generic catch-all bucket rather than trying
	// to enumerate every possible category up front.
	OtherFindings []Finding `json:"other_findings,omitempty"`
	// LastScanErrors holds any per-scanner errors from the most recent
	// /scan call (e.g. one of several scanners for a type failed while
	// others succeeded). Empty on a fully clean scan.
	LastScanErrors []string `json:"last_scan_errors,omitempty"`
	// LastScanAt is when the /scan endpoint last completed for this
	// artifact -- nil until the first scan runs. Deliberately its own
	// field rather than reusing UpdatedAt: UpdatedAt also moves on
	// unrelated mutations (a /stage call, a digest backfill), so it
	// can't tell a caller "was this actually scanned recently" without
	// false positives from those other paths.
	LastScanAt *time.Time `json:"last_scan_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}
