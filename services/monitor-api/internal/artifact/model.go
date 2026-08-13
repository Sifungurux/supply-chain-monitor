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
// FindingStatusNotAffected is the third value, and the only one a
// scan never produces on its own: it means a human (or a build system
// speaking for one) asserted via a VEX document that this artifact is
// not affected by this vulnerability even though a scanner keeps
// reporting it -- the vulnerable code path isn't reachable, the
// component isn't actually included, and so on. Suppressed rather than
// deleted, exactly like "fixed": the finding stays in its bucket with
// the VEX justification attached, out of the counts but still visible
// with a badge on the detail page.
const (
	FindingStatusOpen        = "open"
	FindingStatusFixed       = "fixed"
	FindingStatusNotAffected = "not_affected"
)

// Finding is a single result from a scanner (a CVE, a malware signature
// match, etc.), normalized across scanner backends.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Source   string `json:"source"` // e.g. "trivy", "clamav"
	// Status, FirstSeenAt, ResolvedAt, and Justification are lifecycle
	// metadata managed entirely by MergeFindings (merge.go) -- never set
	// directly by a Scanner implementation or trusted from an external
	// submitFindings caller (MergeFindings always recomputes these four fields itself
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
	// Justification is the VEX statement's own reason for suppressing
	// this finding (e.g. "vulnerable_code_not_in_execute_path") --
	// empty on every finding no VEX document has spoken about, which is
	// most of them. Managed by MergeFindings alongside the three
	// lifecycle fields above and never trusted from a caller for the
	// same reason: it's the *record* of why something was suppressed,
	// so letting a submitFindings caller write it directly would let
	// anything invent a justification for a finding nobody ever
	// assessed.
	Justification string `json:"justification,omitempty"`

	// Category is a transient bucket-routing hint a Scanner may set on
	// a finding it returns -- "cve", "malware", "misconfiguration",
	// "secret", or "other" (see internal/api/scan.go's
	// classifyBucket). It exists because a single scan of a single
	// artifact can legitimately produce findings that belong in more
	// than one bucket (SARIFScanner is the reason this exists:
	// CodeQL/Semgrep/Checkov/Gitleaks/trivy's own --format sarif output
	// can all appear in one SARIF document, and a CVE result in there
	// belongs in cve_findings, not lumped in with a hardcoded-secret
	// result). Most Scanners (TrivyScanner, ClamAVScanner, ...) don't
	// need to set this at all -- classifyBucket (internal/api/scan.go)
	// falls back to its old Source-based heuristic when Category is empty, so existing
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
	// Unsafe is set at registration time when REQUIRE_DIGEST is enabled
	// (monitorApi.requireDigest) and the caller-provided expected_digest
	// didn't match what actually resolved against the registry -- or
	// nothing resolved at all. Unlike expected_digest's own per-request,
	// opt-in pin (which refuses registration outright on a mismatch, see
	// checkExpectedDigest), REQUIRE_DIGEST is a deployment-wide policy
	// that still registers the artifact -- refusing every unverifiable
	// registration outright would be too disruptive to turn on for an
	// existing pipeline that doesn't yet know about it. Marking it
	// unsafe instead keeps registration itself non-blocking while giving
	// a real, visible signal (the dashboard/API caller decides what to
	// do with it) instead of silently registering an unverified artifact
	// the same as a verified one. Never set any other way -- a scan
	// backfilling a missing digest (see scanArtifact) never touches this
	// field, since that's a different concern (an artifact scanned after
	// registration, not one whose registration-time claim didn't check
	// out).
	Unsafe bool `json:"unsafe,omitempty"`
	// MaintainerTeam and MaintainerEmail identify who's responsible for
	// this artifact -- both empty until set, either at registration or
	// via POST .../maintainer. Always set or cleared together: a team
	// name with no way to reach them, or a contact address with no team
	// context, isn't meaningful ownership info, so internal/api/artifacts.go's
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
	// LastScanErrors holds a friendly, classified message per failed
	// scanner from the most recent /scan call (e.g. one of several
	// scanners for a type failed while others succeeded) -- never the
	// scanner's raw error text, see scanner.ClassifyScanError. Empty on
	// a fully clean scan.
	LastScanErrors []string `json:"last_scan_errors,omitempty"`
	// LastScanFailureReason is a short, stable reason code (e.g.
	// "not_found", "scan_timeout") set only when every scanner failed
	// this round (Status == StatusFailed) -- see
	// scanner.ClassifyScanError for the full set of codes. Cleared on
	// the next scan that isn't a total failure.
	LastScanFailureReason string `json:"last_scan_failure_reason,omitempty"`
	// LastScanAt is when the /scan endpoint last completed for this
	// artifact -- nil until the first scan runs. Deliberately its own
	// field rather than reusing UpdatedAt: UpdatedAt also moves on
	// unrelated mutations (a /stage call, a digest backfill), so it
	// can't tell a caller "was this actually scanned recently" without
	// false positives from those other paths.
	LastScanAt *time.Time `json:"last_scan_at,omitempty"`
	// HasSBOM/HasSARIF report whether a generated document of that kind
	// exists for this artifact (see Document, Store.SaveDocument/
	// GetDocument) -- booleans, not the document bytes themselves, so
	// List() (which the dashboard polls every 10s) never carries
	// megabytes of document content just to let the UI decide whether a
	// download button should show. Best-effort like Digest: false just
	// means no document has been captured yet, not an error.
	HasSBOM   bool      `json:"has_sbom,omitempty"`
	HasSARIF  bool      `json:"has_sarif,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Document kinds -- the only two Store.SaveDocument/GetDocument accept
// today (see internal/api/documents.go's validDocumentKind). Kept as constants so
// a typo is a compile error rather than a silently-never-matching kind
// string somewhere.
const (
	DocumentKindSBOM  = "sbom"
	DocumentKindSARIF = "sarif"
	// DocumentKindVEX is stored through the same Store.SaveDocument call
	// as the other two, but is deliberately NOT accepted by the generic
	// documents endpoint (validDocumentKind still lists only sbom/sarif)
	// -- a VEX document is parsed and applied to this artifact's findings
	// when it's uploaded, so it has its own endpoint that does that (see
	// internal/api/vex.go) rather than a second way in that would store
	// the bytes and silently change nothing.
	DocumentKindVEX = "vex"
)

// Component is one entry from an ingested SBOM's component inventory --
// a package this artifact contains. Deliberately its own type/table
// rather than a field on Artifact, for the same reason Document is (see
// its comment): a real image's SBOM lists hundreds to thousands of
// these, and Artifact is round-tripped whole on every List() call the
// dashboard polls every 10 seconds.
//
// PURL (a Package URL, e.g. "pkg:apk/alpine/openssl@3.1.4-r5") is the
// identity that matters here: it's what makes "which of our artifacts
// contain this exact package" answerable across ecosystems, and it's
// the indexed column Store.FindByComponentPURL queries. Name and
// Version are carried alongside for display -- both are derivable from
// a purl, but not without parsing one, and this way the API answer
// reads without a client having to.
type Component struct {
	PURL    string `json:"purl"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// ComponentMatch is one distinct package found by a component search
// (Store.SearchComponents), with how many artifacts contain it --
// deliberately not a Component, which is a per-artifact row and has no
// business carrying a fleet-wide count. This is the discovery half of
// component search: "openssl" finds the handful of purls that exist,
// each with the weight to judge which one you meant, and the purl you
// pick then goes to FindByComponentPURL for the exact answer.
type ComponentMatch struct {
	PURL    string `json:"purl"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	// Artifacts is the number of DISTINCT artifacts containing this
	// purl. The same purl has one row per artifact, so this is a count
	// of rows only by coincidence of the unique constraint -- counted
	// distinctly anyway, so it stays correct if that ever changes.
	Artifacts int `json:"artifacts"`
}

// VEXStatement is one VEX statement reduced to what merging a finding
// needs: which vulnerability it speaks about, what it asserts, and why.
// Lives here rather than in internal/scanner (which does the actual
// OpenVEX/CycloneDX parsing, see scanner.ParseVEX) because MergeFindings
// consumes it and internal/scanner already imports this package -- the
// other direction would be an import cycle.
type VEXStatement struct {
	// VulnID matches Finding.ID (e.g. "CVE-2024-1234"). A statement
	// about a vulnerability this artifact has no finding for is simply
	// never consulted.
	VulnID string
	// Status is the VEX status verbatim: "not_affected", "affected",
	// "fixed", or "under_investigation". Only not_affected and fixed
	// change a finding (see MergeFindings) -- "affected" is what a
	// reported finding already means, and "under_investigation" is an
	// explicit statement that nobody has decided yet, which is not a
	// reason to hide anything.
	Status string
	// Justification is free text from the document (OpenVEX's
	// `justification`/`impact_statement`, CycloneDX's
	// `analysis.justification`/`detail`). Empty is normal and fine --
	// OpenVEX only requires a justification for not_affected, and
	// plenty of real documents omit it anyway.
	Justification string
}

// The two VEX statuses that aren't also finding statuses. Constants
// because both this package (MergeFindings) and internal/scanner
// (ParseVEX's normalizeVEXStatus) compare against them, and a typo in
// one of the two would silently mean "unrecognized status, no opinion"
// rather than failing anywhere.
const (
	// VEXStatusAffected is the one non-suppressing status that still
	// does something: it revokes an earlier not_affected on the same
	// vulnerability (see MergeFindings). Without that, a corrected
	// assessment would be a silent no-op -- suppression could be applied
	// but never taken back.
	VEXStatusAffected = "affected"
	// VEXStatusUnderInvestigation changes nothing at all: "nobody has
	// decided yet" is not a reason to hide a finding, nor to un-hide one
	// somebody already assessed.
	VEXStatusUnderInvestigation = "under_investigation"
)

// VEXByID indexes statements by vulnerability ID for MergeFindings.
// Last statement wins on a duplicate ID: a document that says two
// things about one vulnerability is self-contradictory, and picking the
// later one matches how every other "current state" field in this
// service behaves (a re-uploaded document replaces the previous one
// wholesale).
func VEXByID(statements []VEXStatement) map[string]VEXStatement {
	if len(statements) == 0 {
		return nil
	}
	byID := make(map[string]VEXStatement, len(statements))
	for _, s := range statements {
		byID[s.VulnID] = s
	}
	return byID
}

// Document is a generated artifact document -- a CycloneDX SBOM or
// SARIF report derived from an image scan (see
// scanner.GenerateImageDocuments) -- stored separately from Artifact
// itself. Deliberately its own type/table rather than fields on
// Artifact: these can be multi-megabyte blobs (a real-world image's
// CycloneDX SBOM or SARIF report commonly runs 10-20MB), and Artifact
// is round-tripped whole on every List() call the dashboard polls every
// 10 seconds, plus scanned end-to-end by the dashboard's client-side
// search filter -- putting document bytes directly on the struct would
// drag megabytes through both paths for every artifact on every poll,
// whether or not anyone ever downloads one. See HasSBOM/HasSARIF above
// for the lightweight signal Artifact does carry.
type Document struct {
	ArtifactID  string
	Kind        string // DocumentKindSBOM or DocumentKindSARIF
	ContentType string
	Content     []byte
	CreatedAt   time.Time
}
