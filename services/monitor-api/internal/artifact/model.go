package artifact

import (
	"sort"
	"strings"
	"time"
)

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

	// AcceptedUntil, AcceptedBy and AcceptanceReason record a RISK
	// ACCEPTANCE: "yes, this is real, and we are choosing to live with it
	// until <date>." Distinct from a VEX "not_affected", which asserts
	// the finding does not apply here at all -- an acceptance concedes
	// that it does, which is why it EXPIRES and a VEX statement does not.
	// A suppression with no end date is how a known vulnerability quietly
	// becomes permanent; this one comes back on its own.
	//
	// nil AcceptedUntil is the overwhelmingly common case: no acceptance
	// has ever been recorded for this finding. A non-nil one in the PAST
	// is deliberately left in place rather than cleared -- the same
	// "keep history, don't overwrite it" instinct as ResolvedAt, so the
	// record of who accepted what, and until when, survives the expiry
	// that made the finding active again. See Accepted, which is what
	// every consumer asks instead of reading the field directly.
	//
	// Written only by POST/DELETE .../findings/{findingID}/acceptance
	// (internal/api/findings.go) and carried across merges by
	// MergeFindings, never trusted from a reported finding -- exactly
	// like Justification, and for a sharper version of the same reason:
	// submitFindings decodes findings straight from caller JSON, so a
	// caller that could set these would be able to accept the risk of its
	// own findings, which is the one thing this endpoint's admin scope
	// exists to prevent.
	AcceptedUntil *time.Time `json:"accepted_until,omitempty"`
	// AcceptedBy is the authenticated client name that recorded the
	// acceptance (ClientFromContext), never anything the request body
	// supplied -- an accountability record nobody can self-attribute.
	AcceptedBy string `json:"accepted_by,omitempty"`
	// AcceptanceReason is why, in the accepter's own words. Required by
	// the endpoint: an acceptance with no stated reason is indis-
	// tinguishable from a finding somebody silently hid.
	AcceptanceReason string `json:"acceptance_reason,omitempty"`

	// EPSSScore is FIRST's Exploit Prediction Scoring System value for
	// this CVE: the probability (0..1) that it will be exploited in the
	// wild in the next 30 days. 0 means "no score", which is NOT the
	// same as "0% chance" -- see EnrichmentStatus for why the
	// difference matters and how a caller tells them apart.
	//
	// Set by enrichment at scan time (internal/scanner's Enricher), not
	// by any scanner, and never trusted from an external submitFindings
	// caller for the same reason Status and Justification are not: it
	// is a derived fact about the CVE, not an observation about this
	// artifact, so letting a caller assert it would let anything mark
	// its own findings unexploitable.
	EPSSScore float64 `json:"epss_score,omitempty"`
	// KnownExploited is true when this CVE is in CISA's Known Exploited
	// Vulnerabilities catalog -- i.e. exploitation has been OBSERVED,
	// not predicted. It outranks severity and EPSS for triage: a
	// medium-severity CVE with a working exploit in the wild is a more
	// urgent problem than a critical nobody has ever exploited.
	//
	// Same provenance rules as EPSSScore.
	KnownExploited bool `json:"known_exploited,omitempty"`

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
	// SourceRef records where this artifact ORIGINALLY came from, once
	// Ref has been rewritten to point at the in-cluster registry.
	//
	// When artifact mirroring is on (MIRROR_ARTIFACTS, see
	// scanner.OrasMirror), registration copies the artifact into
	// scm-registry and rewrites Ref to the local copy, so every
	// subsequent scan pulls from the cluster's own registry instead of
	// docker.io/ghcr.io -- no rate limits, no dependency on the upstream
	// tag still existing, and the bytes that were scanned are the bytes
	// that were kept. SourceRef is the note of what that local copy is a
	// copy OF, which is otherwise unrecoverable once Ref is rewritten.
	//
	// Empty means Ref is still the original: mirroring is off, the copy
	// hasn't happened yet (bulk registration defers it to the first
	// scan), or the ref was never a registry reference in the first
	// place. Ref and SourceRef are always written in ONE Update -- a
	// half-applied rewrite would leave a local ref with no record of its
	// origin, and there is no way back from that.
	//
	// Also what signature verification runs against: see
	// internal/api/scan.go's provenanceRef.
	SourceRef string `json:"source_ref,omitempty"`
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
	// scanner's raw error text, see scanner.ClassifyScanError. Holds the
	// LAST failure, which survives later successful scans -- see
	// LastScanErrorAt. Empty only until the artifact's first failure.
	LastScanErrors []string `json:"last_scan_errors,omitempty"`
	// LastScanErrorAt is when the errors currently held in
	// LastScanErrors were recorded. Deliberately NOT cleared by a later
	// clean scan: a scanner that failed once and has worked since is
	// still something an operator needs to see, and wiping the record
	// on success meant the only evidence disappeared exactly when
	// somebody might have gone looking for it. Compare against
	// LastScanAt to tell "failing now" from "failed then, fine since"
	// -- LastScanAt later than this means the artifact has recovered.
	LastScanErrorAt *time.Time `json:"last_scan_error_at,omitempty"`
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
	// Provenance is what signature verification concluded, and it is a
	// FIELD rather than the absence of a finding for one reason: a
	// verified image produces no finding (a finding per signed image
	// would bury the unsigned ones), so without this "signed" is
	// indistinguishable from "cosign is switched off" and from "never
	// scanned since it was switched on". Those three need to look
	// different -- reading a blank as "verified" is an all-clear
	// nobody earned.
	//
	// One of ProvenanceUnknown/Verified/Unsigned/Unverified.
	Provenance string `json:"provenance,omitempty"`
	// ProvenanceCheckedAt is when that conclusion was reached, so a
	// stale "verified" from before an image was retagged is visible as
	// stale rather than current.
	ProvenanceCheckedAt *time.Time `json:"provenance_checked_at,omitempty"`
	// ProvenanceTrustRoot names WHICH Sigstore judged it -- public, or
	// a specific private deployment. "Verified" against the public
	// instance and "verified" against your own mean different things,
	// and a UI that showed one badge for both would be asserting
	// something it cannot support.
	ProvenanceTrustRoot string `json:"provenance_trust_root,omitempty"`

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
	// Licenses is the package's license identifiers, comma-joined --
	// "MIT" or "MIT,Apache-2.0". SPDX ids where the document gave one,
	// otherwise whatever free-text name or SPDX expression it carried
	// (see scanner.ParseSBOMComponents). Empty is extremely common and
	// means "this SBOM said nothing usable", not "unlicensed": SPDX's
	// NOASSERTION/NONE placeholders are dropped rather than stored.
	//
	// A single string rather than a slice because it is one column, one
	// filter (?license=) and one dashboard cell -- nothing in this
	// service asks a question that needs them individually addressable,
	// and a join table for a display field would be its own migration.
	Licenses string `json:"licenses,omitempty"`
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
	// Licenses for the same representative row Name/Version come from
	// -- see SearchComponents' DISTINCT ON.
	Licenses string `json:"licenses,omitempty"`
	// Artifacts is the number of DISTINCT artifacts containing this
	// purl. The same purl has one row per artifact, so this is a count
	// of rows only by coincidence of the unique constraint -- counted
	// distinctly anyway, so it stays correct if that ever changes.
	Artifacts int `json:"artifacts"`
}

// GlobalScanSlotKind is the pseudo-kind the process-wide scan cap
// (SCAN_CONCURRENCY) is counted under, so one mechanism serves both it
// and the per-scanner caps instead of two that can disagree. Never a
// real scanner's kind -- Scanner.Kind() values are names like "trivy".
const GlobalScanSlotKind = "*"

// ScanSlotRequest asks for one slot per named kind, all or nothing.
//
// All-or-nothing because a scan runs its scanners concurrently and is
// accepted or rejected as a unit: holding three of four slots while
// waiting for the fourth would be a queue, and this deliberately has
// none (see internal/api's scanArtifact -- nobody is blocked on the
// response, so a saturated cap answers 429 rather than backlogging work
// a pod restart would silently drop).
type ScanSlotRequest struct {
	// HolderID is unique per scan and tags every row this acquires, so
	// ReleaseScanSlots can free exactly these and nothing else.
	HolderID string
	// Kinds is what to take, typically GlobalScanSlotKind plus each
	// distinct scanner kind the scan will run. Duplicates are ignored.
	Kinds []string
	// Caps is kind -> maximum concurrent holders. A kind absent from
	// this map, or mapped to <= 0, is UNLIMITED -- the same "a
	// nonsensical zero-or-negative value reads as off" convention
	// rate limiting and the artifact quota already use.
	Caps map[string]int
	// StaleAfter is how old a slot must be before it is treated as
	// abandoned and reaped. See scanSlotReapMargin in main.go for why
	// this has to sit above the scan timeout and below the sweep's own
	// artifact reclamation.
	StaleAfter time.Duration
}

// ScanSlotResult reports whether the slots were taken, and if not,
// which cap refused -- the 429 says "malcontent" rather than just
// "concurrency limit", which is the difference between an operator
// raising the right knob and guessing.
type ScanSlotResult struct {
	Acquired bool
	// BlockedKind is the first kind at its cap. Empty when Acquired.
	BlockedKind string
	// BlockedCap is that kind's configured cap, for the message.
	BlockedCap int
}

// LicenseFindingSource is the Source every denylisted-license finding
// carries, and the key that partitions the "other" bucket between the
// license evaluator and the scanners that also write there -- see
// MergePartition, which is what keeps the two from resolving each
// other's findings.
const LicenseFindingSource = "license"

// LicenseFindingID is the finding ID for a denylisted license on one
// package: "license:" plus the package identity, VERSION STRIPPED
// (purlCoordinates) -- "license:pkg:npm/foo", never
// "license:pkg:npm/foo@1.2.3".
//
// This started out keyed on the full purl, justified as "a new release
// is one nobody re-assessed". That justification does not survive
// contact with how the evaluation actually works: LicenseDenylist
// re-derives findings from the current inventory on every index, with
// no human in the loop, so a package that relicenses to something
// allowed resolves whichever way the ID is keyed. Version-keying bought
// no re-assessment -- it just renamed the same unresolved problem on
// every version bump, and that has three real costs:
//
//   - Findings are never deleted and "fixed" ones stay visible, so a
//     weekly-bumping dependency leaves a year of dimmed rows for ONE
//     compliance problem that was never actually fixed.
//   - VEX suppression keys on the finding ID (see MergeFindings), so an
//     accepted exception -- "this AGPL tool is dev-only, we accept it"
//     -- silently evaporated at the next bump. An exception that
//     expires when the version changes is not an exception.
//   - FirstSeenAt read "since Tuesday's bump" rather than "we have
//     shipped this for eight months", which is the compliance-relevant
//     fact.
//
// The audit trail version-keying did provide -- which releases carried
// the denied license, and when -- is kept better by components_history,
// which records per-scan inventory WITH licenses and is queryable
// through the diff endpoint instead of accumulating in a findings list.
//
// Because the version is stripped, two coexisting versions of one
// package map to ONE id. LicenseDenylist.Findings dedupes on that
// deliberately; see its own comment.
func LicenseFindingID(purl string) string { return "license:" + purlCoordinates(purl) }

// ComponentDiff is what changed between two component snapshots (see
// Store.ComponentsAt) -- the answer GET
// /api/v1/artifacts/{id}/components/diff returns.
//
// All three lists are always non-nil, so "nothing changed" serializes as
// three empty arrays rather than three nulls.
type ComponentDiff struct {
	Added   []Component `json:"added"`
	Removed []Component `json:"removed"`
	// VersionChanged is the same package at a different version. It is
	// separate from Added/Removed because an upgrade is one event, not a
	// removal plus an unrelated addition -- which is what a naive diff
	// reports, and the only interesting thing most SBOM comparisons
	// contain.
	VersionChanged []ComponentVersionChange `json:"version_changed"`
}

// ComponentVersionChange is one package whose version moved. PURL is
// the NEW purl (what the artifact contains now); From/To are the old
// and new versions.
type ComponentVersionChange struct {
	PURL string `json:"purl"`
	From string `json:"from"`
	To   string `json:"to"`
}

// purlCoordinates strips the version and everything after it from a
// purl, leaving what identifies the PACKAGE rather than the release:
// "pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64" -> "pkg:apk/alpine/openssl".
//
// This is the whole reason DiffComponents can report a version change
// at all. A purl embeds its version, so an upgrade changes the purl --
// meaning a diff keyed on purl alone sees openssl@3.1.4-r5 disappear
// and openssl@3.1.4-r6 appear, reports one removal and one unrelated
// addition, and never finds a single version change. Which is exactly
// the thing anyone comparing two SBOMs is looking for.
//
// Qualifiers ("?arch=") and subpaths ("#") are cut first, since both
// may contain an "@" that is not the version separator. The version is
// then whatever follows the LAST remaining "@" -- purl namespaces can
// contain "@" (a scoped npm package, "pkg:npm/%40angular/core@17.0.0",
// though the spec percent-encodes it), so the last one is the safe
// choice.
func purlCoordinates(purl string) string {
	s := purl
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i > 0 {
		s = s[:i]
	}
	return s
}

// DiffComponents compares two component snapshots, oldest first.
//
// Deliberately a pure function over two slices rather than SQL or a
// Store method: MemStore and PostgresStore have disagreed twice in this
// codebase's history (one scanned three of five finding buckets while
// the other queried all five; one grouped components by purl while the
// other grouped by purl+name+version), and both times the disagreement
// was invisible until production. There is exactly one implementation
// of these semantics and both backends feed it.
//
// Matching runs in two passes, which is what makes multiple concurrent
// versions of one package behave sanely:
//
//  1. Exact purl matches are unchanged, and drop out of both sides.
//  2. Of what remains, a package identity (purlCoordinates) with
//     exactly one entry left on each side is a version change.
//
// Anything still unmatched is a genuine addition or removal. So an
// artifact that legitimately ships two versions of the same library,
// and drops one, reports a removal rather than inventing a version
// change between the two survivors.
func DiffComponents(from, to []Component) ComponentDiff {
	diff := ComponentDiff{
		Added:          []Component{},
		Removed:        []Component{},
		VersionChanged: []ComponentVersionChange{},
	}

	// Pass 1: drop exact purl matches.
	inFrom := map[string]Component{}
	for _, c := range from {
		inFrom[c.PURL] = c
	}
	remainingTo := make([]Component, 0, len(to))
	seenTo := map[string]bool{}
	for _, c := range to {
		seenTo[c.PURL] = true
		if _, unchanged := inFrom[c.PURL]; unchanged {
			continue
		}
		remainingTo = append(remainingTo, c)
	}
	remainingFrom := make([]Component, 0, len(from))
	for _, c := range from {
		if !seenTo[c.PURL] {
			remainingFrom = append(remainingFrom, c)
		}
	}

	// Pass 2: pair what's left by package identity.
	fromByCoord := map[string][]Component{}
	for _, c := range remainingFrom {
		k := purlCoordinates(c.PURL)
		fromByCoord[k] = append(fromByCoord[k], c)
	}
	toByCoord := map[string][]Component{}
	for _, c := range remainingTo {
		k := purlCoordinates(c.PURL)
		toByCoord[k] = append(toByCoord[k], c)
	}

	matched := map[string]bool{}
	for _, c := range remainingTo {
		k := purlCoordinates(c.PURL)
		if len(fromByCoord[k]) == 1 && len(toByCoord[k]) == 1 {
			matched[k] = true
			diff.VersionChanged = append(diff.VersionChanged, ComponentVersionChange{
				PURL: c.PURL,
				From: versionOf(fromByCoord[k][0]),
				To:   versionOf(c),
			})
			continue
		}
		diff.Added = append(diff.Added, c)
	}
	for _, c := range remainingFrom {
		if matched[purlCoordinates(c.PURL)] {
			continue
		}
		diff.Removed = append(diff.Removed, c)
	}

	// Stable order, so two calls on the same data -- and the two
	// backends feeding this -- can't produce differently-ordered JSON.
	sort.Slice(diff.Added, func(i, j int) bool { return diff.Added[i].PURL < diff.Added[j].PURL })
	sort.Slice(diff.Removed, func(i, j int) bool { return diff.Removed[i].PURL < diff.Removed[j].PURL })
	sort.Slice(diff.VersionChanged, func(i, j int) bool {
		return diff.VersionChanged[i].PURL < diff.VersionChanged[j].PURL
	})
	return diff
}

// versionOf prefers the parsed Version field and falls back to the
// version embedded in the purl -- some SBOM formats populate one and
// not the other, and a version change reported as "" -> "" would be
// worse than useless.
func versionOf(c Component) string {
	if c.Version != "" {
		return c.Version
	}
	s := c.PURL
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i > 0 {
		return s[i+1:]
	}
	return ""
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

// ProductVEXStatement is a VEX statement that still knows WHICH
// products it was made about -- the OpenVEX `products` array, which the
// per-artifact path deliberately ignores (see scanner.ParseVEX's
// comment: an upload to POST /artifacts/{id}/vex has already named its
// artifact).
//
// A separate type rather than a Products field on VEXStatement,
// because VEXByID collapses statements into map[string]VEXStatement
// keyed by vulnerability ID alone. That is exactly right per-artifact
// and exactly wrong fleet-wide: two fleet documents can both speak
// about CVE-2024-1234 about DIFFERENT products, and keying by ID would
// silently keep whichever was parsed last. Product scoping has to
// survive until after the statements have been narrowed to one
// artifact -- only then is "one statement per vulnerability" true
// again.
type ProductVEXStatement struct {
	VEXStatement
	// Products holds every identifier the document offered for the
	// products this statement is about: OpenVEX 0.0.1 bare purl
	// strings, and 0.2.0's `@id`, `identifiers.*` and `hashes.*`. All
	// of them, unparsed, because which one matches an artifact depends
	// on what the artifact has on record -- a digest for one, a
	// component purl for another.
	//
	// Empty means the statement named no product at all, which
	// fleet-wide can only mean "matches nothing". That is the safe
	// direction: the alternative reading, "applies to everything",
	// would let a document with a typo suppress the estate.
	Products []string
}

// FleetVEXDocument is an OpenVEX document uploaded fleet-wide
// (POST /api/v1/vex) rather than against one artifact.
//
// Deliberately NOT a row in artifact_documents with kind "vex", even
// though that table already stores per-artifact VEX: that one is keyed
// by (artifact_id, kind), which is precisely the thing a fleet document
// does not have. The two coexist and neither supersedes the other -- a
// fleet document says "this assessment holds wherever these products
// appear", a per-artifact one says "this assessment holds here" -- and
// on conflict the per-artifact statement wins, because it is the more
// specific claim. See internal/api/vexfleet.go.
type FleetVEXDocument struct {
	// ID is the SHA-256 of Content, which makes re-uploading the same
	// document an idempotent no-op rather than a second row saying the
	// same thing. An operator re-running the same `vexctl` pipeline in
	// CI is the expected case, not an unusual one.
	ID          string
	ContentType string
	Content     []byte
	UploadedAt  time.Time
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

// FindingMatch is one distinct finding id found by a search
// (Store.SearchFindings), with how many artifacts currently carry it --
// the discovery half of finding lookup, exactly as ComponentMatch is for
// packages. "log4j" or "CVE-2024" finds the ids that actually exist,
// each with the weight to judge which matters, and the id picked then
// goes to FindByFindingID for the artifact list.
type FindingMatch struct {
	ID string `json:"id"`
	// Title and Severity describe the finding as most recently recorded.
	// One id can legitimately carry different severities across artifacts
	// (a CVE's rating gets revised upstream between scans -- see
	// MergeFindings, which refreshes both from every report), so Severity
	// is the WORST seen: a search that showed "medium" while one artifact
	// rated it critical would rank the wrong thing first.
	Title    string `json:"title,omitempty"`
	Severity string `json:"severity,omitempty"`
	// Artifacts is the number of DISTINCT artifacts where this finding is
	// active -- neither fixed nor VEX-suppressed, the same population
	// FindByFindingID returns and the same one every count on the
	// dashboard uses.
	Artifacts int `json:"artifacts"`
}

// Stats is the fleet-wide aggregate behind GET /api/v1/stats -- the
// numbers the dashboard's summary cards and pipeline strip show. It
// exists because those numbers are about the whole store and the
// dashboard only ever holds one page of artifacts: computing them from
// state.artifacts made "With CVEs" mean "with CVEs on this page", which
// is a different and much smaller number than the card claims.
//
// Every map counts artifacts, never findings: "3" under
// WithFindings["cve"] means three artifacts each have at least one
// active CVE, not that three CVEs exist.
//
// The maps carry only the keys they observed -- a status nothing is in,
// or a stage nothing has reached, is absent rather than present as 0, so
// a client reads them with a "|| 0" default. WithFindings is the one
// exception: its five buckets are a closed set fixed in code (they're
// the five Finding slices on Artifact), and "0 artifacts with malware"
// is a statement this endpoint should make out loud rather than leave a
// caller to infer from a missing key.
type Stats struct {
	Total int `json:"total"`
	// ByStatus and ByType are keyed by Status/Type values
	// ("scanned", "image", ...).
	ByStatus map[string]int `json:"by_status"`
	ByType   map[string]int `json:"by_type"`
	// WithFindings is keyed by bucket name ("cve", "malware",
	// "misconfiguration", "secret", "other" -- the same strings
	// PostgresStore stores in findings.bucket) and counts artifacts with
	// at least one ACTIVE finding in that bucket, i.e. neither fixed nor
	// VEX-suppressed (Finding.IsActive). Same population every other
	// count in this service reports -- see FindByFindingID.
	WithFindings map[string]int `json:"with_findings"`
	// ByStage is keyed by Artifact.CurrentStage, which means artifacts
	// that have not been staged yet are counted under the EMPTY string
	// key rather than a made-up "unassigned" one. Deliberate: the stage
	// list is deployment configuration (PIPELINE_STAGES), so any
	// placeholder name this invented could collide with a real stage
	// somebody configured. "" cannot, because it's never a valid stage.
	ByStage map[string]int `json:"by_stage"`
}

// severityRank orders severities for "worst seen" aggregation. A
// deliberate duplicate of internal/notify's identical table: notify
// imports this package (ScanEvent carries []Finding), so importing it
// back would be a cycle. TestSeverityRankMatchesNotify (store_test.go)
// asserts the two stay in agreement, which is the part that actually
// matters -- a picker calling something "high" that notifications treat
// as critical would be worse than having no severity at all.
var severityRank = map[string]int{
	"critical":   5,
	"high":       4,
	"medium":     3,
	"low":        2,
	"negligible": 1,
	"unknown":    0,
}

// SeverityRank is exported so the SQL CASE in PostgresStore.SearchFindings
// can be checked against it in a test rather than drifting silently.
func SeverityRank(severity string) int {
	rank, _ := SeverityRankOK(severity)
	return rank
}

// SeverityRankOK is SeverityRank plus whether the severity was one this
// table actually knows.
//
// The two are indistinguishable through SeverityRank alone: an
// unrecognized string like "moderate" or "IMPORTANT" ranks 0, and so
// does the perfectly legitimate "unknown". For "worst seen"
// aggregation that conflation is harmless -- both sort to the bottom.
// For internal/policy it is not: a threshold comparison that silently
// treats an unrecognized severity as the lowest possible one passes
// every gate, so a scanner that starts spelling severities differently
// would turn a policy gate green while enforcing nothing.
//
// Callers that need to tell those apart use this; everything doing
// ordering keeps using SeverityRank and is unaffected.
func SeverityRankOK(severity string) (int, bool) {
	rank, ok := severityRank[strings.ToLower(strings.TrimSpace(severity))]
	return rank, ok
}

// IsActive reports whether a finding still counts as a live problem:
// anything that is not fixed, not VEX-suppressed, and not under an
// in-force risk acceptance. Written as an exclusion rather than
// `== FindingStatusOpen` because a finding persisted before the
// lifecycle columns existed (or submitted by a caller that never set
// one) has an empty status, and the dashboard has always treated those
// as open -- see openFindings in dashboard/index.html. Failing toward
// "still a problem" is the safe direction.
//
// This is the single definition every count in this service is built on
// -- internal/policy's Evaluate, GET /api/v1/stats, the finding search
// -- so an acceptance takes effect everywhere by being honoured here,
// with no rule to remember at any of those call sites. The Postgres
// backend computes the same population in SQL rather than in Go; see
// activeFindingSQL, which must be kept in step with this.
//
// Reads the wall clock, deliberately and unlike every other method on
// this type: an acceptance expires on its own, so "is this active" is a
// question about NOW, and threading a clock through every caller would
// be a signature change to the whole read path to buy testability the
// Accepted(t) split below already provides.
func (f Finding) IsActive() bool {
	if f.Status == FindingStatusFixed || f.Status == FindingStatusNotAffected {
		return false
	}
	return !f.Accepted(time.Now())
}

// Accepted reports whether a risk acceptance is in force at t.
//
// Exported as the one place the rule lives, so a caller that needs to
// ask about a specific moment (a test, the dashboard's badge, the SQL
// predicate this is checked against) agrees with IsActive by
// construction rather than by re-deriving "not nil and in the future"
// and getting the boundary wrong. An acceptance that expires exactly at
// t has expired: the finding is active again, which is the direction
// that fails toward showing a problem rather than hiding one.
func (f Finding) Accepted(t time.Time) bool {
	return f.AcceptedUntil != nil && t.Before(*f.AcceptedUntil)
}

// Enrichment is what the KEV/EPSS feeds know about one CVE.
type Enrichment struct {
	EPSSScore      float64
	KnownExploited bool
}

// EnrichmentStatus reports when each feed was last successfully
// refreshed, and how many entries it holds.
//
// It exists because the absence of enrichment is indistinguishable
// from a negative result: a CVE with no KEV entry and a CVE the feed
// was never downloaded for both come back KnownExploited=false,
// EPSSScore=0. A red "known exploited" badge that silently never
// appears reads as good news, which is the worst possible failure
// direction for this feature. Anything displaying enrichment is
// expected to show staleness rather than let it pass as a clean bill
// of health -- see GET /api/v1/stats and the dashboard's policyBadge
// neighbours.
type EnrichmentStatus struct {
	KEVUpdatedAt  *time.Time `json:"kev_updated_at,omitempty"`
	EPSSUpdatedAt *time.Time `json:"epss_updated_at,omitempty"`
	KEVEntries    int        `json:"kev_entries"`
	EPSSEntries   int        `json:"epss_entries"`
}

// Fresh reports whether both feeds were refreshed within maxAge.
// Never-refreshed counts as stale, not as fresh-with-nothing.
func (s EnrichmentStatus) Fresh(now time.Time, maxAge time.Duration) bool {
	if s.KEVUpdatedAt == nil || s.EPSSUpdatedAt == nil {
		return false
	}
	return now.Sub(*s.KEVUpdatedAt) <= maxAge && now.Sub(*s.EPSSUpdatedAt) <= maxAge
}

// IsCVEID reports whether a finding id looks like a CVE, which is the
// only thing the KEV and EPSS feeds are keyed on.
//
// Used to skip lookups that cannot match: secret findings carry ids
// like "secret:/app/.env:aws-access-key-id:3" and malware findings
// carry signature names, and querying a 300k-row table for those is
// pure waste.
func IsCVEID(id string) bool {
	return strings.HasPrefix(strings.ToUpper(id), "CVE-")
}

// Provenance verification outcomes.
//
// UNKNOWN IS NOT A FAILURE AND NOT A PASS. It is the state of every
// artifact in a deployment that has never enabled cosign, and of every
// artifact not yet rescanned since it was enabled -- and it must be
// shown as its own thing rather than collapsed into either.
const (
	ProvenanceUnknown = ""
	// ProvenanceVerified: a valid signature from the required identity
	// (plus a SLSA attestation, where one is required).
	ProvenanceVerified = "verified"
	// ProvenanceUnsigned: checked, and there is no such signature.
	ProvenanceUnsigned = "unsigned"
	// ProvenanceUnverified: the check could not be COMPLETED -- registry
	// unreachable, trust root unusable. Distinct from unsigned, because
	// an outage must not read as an accusation.
	ProvenanceUnverified = "unverified"
)

// ValidProvenance reports whether a status is one this system sets.
func ValidProvenance(s string) bool {
	switch s {
	case ProvenanceUnknown, ProvenanceVerified, ProvenanceUnsigned, ProvenanceUnverified:
		return true
	}
	return false
}
