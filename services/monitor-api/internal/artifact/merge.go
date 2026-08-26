package artifact

import (
	"sort"
	"strings"
	"time"
)

// MergeFindings combines a single bucket's existing (already persisted)
// findings with a freshly reported set from a new /scan or /findings
// call, producing that bucket's next persisted state -- rather than the
// naive "just replace the bucket" behavior this project started with,
// which silently destroyed the record of anything that stopped being
// reported (a fixed CVE, a malware match that's no longer there) with
// no way to tell "this was fixed" from "this was never found."
//
// Findings are matched by ID (e.g. "CVE-2024-1234",
// "clamav-signature-match"). The result:
//   - A finding present in both existing and reported stays "open",
//     with its FirstSeenAt preserved from existing (so it doesn't look
//     newly discovered just because a scan re-ran) but every other
//     field refreshed from the latest report (severity/title/source can
//     legitimately change between scans -- e.g. a CVE's severity gets
//     revised upstream). If it had previously been marked "fixed" (a
//     regression -- it went away and came back), ResolvedAt is cleared
//     and it goes back to "open"; FirstSeenAt still reflects the
//     original discovery, not the regression.
//   - A finding present only in reported (never seen before) is "open"
//     with FirstSeenAt set to now.
//   - A finding present only in existing (was reported before, isn't
//     now) becomes "fixed" with ResolvedAt set to now -- but only when
//     detectFixed is true. When detectFixed is false (see below), it's
//     carried over completely unchanged instead.
//   - A finding already "fixed" that's still absent from reported stays
//     exactly as it was -- ResolvedAt doesn't get bumped forward every
//     subsequent scan just because it's still gone.
//
// detectFixed exists because "not in this round's report" only means
// "actually fixed" if this round's report can be trusted as a complete
// picture of the bucket. scanArtifact sets this to false whenever any
// registered scanner for the artifact's type errored this round (see
// internal/api/scan.go) -- otherwise a Trivy failure with ClamAV still succeeding
// would silently mark every previously-open CVE "fixed" just because
// Trivy didn't run, not because any of them actually got patched. An
// external submitFindings call always passes true: the caller is
// asserting a complete current result for the one bucket it named, by
// definition of what that endpoint is for.
//
// vex (nil when the artifact has no VEX document, which is the common
// case) overrides all of the above for the vulnerability IDs it speaks
// about, and is consulted on every path -- a finding still reported, a
// finding that just vanished, one already on record, one brand new this
// round. A statement of "not_affected" or "fixed" wins over what the
// scanner reported: the whole point of VEX is that a human assessed a
// finding a scanner cannot assess for itself, so a scanner that keeps
// reporting it is not new information. "affected" and
// "under_investigation" deliberately change nothing (see
// VEXStatement.Status).
//
// Suppression also survives without vex being passed at all: a finding
// already carrying "not_affected" keeps that status and its
// Justification when it's reported again, instead of being reopened.
// That's what makes this stick across scans rather than depending on
// every caller remembering to re-read the document -- see
// docs/architecture.md ("Suppressing findings with VEX").
//
// A RISK ACCEPTANCE (Finding.AcceptedUntil/AcceptedBy/AcceptanceReason)
// survives every merge the same way, and for the same reason: it is a
// decision recorded about a finding, not an observation a scan can
// make, so re-reporting the finding must not revoke it. It differs from
// a VEX suppression in one respect, deliberately: it never blocks
// fix-detection. A finding that stops being reported while accepted is
// marked "fixed" exactly as it would be otherwise, keeping the
// acceptance alongside as history -- an accepted finding actually
// getting fixed is good news, and swallowing it would leave a resolved
// problem looking like an outstanding one somebody chose to tolerate.
// MergePartition merges only the part of a bucket one producer owns,
// carrying every other finding in it through completely untouched.
//
// This exists because the "other" bucket has two independent producers
// and MergeFindings' contract is that `reported` is a COMPLETE picture
// of what it is merged against. SARIF and pluggable scanners write
// there during a scan; license findings (see LicenseFindingSource) are
// produced when an SBOM is indexed, which is a different event
// entirely. Merge either one against the whole bucket and everything
// the other producer wrote is absent from `reported`, so fix-detection
// marks all of it "fixed":
//
//   - a scan of an artifact with license findings would resolve every
//     one of them, because no scanner reports licenses;
//   - indexing an SBOM would resolve every SARIF finding, because the
//     license evaluator reports none.
//
// Both are silent data corruption -- the findings still exist, they
// just quietly claim to be fixed. So each producer merges its own
// partition and leaves the rest alone. The two call sites use
// complementary predicates (Source == licenseSource, Source !=
// licenseSource), which is what makes it checkable at a glance that the
// bucket is partitioned exactly once with nothing dropped.
//
// owns identifies the EXISTING findings this merge is responsible for.
// Everything reported is assumed to belong to the caller -- it is the
// caller's own output.
func MergePartition(existing, reported []Finding, owns func(Finding) bool, now time.Time, detectFixed bool, vex map[string]VEXStatement) []Finding {
	mine := make([]Finding, 0, len(existing))
	theirs := make([]Finding, 0, len(existing))
	for _, f := range existing {
		if owns(f) {
			mine = append(mine, f)
			continue
		}
		theirs = append(theirs, f)
	}
	// theirs is passed through verbatim -- not re-merged, not restamped
	// -- so another producer's FirstSeenAt, Status and Justification
	// survive this call untouched.
	return append(theirs, MergeFindings(mine, reported, now, detectFixed, vex)...)
}

func MergeFindings(existing, reported []Finding, now time.Time, detectFixed bool, vex map[string]VEXStatement) []Finding {
	reportedByID := make(map[string]Finding, len(reported))
	for _, f := range reported {
		reportedByID[f.ID] = f
	}

	merged := make([]Finding, 0, len(existing)+len(reported))
	seen := make(map[string]bool, len(existing))

	// Walk existing findings first, in their existing order, so a
	// finding's position doesn't reshuffle every scan for no reason.
	for _, old := range existing {
		seen[old.ID] = true
		stillReported, isReported := reportedByID[old.ID]

		// A risk acceptance is a property of the finding on record, not
		// of anything a scanner or a submitFindings caller reported, so
		// it is carried across from old BEFORE any branch below can
		// return stillReported in old's place. Done once here rather
		// than in each of the three branches that do that: this is
		// exactly how Justification lost its way into being re-derived
		// per-branch, and a branch added later that forgets the carry
		// would silently revoke acceptances the moment a scan re-reports
		// the finding.
		//
		// Also the trust boundary. Whatever a caller supplied in these
		// three fields is discarded here, so submitFindings -- which
		// decodes findings straight from request JSON -- cannot accept
		// the risk of its own findings; that requires the admin-scoped
		// acceptance endpoint. New findings get the same treatment in
		// the reported-only loop below.
		if isReported {
			stillReported.AcceptedUntil = old.AcceptedUntil
			stillReported.AcceptedBy = old.AcceptedBy
			stillReported.AcceptanceReason = old.AcceptanceReason
		}

		// An explicit "affected" statement revokes an earlier
		// suppression: an assessment that turned out to be wrong has to
		// be retractable, and re-uploading a corrected document is how.
		// Only an explicit statement does this -- a document that simply
		// stops mentioning the vulnerability leaves it suppressed, since
		// "absent from a document" is not an assertion about anything.
		revoked := vex[old.ID].Status == VEXStatusAffected

		// VEX is checked before any scan-derived transition, and before
		// the !detectFixed early return below: an operator uploading a
		// VEX document is asserting something about this artifact that
		// doesn't depend on a scan having run at all, so it has to apply
		// on a merge with nothing reported (which is exactly how
		// uploadVEX applies a freshly uploaded document -- see
		// internal/api/vex.go).
		if v, ok := vex[old.ID]; ok && vexSuppresses(v) {
			next := old
			if isReported {
				// Still reported: take the fresh severity/title/source
				// the way the still-reported branch below does, then let
				// VEX decide the lifecycle fields.
				next = stillReported
				next.FirstSeenAt = old.FirstSeenAt
				// Carried for the same reason FirstSeenAt is: a scanner's
				// Finding has no ResolvedAt, and applyVEX only stamps one
				// when it finds none -- so without this a VEX "fixed"
				// finding would be re-resolved with a fresh timestamp on
				// every single scan that keeps reporting it, and the
				// dashboard's "Fixed <time ago>" would reset each round.
				next.ResolvedAt = old.ResolvedAt
			}
			applyVEX(&next, v, now)
			merged = append(merged, next)
			continue
		}

		// A retraction has to take effect on the same path an
		// application does -- uploadVEX merges with NOTHING reported and
		// detectFixed false, so handling this only in the still-reported
		// branch below meant uploading an "affected" statement appeared
		// to do nothing until the next scan happened to report the
		// finding again, while uploading a "not_affected" one applied
		// instantly. Reopened rather than left to the scan to decide:
		// "affected" is an assertion that this artifact IS affected, and
		// the next scan reclassifies it normally from there.
		if revoked && old.Status == FindingStatusNotAffected {
			next := old
			if isReported {
				next = stillReported
				next.FirstSeenAt = old.FirstSeenAt
			}
			next.Status = FindingStatusOpen
			next.Justification = ""
			next.ResolvedAt = nil
			merged = append(merged, next)
			continue
		}

		if isReported {
			stillReported.FirstSeenAt = old.FirstSeenAt
			stillReported.ResolvedAt = nil
			if old.Status == FindingStatusNotAffected {
				// Suppressed by a VEX document at some point in the past.
				// A scanner reporting it again is not news -- that's the
				// whole premise of VEX -- so it must not reopen, and the
				// justification stays attached as the record of why.
				// This is what makes suppression survive without every
				// merge caller having to re-read the document first.
				stillReported.Status = FindingStatusNotAffected
				stillReported.Justification = old.Justification
			} else {
				stillReported.Status = FindingStatusOpen
				// Never carried from the reported finding: Justification is
				// only ever written by a VEX statement (see Finding's own
				// comment), and submitFindings decodes reported findings
				// straight from caller JSON.
				stillReported.Justification = ""
			}
			merged = append(merged, stillReported)
			continue
		}

		if !detectFixed {
			// This round's report can't be trusted as complete for
			// this bucket -- leave old exactly as it was rather than
			// risk marking something "fixed" that simply didn't get
			// scanned this round.
			merged = append(merged, old)
			continue
		}

		if old.Status == FindingStatusFixed || old.Status == FindingStatusNotAffected {
			// Already fixed from an earlier round; don't touch
			// ResolvedAt again just because it's still gone. A
			// VEX-suppressed finding is left alone for the same reason
			// plus one more: overwriting "not affected" with "fixed"
			// would replace a human's assessment with a guess, and both
			// statuses are already out of every count anyway. (A
			// retracted suppression never reaches here -- it was reopened
			// above -- so anything still carrying "not_affected" at this
			// point is one nobody has retracted.)
			merged = append(merged, old)
			continue
		}

		fixed := old
		fixed.Status = FindingStatusFixed
		// Defensive: a finding reaching here should never carry one (a
		// justification only ever accompanies a suppression, and those
		// are handled above), and a stale reason would misdescribe the
		// status it is now paired with.
		fixed.Justification = ""
		resolvedAt := now
		fixed.ResolvedAt = &resolvedAt
		merged = append(merged, fixed)
	}

	// Anything reported that wasn't already tracked at all is brand new.
	for _, f := range reported {
		if seen[f.ID] {
			continue
		}
		f.Status = FindingStatusOpen
		f.FirstSeenAt = now
		f.ResolvedAt = nil
		f.Justification = ""
		// Nothing can arrive already accepted: an acceptance is recorded
		// against a finding that is on record, by an admin-scoped call
		// naming it. See the carry above for the trust-boundary half of
		// this.
		f.AcceptedUntil = nil
		f.AcceptedBy = ""
		f.AcceptanceReason = ""
		// A VEX document can speak about a vulnerability before any scan
		// ever reports it -- the first scan that does find it comes in
		// already suppressed, rather than being open until the next
		// merge notices.
		if v, ok := vex[f.ID]; ok && vexSuppresses(v) {
			applyVEX(&f, v, now)
		}
		merged = append(merged, f)
	}

	return merged
}

// vexSuppresses reports whether a statement is one of the two that
// actually change a finding. Anything else -- "affected",
// "under_investigation", a status this service doesn't recognize at all,
// or an empty one from a document that omitted the field -- is treated
// as "no opinion" and leaves the finding exactly as the scan found it.
// That's the safe direction: a spelling this parser doesn't know shows a
// real vulnerability rather than silently hiding one.
func vexSuppresses(v VEXStatement) bool {
	return v.Status == FindingStatusNotAffected || v.Status == FindingStatusFixed
}

// applyVEX stamps a suppressing statement onto a finding. ResolvedAt
// tracks the two statuses' different meanings: "fixed" means this
// stopped being a problem at some point (so it gets a resolution
// timestamp, the same as scan-detected fixes -- kept if one is already
// there, since re-uploading a document shouldn't move the date), while
// "not affected" means it was never a problem here in the first place,
// so there's nothing to have resolved.
func applyVEX(f *Finding, v VEXStatement, now time.Time) {
	f.Status = v.Status
	f.Justification = v.Justification
	if v.Status == FindingStatusFixed {
		if f.ResolvedAt == nil {
			resolvedAt := now
			f.ResolvedAt = &resolvedAt
		}
		return
	}
	f.ResolvedAt = nil
}

// CoalesceSameIDSources collapses a single scan round's freshly reported
// findings that share an ID (e.g. trivy and grype both reporting
// "CVE-2024-1234") into one finding per ID, with Source set to every
// contributing tool, sorted and comma-joined (e.g. "grype, trivy").
// Without this, MergeFindings' plain map-by-ID dedup would let whichever
// scanner's finding lands second in the slice silently overwrite the
// first's Source. Non-Source fields (Severity, Title, ...) come from
// whichever finding for that ID appears first in reported -- scanArtifact
// runs scanners concurrently, so which one that is isn't deterministic
// run to run, but Severity/Title for the same CVE ID are expected to
// agree across tools anyway.
//
// Each finding's own Source is split on "," before rejoining, so an
// already-coalesced value passed back through (e.g. a bucket that went
// through this twice) doesn't accumulate into "trivy, grype, trivy".
func CoalesceSameIDSources(reported []Finding) []Finding {
	type group struct {
		finding Finding
		sources map[string]bool
	}

	groups := make(map[string]*group, len(reported))
	order := make([]string, 0, len(reported))

	for _, f := range reported {
		g, ok := groups[f.ID]
		if !ok {
			g = &group{finding: f, sources: map[string]bool{}}
			groups[f.ID] = g
			order = append(order, f.ID)
		}
		for _, s := range strings.Split(f.Source, ",") {
			if s = strings.TrimSpace(s); s != "" {
				g.sources[s] = true
			}
		}
	}

	coalesced := make([]Finding, 0, len(order))
	for _, id := range order {
		g := groups[id]
		sources := make([]string, 0, len(g.sources))
		for s := range g.sources {
			sources = append(sources, s)
		}
		sort.Strings(sources)

		f := g.finding
		f.Source = strings.Join(sources, ", ")
		coalesced = append(coalesced, f)
	}

	return coalesced
}

// CarrySourcesForward unions each reported finding's Source with the
// Source already recorded for that finding, and is what a PARTIAL scan
// round must run its results through before merging them.
//
// THE PROBLEM IT SOLVES. MergeFindings replaces a stored finding with
// the reported one, so Source becomes whatever scanner ran most
// recently. That is correct for a full round -- if trivy still reports
// a CVE and grype no longer does, "trivy" is the honest record. It is
// wrong for a round that never ASKED grype: the sbom-only sweep runs
// trivy alone, so within a day of enabling it every finding on the
// fleet claimed to come from trivy, and grype's corroboration was
// erased. Measured here: findings sourced "grype, trivy" fell from
// 7,073 to 7 overnight.
//
// This is the same rule the fix-detection and bucket-merge decisions
// already follow (see MergeFindings' detectFixed, and scanArtifact's
// bucket skip): a round that did not run a scanner may not draw
// conclusions on that scanner's behalf. It cannot conclude a finding is
// fixed, it cannot conclude a bucket is empty, and it cannot conclude a
// tool stopped reporting.
//
// Union rather than replace-if-empty, because both directions matter: a
// finding trivy newly reports that grype already had must end up
// "grype, trivy", not either one alone.
//
// A finding not previously recorded is returned untouched -- there is
// no prior attribution to carry, and inventing one would be worse than
// the narrowing this exists to prevent.
func CarrySourcesForward(existing, reported []Finding) []Finding {
	if len(existing) == 0 || len(reported) == 0 {
		return reported
	}
	prior := make(map[string]string, len(existing))
	for _, f := range existing {
		prior[f.ID] = f.Source
	}
	// Copied rather than mutated in place: reported is the caller's
	// slice and is also handed to notification and enrichment paths.
	out := make([]Finding, len(reported))
	copy(out, reported)
	for i := range out {
		if old, ok := prior[out[i].ID]; ok {
			out[i].Source = mergeSourceList(out[i].Source, old)
		}
	}
	return out
}

// mergeSourceList unions comma-separated Source values into one sorted,
// comma-joined value. Splitting both sides first is what keeps this
// idempotent -- an already-joined "grype, trivy" passed back through
// does not accumulate into "grype, trivy, trivy", the same property
// CoalesceSameIDSources relies on for the same reason.
func mergeSourceList(values ...string) string {
	set := map[string]bool{}
	for _, v := range values {
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				set[s] = true
			}
		}
	}
	sources := make([]string, 0, len(set))
	for s := range set {
		sources = append(sources, s)
	}
	sort.Strings(sources)
	return strings.Join(sources, ", ")
}
