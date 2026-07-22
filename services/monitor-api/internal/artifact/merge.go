package artifact

import "time"

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
// handlers.go) -- otherwise a Trivy failure with ClamAV still succeeding
// would silently mark every previously-open CVE "fixed" just because
// Trivy didn't run, not because any of them actually got patched. An
// external submitFindings call always passes true: the caller is
// asserting a complete current result for the one bucket it named, by
// definition of what that endpoint is for.
func MergeFindings(existing, reported []Finding, now time.Time, detectFixed bool) []Finding {
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

		if stillReported, ok := reportedByID[old.ID]; ok {
			stillReported.Status = FindingStatusOpen
			stillReported.FirstSeenAt = old.FirstSeenAt
			stillReported.ResolvedAt = nil
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

		if old.Status == FindingStatusFixed {
			// Already fixed from an earlier round; don't touch
			// ResolvedAt again just because it's still gone.
			merged = append(merged, old)
			continue
		}

		fixed := old
		fixed.Status = FindingStatusFixed
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
		merged = append(merged, f)
	}

	return merged
}
