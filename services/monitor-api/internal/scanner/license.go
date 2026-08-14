package scanner

import (
	"sort"
	"strings"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// licenseFindingSeverity is what a denylisted license is reported at.
// Medium, deliberately: a forbidden license is a real compliance
// problem that someone has to act on, but it is not a vulnerability and
// nothing is exploitable because of it. Reporting it as high would put
// it above genuine CVEs in every severity-ordered view, and reporting
// it as low would bury it under noise.
const licenseFindingSeverity = "medium"

// LicenseDenylist decides whether a component's license is one this
// deployment refuses (LICENSE_DENYLIST / monitorApi.licenseDenylist).
//
// MATCHING RULE, stated once because it is the difference between this
// feature being useful and being quietly wrong in either direction:
// each identifier a component carries is compared to each denylist
// entry EXACTLY, after trimming, case-insensitively. It is not a
// substring test.
//
//   - "GPL-3.0-only" does not match a component licensed
//     "LGPL-3.0-only". Different licenses; a substring test would
//     conflate them.
//   - "AGPL-3.0-only" does not match a component whose license is the
//     SPDX expression "MIT OR AGPL-3.0-only". The OR is exactly the
//     permissive escape that makes such a package usable, so flagging
//     it would be a false positive on the one signal this produces. A
//     deployment that wants to refuse those anyway can add the whole
//     expression as its own denylist entry, since expressions are
//     stored verbatim (see ParseSBOMComponents).
//
// The zero value denies nothing, which is what every deployment that
// never sets the variable gets.
type LicenseDenylist struct {
	// denied is keyed by the lowercased identifier.
	denied map[string]bool
}

// NewLicenseDenylist parses a comma-separated list. Blank entries are
// skipped rather than becoming an identifier that matches every
// component with no license information.
func NewLicenseDenylist(raw string) LicenseDenylist {
	denied := make(map[string]bool)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		denied[strings.ToLower(entry)] = true
	}
	return LicenseDenylist{denied: denied}
}

// Enabled reports whether anything is denied at all -- callers skip the
// whole evaluation when nothing is configured.
func (d LicenseDenylist) Enabled() bool { return len(d.denied) > 0 }

// Denies reports whether any of this component's identifiers is on the
// list. See the type comment for the matching rule.
func (d LicenseDenylist) Denies(component artifact.Component) (string, bool) {
	if len(d.denied) == 0 {
		return "", false
	}
	for _, one := range strings.Split(component.Licenses, ",") {
		one = strings.TrimSpace(one)
		if one == "" {
			continue
		}
		if d.denied[strings.ToLower(one)] {
			return one, true
		}
	}
	return "", false
}

// Findings turns a component inventory into one finding per PACKAGE
// carrying a denied license.
//
// Per package, not per component row: artifact.LicenseFindingID strips
// the version, so an inventory legitimately shipping two versions of
// one library -- which happens, and which the component diff handles
// explicitly -- maps both to the same finding ID. Emitting both would
// hand MergeFindings a `reported` slice containing duplicate IDs, where
// one would silently overwrite the other and which one won would depend
// on inventory order. So they are deduped here, and the surviving entry
// is chosen by lowest purl: an arbitrary rule, but a STABLE one, so two
// runs over the same inventory produce byte-identical findings rather
// than a Title that flickers between versions.
//
// The result is a COMPLETE picture of this producer's findings for the
// inventory it was given, which is what lets the caller merge it with
// fix-detection on: a package that no longer appears, or whose license
// changed to an allowed one, is genuinely resolved. It is emphatically
// NOT a complete picture of the "other" bucket, which is why the caller
// merges it as a partition -- see artifact.MergePartition.
func (d LicenseDenylist) Findings(components []artifact.Component) []artifact.Finding {
	if !d.Enabled() {
		return nil
	}

	byID := make(map[string]artifact.Finding)
	// wonBy records which purl produced the current entry for an id, so
	// the lowest-purl tie-break is decidable without re-parsing.
	wonBy := make(map[string]string)

	for _, c := range components {
		license, denied := d.Denies(c)
		if !denied {
			continue
		}
		id := artifact.LicenseFindingID(c.PURL)
		if prev, taken := wonBy[id]; taken && prev <= c.PURL {
			continue
		}
		name := c.Name
		if name == "" {
			name = c.PURL
		}
		wonBy[id] = c.PURL
		byID[id] = artifact.Finding{
			ID:       id,
			Severity: licenseFindingSeverity,
			Title:    name + " is licensed " + license + ", which this deployment denies",
			Source:   artifact.LicenseFindingSource,
			// Routed to "other" by the caller rather than by this hint:
			// Category is a Scanner-to-classifyBucket signal, and this
			// is not reached through the scanner path at all.
			Category: LicenseFindingBucket,
		}
	}

	out := make([]artifact.Finding, 0, len(byID))
	for _, f := range byID {
		out = append(out, f)
	}
	// Map iteration has no order of its own; sort so the output is
	// stable across runs.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// LicenseFindingBucket is the one bucket license findings ever land in.
const LicenseFindingBucket = "other"

// Bucket implements BucketAffinity.
//
// Declarative only, and worth being honest about: scanArtifact consults
// BucketAffinity on the scanners in its own registry to decide which
// buckets a FAILED scanner blocks fix-detection for, and this evaluator
// is not one of them -- it runs when an SBOM is indexed, not during a
// scan. What actually confines license findings to "other" is the
// caller placing them there and merging them as a partition of it
// (artifact.MergePartition).
//
// It exists so the type states its own scope alongside every real
// scanner that does, and so it is already correct if the evaluator is
// ever registered as a Scanner.
func (d LicenseDenylist) Bucket() string { return LicenseFindingBucket }
