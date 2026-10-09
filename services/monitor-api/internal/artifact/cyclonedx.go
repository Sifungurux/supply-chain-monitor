package artifact

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// AnnotateCycloneDX overlays this deployment's own finding state onto a
// stored CycloneDX document and returns the result.
//
// WHAT THIS ADDS THAT THE STORED DOCUMENT DOES NOT HAVE. The SBOM is
// `trivy convert --format cyclonedx --scanners vuln` output: trivy's
// components and trivy's vulnerabilities, as they were at scan time. It
// carries none of the judgements that live only here --
//
//   - a VEX not_affected and the justification behind it
//   - a time-boxed risk acceptance, who made it and when it lapses
//   - that a finding has since been fixed
//   - findings from the OTHER scanner entirely (grype contributed 4,557
//     of 46,728 open findings on this fleet, and trivy's document names
//     none of them)
//
// -- which is the whole reason to export rather than hand someone the
// stored file.
//
// The document is decoded into a generic map rather than a typed
// CycloneDX model, deliberately. Everything this function does not
// understand passes through byte-for-byte: component trees, pedigree,
// signatures, and whatever a future spec version adds. A typed model
// would silently drop every field it had not been taught, and the
// consumer would never know what it lost.
func AnnotateCycloneDX(stored []byte, findings []Finding, now time.Time) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(stored, &doc); err != nil {
		return nil, fmt.Errorf("stored SBOM is not JSON: %w", err)
	}
	if bf, _ := doc["bomFormat"].(string); bf != "CycloneDX" {
		// Refused rather than annotated anyway: an SPDX document would
		// take the vulnerabilities array happily and mean nothing by it.
		return nil, fmt.Errorf("stored SBOM is %q, not CycloneDX -- nothing to annotate", bf)
	}

	byID := make(map[string]Finding, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
	}

	existing, _ := doc["vulnerabilities"].([]any)
	seen := make(map[string]bool, len(existing))

	// Annotate what the document already lists.
	for _, v := range existing {
		vuln, ok := v.(map[string]any)
		if !ok {
			continue
		}
		id, _ := vuln["id"].(string)
		if id == "" {
			continue
		}
		seen[id] = true
		f, known := byID[id]
		if !known {
			// trivy reported it and we have no record: left exactly as
			// it is. Inventing an analysis for a finding this system
			// never stored would be asserting something nobody assessed.
			continue
		}
		if a := analysisFor(f, now); a != nil {
			vuln["analysis"] = a
		}
	}

	// Add what only we know about. These carry no `affects`, because a
	// Finding records no package: nothing in this system ties a finding
	// to the component it came from. A consumer that links
	// vulnerabilities to components by `affects` will therefore show
	// these as unattached, which is honest -- the alternative is
	// inventing a component ref.
	added := make([]string, 0)
	for _, f := range findings {
		if seen[f.ID] {
			continue
		}
		added = append(added, f.ID)
	}
	sort.Strings(added) // stable output: a diff between two exports should mean a change
	for _, id := range added {
		f := byID[id]
		vuln := map[string]any{
			"id":          f.ID,
			"source":      map[string]any{"name": f.Source},
			"description": f.Title,
		}
		if f.Severity != "" {
			vuln["ratings"] = []any{map[string]any{
				"source":   map[string]any{"name": f.Source},
				"severity": strings.ToLower(f.Severity),
			}}
		}
		if a := analysisFor(f, now); a != nil {
			vuln["analysis"] = a
		}
		existing = append(existing, vuln)
	}
	if len(existing) > 0 {
		doc["vulnerabilities"] = existing
	}

	return json.MarshalIndent(doc, "", "  ")
}

// analysisFor maps one finding's state onto a CycloneDX `analysis`
// object, or nil when there is nothing to say.
//
// An OPEN, unsuppressed, unaccepted finding returns nil rather than
// `state: in_triage`. Absence means "no analysis recorded", which is
// true; in_triage would claim somebody is looking at it.
//
// The `detail` field carries our own wording in every case. CycloneDX's
// `justification` enum and OpenVEX's are different vocabularies -- ours
// comes from whatever the VEX document said -- so detail is the only
// place the real reason survives a round trip intact.
func analysisFor(f Finding, now time.Time) map[string]any {
	switch {
	case f.Status == FindingStatusNotAffected:
		a := map[string]any{"state": "not_affected"}
		if f.Justification != "" {
			a["detail"] = f.Justification
		}
		return a

	case f.Status == FindingStatusFixed:
		a := map[string]any{"state": "resolved"}
		if f.ResolvedAt != nil {
			a["detail"] = "resolved; no longer reported as of " + f.ResolvedAt.UTC().Format(time.RFC3339)
		}
		return a

	case f.Accepted(now):
		// There is no "accepted risk" state in CycloneDX, and the
		// closest honest reading is: still exploitable, and we have
		// decided not to act yet. `will_not_fix` is the response that
		// says that without claiming the vulnerability is absent.
		//
		// The expiry goes in detail because it is the part that makes
		// this an acceptance rather than a dismissal, and nothing in
		// the schema carries it.
		detail := "risk accepted"
		if f.AcceptedBy != "" {
			detail += " by " + f.AcceptedBy
		}
		if f.AcceptedUntil != nil {
			detail += ", expires " + f.AcceptedUntil.UTC().Format(time.RFC3339)
		}
		if f.AcceptanceReason != "" {
			detail += ": " + f.AcceptanceReason
		}
		return map[string]any{
			"state":    "exploitable",
			"response": []any{"will_not_fix"},
			"detail":   detail,
		}
	}
	return nil
}
