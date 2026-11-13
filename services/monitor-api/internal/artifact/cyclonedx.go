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

	purls := componentPURLs(doc)
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
		relabelForDT(vuln, purls)
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
				"severity": cdxSeverity(f.Severity),
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

// cdxSeverity maps a scanner's severity onto CycloneDX's closed enum.
// Lowercasing alone is not enough: grype's "Negligible" is not in it, and
// one out-of-enum rating makes Dependency-Track reject the whole document.
func cdxSeverity(s string) string {
	switch s = strings.ToLower(s); s {
	case "critical", "high", "medium", "low", "info", "none", "unknown":
		return s
	case "negligible":
		return "info"
	}
	return "unknown"
}

// relabelForDT renames a vulnerability to the (source, id) pair
// Dependency-Track files it under, so that DT applies our analysis to it.
//
// DT matches a VEX entry to a finding on exact (source, id) and nothing
// else: no aliases. trivy names a vulnerability after the CVE and labels
// it with the feed it read ("alpine", "debian", "govulndb"), while DT --
// which finds distro and Go vulnerabilities through OSV -- files the same
// thing as OSV/ALPINE-CVE-..., OSV/DEBIAN-CVE-..., OSV/GO-2025-4010. Under
// trivy's naming, not one analysis in an export applied. Each mapping
// below was checked against DT 4.14.6 with the OSV ecosystem enabled.
//
// The ecosystem is read from the affected component's purl, not from the
// ID: the same CVE is ALPINE- in one image and DEBIAN- in another. Only
// entries with `affects` are touched; DT skips the rest whatever they
// are called. What trivy called it is kept as a CycloneDX reference.
func relabelForDT(vuln map[string]any, purls map[string]string) {
	id, _ := vuln["id"].(string)
	affects, _ := vuln["affects"].([]any)
	if len(affects) == 0 {
		return
	}
	// ponytail: first affected component decides; trivy writes one entry
	// per ecosystem (0 mixed entries across 4 real images), so it is all.
	first, _ := affects[0].(map[string]any)
	ref, _ := first["ref"].(string)
	purl := purls[ref]

	newID := ""
	for prefix, osv := range map[string]string{
		"pkg:apk/alpine/": "ALPINE-",
		"pkg:deb/debian/": "DEBIAN-",
		"pkg:deb/ubuntu/": "UBUNTU-",
	} {
		if strings.HasPrefix(purl, prefix) {
			newID = id // a DSA- is filed under its own name
			if strings.HasPrefix(id, "CVE-") {
				newID = osv + id
			}
		}
	}
	if strings.HasPrefix(purl, "pkg:golang/") {
		newID = goVulnID(vuln) // "" when trivy gave no Go advisory: left alone
	}
	if newID == "" {
		return
	}

	orig := map[string]any{"id": id}
	if src, ok := vuln["source"].(map[string]any); ok {
		orig["source"] = src
	}
	refs, _ := vuln["references"].([]any)
	vuln["references"] = append(refs, orig)
	vuln["id"] = newID
	vuln["source"] = map[string]any{"name": "OSV"}
}

// componentPURLs maps every component's bom-ref to its purl, nested
// components included.
func componentPURLs(doc map[string]any) map[string]string {
	out := map[string]string{}
	var walk func([]any)
	walk = func(cs []any) {
		for _, c := range cs {
			m, _ := c.(map[string]any)
			ref, _ := m["bom-ref"].(string)
			purl, _ := m["purl"].(string)
			if ref != "" && purl != "" {
				out[ref] = purl
			}
			sub, _ := m["components"].([]any)
			walk(sub)
		}
	}
	cs, _ := doc["components"].([]any)
	walk(cs)
	return out
}

// goVulnID is the Go vulnerability database ID trivy links to in an
// entry's advisories (https://pkg.go.dev/vuln/GO-2025-4010), or "".
func goVulnID(vuln map[string]any) string {
	advs, _ := vuln["advisories"].([]any)
	for _, a := range advs {
		m, _ := a.(map[string]any)
		u, _ := m["url"].(string)
		if _, id, ok := strings.Cut(u, "pkg.go.dev/vuln/GO-"); ok && id != "" {
			return "GO-" + id
		}
	}
	return ""
}
