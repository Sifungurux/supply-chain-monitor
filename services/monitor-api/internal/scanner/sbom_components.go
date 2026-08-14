package scanner

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// ParseSBOMComponents reads an ingested SBOM document and returns the
// packages it lists, so they can be normalized into rows and queried
// ("which of our artifacts contain this exact package") instead of
// staying a blob nothing can look inside -- see
// artifact.Store.FindByComponentPURL.
//
// Both formats this project actually receives are handled, told apart
// by shape rather than by a version field: a CycloneDX document has a
// `components` array, an SPDX one has `packages`. Same sniffing
// ParseVEX (vex.go) uses, for the same reason -- it survives a document
// whose `bomFormat`/`spdxVersion` is missing or misspelled, which
// hand-assembled SBOMs routinely are.
//
// Verified against real output from this project's own pinned trivy
// (`trivy image --format cyclonedx` and `--format spdx-json`), not from
// the specs alone -- see testdata/cyclonedx_sbom_sample.json and
// testdata/spdx_sbom_sample.json, which are trimmed copies of exactly
// that.
//
// Components with no purl are skipped. A purl is the identity this
// whole feature queries on, so a component without one can never be
// found by the endpoint it exists to serve -- storing it would add rows
// that answer nothing. (In practice this is the CycloneDX
// `operating-system` entry and the occasional file-level component.)
//
// ponytail: JSON only. SPDX also has a tag-value serialization, which
// no path in this service produces or accepts today -- a
// tag-value document is rejected here as unparseable rather than
// silently returning zero components. Add a second parser if an
// ingestion path ever hands us one.
func ParseSBOMComponents(content []byte) ([]artifact.Component, error) {
	var doc struct {
		// CycloneDX
		Components []cycloneDXComponent `json:"components"`
		// SPDX
		Packages []struct {
			Name        string `json:"name"`
			VersionInfo string `json:"versionInfo"`
			// SPDX carries two license fields per package.
			// licenseConcluded is the producer's assessment, declared is
			// what the package itself claims -- concluded wins when both
			// are present and disagree, since it is the considered
			// answer. Both are frequently the placeholders "NOASSERTION"
			// or "NONE", which are dropped rather than stored as if they
			// were licenses (see normalizeLicenses).
			LicenseConcluded string `json:"licenseConcluded"`
			LicenseDeclared  string `json:"licenseDeclared"`
			// PrimaryPackagePurpose is "CONTAINER" on the package
			// describing the image the document is ABOUT (confirmed in
			// trivy's spdx-json output, where it's packages[0] and
			// carries a pkg:oci/... purl). That's the artifact itself,
			// not something it contains -- and CycloneDX agrees, keeping
			// the same entry in `metadata.component`, outside
			// `components`. Skipped so the two formats produce the same
			// inventory for the same image.
			PrimaryPackagePurpose string `json:"primaryPackagePurpose"`
			ExternalRefs          []struct {
				ReferenceType    string `json:"referenceType"`
				ReferenceLocator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}

	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("parse SBOM document: %w", err)
	}
	if doc.Components == nil && doc.Packages == nil {
		return nil, fmt.Errorf("not an SBOM document: no CycloneDX \"components\" or SPDX \"packages\" array")
	}

	// Deduped by purl as they're collected: one document can list the
	// same package more than once (pulled in through two dependency
	// paths), and the components table's UNIQUE (artifact_id, purl)
	// would reject the repeat anyway.
	seen := make(map[string]bool)
	out := make([]artifact.Component, 0, len(doc.Components)+len(doc.Packages))
	add := func(c artifact.Component) {
		c.PURL = strings.TrimSpace(c.PURL)
		if c.PURL == "" || seen[c.PURL] {
			return
		}
		seen[c.PURL] = true
		out = append(out, c)
	}

	var walk func(components []cycloneDXComponent)
	walk = func(components []cycloneDXComponent) {
		for _, c := range components {
			add(artifact.Component{
				PURL: c.PURL, Name: c.Name, Version: c.Version,
				Licenses: normalizeLicenses(c.licenseIDs()),
			})
			// CycloneDX components nest: syft and several other
			// producers express "this package brings in these packages"
			// as a child array rather than flattening. A top-level-only
			// walk looks correct against trivy's flat output and
			// silently under-populates for everything else.
			walk(c.Components)
		}
	}
	walk(doc.Components)

	for _, p := range doc.Packages {
		if strings.EqualFold(p.PrimaryPackagePurpose, "CONTAINER") {
			continue
		}
		for _, ref := range p.ExternalRefs {
			// Case-insensitive: the SPDX spec's own examples and real
			// producers disagree on "purl" vs "PURL".
			if !strings.EqualFold(strings.TrimSpace(ref.ReferenceType), "purl") {
				continue
			}
			add(artifact.Component{
				PURL: ref.ReferenceLocator, Name: p.Name, Version: p.VersionInfo,
				// Concluded first: it is the producer's considered
				// answer, where declared is only what the package says
				// about itself. Both are listed when they differ and
				// both carry information.
				Licenses: normalizeLicenses([]string{p.LicenseConcluded, p.LicenseDeclared}),
			})
			break
		}
	}
	return out, nil
}

// cycloneDXComponent is its own named type purely so the nested
// `components` array can refer to it recursively.
type cycloneDXComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	// CycloneDX expresses licenses as a list whose entries are EITHER a
	// `license` object (with an SPDX `id`, or a free-text `name` when
	// the producer could not map it to one) OR an `expression`
	// ("MIT OR Apache-2.0"). Both shapes appear in real trivy output,
	// sometimes within one document, so both are read.
	Licenses []struct {
		License struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"license"`
		Expression string `json:"expression"`
	} `json:"licenses"`
	Components []cycloneDXComponent `json:"components"`
}

// licenseIDs pulls the identifiers out of one CycloneDX component,
// preferring the SPDX `id` over the free-text `name` for a given entry
// (the id is the machine-comparable one, which is the whole point of
// storing these) and taking `expression` as its own single identifier.
//
// An expression is deliberately NOT split on its operators. "MIT OR
// AGPL-3.0-only" means a consumer may choose MIT, so decomposing it and
// matching AGPL-3.0-only against a denylist would flag a package that
// can be used compliantly -- a false positive on the one signal this
// data exists to produce. It is stored whole, and matched whole. See
// LicenseDenylist.
func (c cycloneDXComponent) licenseIDs() []string {
	out := make([]string, 0, len(c.Licenses))
	for _, l := range c.Licenses {
		switch {
		case strings.TrimSpace(l.License.ID) != "":
			out = append(out, l.License.ID)
		case strings.TrimSpace(l.License.Name) != "":
			out = append(out, l.License.Name)
		case strings.TrimSpace(l.Expression) != "":
			out = append(out, l.Expression)
		}
	}
	return out
}

// normalizeLicenses trims, drops SPDX's "no information" placeholders,
// dedupes case-insensitively while keeping the first spelling seen, and
// joins with commas -- the form artifact.Component.Licenses stores.
//
// NOASSERTION and NONE are dropped rather than stored: both mean "this
// document is not telling you the license", and keeping them would make
// a package with no license information indistinguishable from one
// licensed under something actually called NOASSERTION, while filling
// the column with noise on the many real packages that carry them.
func normalizeLicenses(ids []string) string {
	seen := make(map[string]bool, len(ids))
	kept := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		switch strings.ToUpper(id) {
		case "NOASSERTION", "NONE":
			continue
		}
		key := strings.ToLower(id)
		if seen[key] {
			continue
		}
		seen[key] = true
		kept = append(kept, id)
	}
	return strings.Join(kept, ",")
}
