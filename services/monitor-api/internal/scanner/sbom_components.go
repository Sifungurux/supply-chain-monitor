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
			add(artifact.Component{PURL: c.PURL, Name: c.Name, Version: c.Version})
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
			add(artifact.Component{PURL: ref.ReferenceLocator, Name: p.Name, Version: p.VersionInfo})
			break
		}
	}
	return out, nil
}

// cycloneDXComponent is its own named type purely so the nested
// `components` array can refer to it recursively.
type cycloneDXComponent struct {
	Name       string               `json:"name"`
	Version    string               `json:"version"`
	PURL       string               `json:"purl"`
	Components []cycloneDXComponent `json:"components"`
}
