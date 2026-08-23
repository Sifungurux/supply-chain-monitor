package scanner

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// ParseVEX reads a VEX document in either of the two formats this
// project is likely to be handed one in -- OpenVEX (openvex.dev, what
// `vexctl` produces) or CycloneDX with an `analysis` block per
// vulnerability (what `cyclonedx` tooling and several scanners emit) --
// and returns the statements it understood.
//
// The two are told apart by shape, not by a version/context string: an
// OpenVEX document has a top-level `statements` array, a CycloneDX one
// has `vulnerabilities`. Sniffing the shape means a document that omits
// or misspells `@context` (routine in hand-written VEX) still parses,
// and it's one json.Unmarshal into a struct that has both fields rather
// than a probe-then-reparse.
//
// Deliberately lenient about everything except being JSON at all:
// unknown fields are ignored, a statement with no vulnerability ID or
// no status is skipped, and an unrecognized status string is passed
// through verbatim for MergeFindings to ignore (see vexSuppresses --
// anything it doesn't recognize suppresses nothing, so a typo shows a
// real vulnerability rather than hiding one). An error comes back only
// when the bytes aren't JSON or the document has neither array, since
// those are the two cases where the operator has uploaded something
// that was never going to do anything and should be told so.
func ParseVEX(content []byte) ([]artifact.VEXStatement, error) {
	var doc struct {
		// OpenVEX
		Statements []struct {
			// OpenVEX's `vulnerability` was a bare string in 0.0.1 and
			// became an object with a `name` in 0.2.0 -- both shapes are
			// still in the wild, so both are accepted (see vexVuln).
			Vulnerability vexVuln `json:"vulnerability"`
			Status        string  `json:"status"`
			Justification string  `json:"justification"`
			// ImpactStatement is what OpenVEX asks for when a
			// not_affected statement's reason isn't one of the five
			// enumerated justifications -- used as the justification here
			// when the enumerated field is absent, since for our purposes
			// they answer the same question ("why doesn't this apply?").
			ImpactStatement string `json:"impact_statement"`
		} `json:"statements"`
		// CycloneDX VEX
		Vulnerabilities []struct {
			ID       string `json:"id"`
			Analysis struct {
				State         string `json:"state"`
				Justification string `json:"justification"`
				Detail        string `json:"detail"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("parse VEX document: %w", err)
	}
	if doc.Statements == nil && doc.Vulnerabilities == nil {
		return nil, fmt.Errorf("not a VEX document: no OpenVEX \"statements\" or CycloneDX \"vulnerabilities\" array")
	}

	// ponytail: OpenVEX `products`/`subcomponents` are ignored HERE on
	// purpose, and only here. A document uploaded through
	// POST /api/v1/artifacts/{id}/vex has already been told which
	// artifact it is about, so matching purls against Artifact.Ref/
	// Digest as well would only ever reject statements the uploader
	// meant to apply.
	//
	// The fleet-wide endpoint has no such context and does read them:
	// see ParseVEXProducts below.
	var out []artifact.VEXStatement
	for _, s := range doc.Statements {
		id := strings.TrimSpace(s.Vulnerability.name())
		if id == "" {
			continue
		}
		justification := s.Justification
		if justification == "" {
			justification = s.ImpactStatement
		}
		out = append(out, artifact.VEXStatement{
			VulnID:        id,
			Status:        normalizeVEXStatus(s.Status),
			Justification: strings.TrimSpace(justification),
		})
	}
	for _, v := range doc.Vulnerabilities {
		id := strings.TrimSpace(v.ID)
		if id == "" {
			continue
		}
		justification := v.Analysis.Justification
		if justification == "" {
			justification = v.Analysis.Detail
		}
		out = append(out, artifact.VEXStatement{
			VulnID:        id,
			Status:        normalizeVEXStatus(v.Analysis.State),
			Justification: strings.TrimSpace(justification),
		})
	}
	return out, nil
}

// vexVuln accepts OpenVEX's `vulnerability` in both the shapes that
// exist in the wild: the 0.0.1 bare string ("CVE-2024-1234") and the
// 0.2.0 object ({"name": "CVE-2024-1234", ...}). Anything else (a
// number, an array) unmarshals to an empty name and the statement is
// skipped rather than failing the whole document.
type vexVuln struct {
	Name string `json:"name"`
	ID   string `json:"@id"`
	raw  string
}

func (v *vexVuln) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &v.raw); err == nil {
		return nil
	}
	var obj struct {
		Name string `json:"name"`
		ID   string `json:"@id"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil
	}
	v.Name, v.ID = obj.Name, obj.ID
	return nil
}

func (v vexVuln) name() string {
	if v.raw != "" {
		return v.raw
	}
	if v.Name != "" {
		return v.Name
	}
	return v.ID
}

// normalizeVEXStatus maps both vocabularies onto the four statuses this
// service speaks (artifact.VEXStatement.Status). OpenVEX already uses
// those four verbatim; CycloneDX's `analysis.state` uses its own enum,
// mapped here:
//
//	not_affected, false_positive     -> not_affected
//	resolved, resolved_with_pedigree -> fixed
//	exploitable                      -> affected
//	in_triage                        -> under_investigation
//
// "false_positive" maps to not_affected rather than fixed for the same
// reason applyVEX treats them differently: nothing was resolved, the
// finding just doesn't apply here.
//
// Case- and separator-insensitive (some tooling writes
// "NOT_AFFECTED", some "notAffected"), and anything unrecognized comes
// back lowercased-verbatim so MergeFindings can ignore it rather than
// this guessing.
func normalizeVEXStatus(status string) string {
	s := strings.ToLower(strings.TrimSpace(status))
	s = strings.NewReplacer("-", "_", " ", "_").Replace(s)
	switch s {
	case "notaffected", "false_positive":
		return artifact.FindingStatusNotAffected
	case "resolved", "resolved_with_pedigree":
		return artifact.FindingStatusFixed
	case "exploitable":
		return artifact.VEXStatusAffected
	case "in_triage", "underinvestigation":
		return artifact.VEXStatusUnderInvestigation
	}
	return s
}

// ParseVEXProducts is ParseVEX for the fleet-wide endpoint
// (POST /api/v1/vex): same statements, but each one keeps the product
// identifiers it was made about, so the caller can work out which
// artifacts it applies to.
//
// OpenVEX only, and that is not an oversight. CycloneDX expresses the
// same idea through `affects[].ref`, which points at bom-refs INSIDE
// the document's own component tree -- resolving those means resolving
// a whole CycloneDX BOM, not reading an identifier. A CycloneDX
// document uploaded here parses to zero product-scoped statements and
// is refused by the handler with a message saying so, which is a much
// better outcome than silently matching nothing.
//
// Lenient in exactly the ways ParseVEX is: a statement with no
// vulnerability ID is skipped, an unrecognized status is passed through
// for vexSuppresses to ignore, and a statement naming no product is
// KEPT -- with an empty Products, so it matches nothing. The handler
// counts those and reports them, rather than this quietly dropping
// them; "my document did nothing" is much easier to debug when the
// count of unmatched statements comes back in the response.
func ParseVEXProducts(content []byte) ([]artifact.ProductVEXStatement, error) {
	var doc struct {
		Statements []struct {
			Vulnerability   vexVuln      `json:"vulnerability"`
			Status          string       `json:"status"`
			Justification   string       `json:"justification"`
			ImpactStatement string       `json:"impact_statement"`
			Products        []vexProduct `json:"products"`
		} `json:"statements"`
	}

	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("parse VEX document: %w", err)
	}
	if doc.Statements == nil {
		return nil, fmt.Errorf("not an OpenVEX document: no \"statements\" array")
	}

	var out []artifact.ProductVEXStatement
	for _, s := range doc.Statements {
		id := strings.TrimSpace(s.Vulnerability.name())
		if id == "" {
			continue
		}
		justification := s.Justification
		if justification == "" {
			justification = s.ImpactStatement
		}
		var products []string
		for _, p := range s.Products {
			products = append(products, p.identifiers()...)
		}
		out = append(out, artifact.ProductVEXStatement{
			VEXStatement: artifact.VEXStatement{
				VulnID:        id,
				Status:        normalizeVEXStatus(s.Status),
				Justification: strings.TrimSpace(justification),
			},
			Products: dedupeStrings(products),
		})
	}
	return out, nil
}

// vexProduct accepts an OpenVEX `products` entry in both shapes that
// exist in the wild, the same way vexVuln does for `vulnerability`: the
// 0.0.1 bare string ("pkg:apk/wolfi/bash@1.0.0") and the 0.2.0 object
// carrying an `@id`, an `identifiers` map and a `hashes` map.
type vexProduct struct {
	ID          string            `json:"@id"`
	Identifiers map[string]string `json:"identifiers"`
	Hashes      map[string]string `json:"hashes"`
	raw         string
}

func (p *vexProduct) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &p.raw); err == nil {
		return nil
	}
	var obj struct {
		ID          string            `json:"@id"`
		Identifiers map[string]string `json:"identifiers"`
		Hashes      map[string]string `json:"hashes"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		// Anything else (a number, an array) contributes no identifiers
		// rather than failing the document -- same call ParseVEX makes
		// for a malformed `vulnerability`.
		return nil
	}
	p.ID, p.Identifiers, p.Hashes = obj.ID, obj.Identifiers, obj.Hashes
	return nil
}

// identifiers returns every string this product entry offers as a way
// to name itself, in no particular order and with no interpretation.
// Deciding which of them identifies a known artifact is the store's
// job, not this parser's -- a purl might name the artifact itself or a
// component inside it, and only the store knows which.
//
// Hash values are returned in the "sha256:<hex>" form Artifact.Digest
// uses, since OpenVEX carries the algorithm as the map KEY and the bare
// hex as the value. Both "sha-256" (the spec's spelling) and "sha256"
// (what several tools emit) are accepted.
func (p vexProduct) identifiers() []string {
	var out []string
	add := func(v string) {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	add(p.raw)
	add(p.ID)
	for _, v := range p.Identifiers {
		add(v)
	}
	for alg, v := range p.Hashes {
		switch strings.ToLower(strings.TrimSpace(alg)) {
		case "sha-256", "sha256":
			if v = strings.TrimSpace(v); v != "" {
				add("sha256:" + strings.ToLower(v))
			}
		}
	}
	return out
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
