package scanner_test

import (
	"os"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

func componentsByPURL(components []artifact.Component) map[string]artifact.Component {
	out := make(map[string]artifact.Component, len(components))
	for _, c := range components {
		out[c.PURL] = c
	}
	return out
}

func parseFixture(t *testing.T, path string) []artifact.Component {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	components, err := scanner.ParseSBOMComponents(content)
	if err != nil {
		t.Fatalf("ParseSBOMComponents(%s): %v", path, err)
	}
	return components
}

// Both fixtures are trimmed copies of real `trivy image --format
// cyclonedx` / `--format spdx-json` output for the same image, so the
// two formats must produce the same inventory -- that equivalence is
// the actual contract, and it's what a spec-only reading of either
// format gets wrong.
func TestParseSBOMComponents_BothFormatsAgree(t *testing.T) {
	cdx := componentsByPURL(parseFixture(t, "testdata/cyclonedx_sbom_sample.json"))
	spdx := componentsByPURL(parseFixture(t, "testdata/spdx_sbom_sample.json"))

	if len(cdx) == 0 {
		t.Fatal("CycloneDX fixture parsed to nothing")
	}
	if len(cdx) != len(spdx) {
		t.Fatalf("CycloneDX yielded %d components, SPDX %d -- the same image should give the same inventory\ncdx=%v\nspdx=%v",
			len(cdx), len(spdx), cdx, spdx)
	}
	for purl, c := range cdx {
		other, ok := spdx[purl]
		if !ok {
			t.Errorf("%s is in the CycloneDX inventory but not the SPDX one", purl)
			continue
		}
		if c.Name != other.Name || c.Version != other.Version {
			t.Errorf("%s: cyclonedx %+v vs spdx %+v", purl, c, other)
		}
	}

	// A real value from the fixture, spelled out rather than derived, so
	// this fails if the purl stops being carried verbatim (query params
	// and all -- FindByComponentPURL matches exactly).
	const apkTools = "pkg:apk/alpine/apk-tools@2.14.4-r0?arch=x86_64&distro=3.19.9"
	if got, ok := cdx[apkTools]; !ok {
		t.Errorf("expected %q in the parsed inventory, got %v", apkTools, cdx)
	} else if got.Name != "apk-tools" || got.Version != "2.14.4-r0" {
		t.Errorf("apk-tools = %+v, want name/version carried alongside the purl", got)
	}
}

// The document's subject is not one of its own components. CycloneDX
// keeps it in metadata.component (outside the array this parser walks);
// SPDX keeps it in packages[] with primaryPackagePurpose CONTAINER and
// a pkg:oci/... purl, which has to be skipped explicitly or the two
// formats disagree by exactly one row.
func TestParseSBOMComponents_SkipsTheDocumentsOwnSubject(t *testing.T) {
	for _, fixture := range []string{"testdata/cyclonedx_sbom_sample.json", "testdata/spdx_sbom_sample.json"} {
		for purl := range componentsByPURL(parseFixture(t, fixture)) {
			if len(purl) >= 8 && purl[:8] == "pkg:oci/" {
				t.Errorf("%s: %q is the artifact the SBOM describes, not a component of it", fixture, purl)
			}
		}
	}
}

// syft and several other producers express "this package brings in
// these packages" as nested components rather than a flat list. A
// top-level-only walk looks right against trivy's flat output and
// silently under-populates for everything else.
func TestParseSBOMComponents_WalksNestedComponents(t *testing.T) {
	components, err := scanner.ParseSBOMComponents([]byte(`{
	  "bomFormat": "CycloneDX",
	  "components": [
	    {
	      "name": "parent", "version": "1.0", "purl": "pkg:npm/parent@1.0",
	      "components": [
	        { "name": "child", "version": "2.0", "purl": "pkg:npm/child@2.0",
	          "components": [ { "name": "grandchild", "version": "3.0", "purl": "pkg:npm/grandchild@3.0" } ] }
	      ]
	    }
	  ]
	}`))
	if err != nil {
		t.Fatalf("ParseSBOMComponents: %v", err)
	}
	got := componentsByPURL(components)
	for _, want := range []string{"pkg:npm/parent@1.0", "pkg:npm/child@2.0", "pkg:npm/grandchild@3.0"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%q missing from %v", want, got)
		}
	}
}

func TestParseSBOMComponents_SkipsPurllessAndDedupes(t *testing.T) {
	components, err := scanner.ParseSBOMComponents([]byte(`{
	  "bomFormat": "CycloneDX",
	  "components": [
	    { "type": "operating-system", "name": "alpine", "version": "3.19.9" },
	    { "name": "openssl", "version": "3.1.4-r5", "purl": "pkg:apk/alpine/openssl@3.1.4-r5" },
	    { "name": "openssl", "version": "3.1.4-r5", "purl": "pkg:apk/alpine/openssl@3.1.4-r5" },
	    { "name": "blank", "purl": "   " }
	  ]
	}`))
	if err != nil {
		t.Fatalf("ParseSBOMComponents: %v", err)
	}
	if len(components) != 1 {
		t.Fatalf("components = %+v, want just the one identifiable, deduped package", components)
	}
	if components[0].PURL != "pkg:apk/alpine/openssl@3.1.4-r5" {
		t.Fatalf("components[0] = %+v", components[0])
	}
}

func TestParseSBOMComponents_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"not json", "SPDXVersion: SPDX-2.3\nPackageName: openssl"}, // tag-value SPDX, deliberately unsupported
		{"json but neither format", `{"hello":"world"}`},
		{"a VEX document, not an SBOM", `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := scanner.ParseSBOMComponents([]byte(tt.content)); err == nil {
				t.Fatalf("ParseSBOMComponents(%q) = nil error, want a rejection", tt.content)
			}
		})
	}
}

// An empty inventory is a legitimate answer (a document that genuinely
// lists nothing), not an error -- and it must stay distinguishable from
// a parse failure, since SaveComponents treats it as "this artifact now
// contains nothing we could identify".
func TestParseSBOMComponents_EmptyInventoryIsNotAnError(t *testing.T) {
	components, err := scanner.ParseSBOMComponents([]byte(`{"bomFormat":"CycloneDX","components":[]}`))
	if err != nil {
		t.Fatalf("ParseSBOMComponents: %v", err)
	}
	if len(components) != 0 {
		t.Fatalf("components = %+v, want none", components)
	}
}

// licenseOf finds one component by purl and returns its Licenses.
func licenseOf(t *testing.T, components []artifact.Component, purl string) string {
	t.Helper()
	for _, c := range components {
		if c.PURL == purl {
			return c.Licenses
		}
	}
	t.Fatalf("no component with purl %q in %+v", purl, components)
	return ""
}

// CycloneDX expresses licenses three ways, and real trivy output mixes
// them within one document: an SPDX `id`, a free-text `name` when the
// producer could not map it, and an `expression`.
func TestParseSBOMComponents_CycloneDXLicenses(t *testing.T) {
	doc := []byte(`{
	  "bomFormat": "CycloneDX",
	  "components": [
	    {"name":"a","version":"1","purl":"pkg:apk/a@1",
	      "licenses":[{"license":{"id":"MIT"}}]},
	    {"name":"b","version":"1","purl":"pkg:apk/b@1",
	      "licenses":[{"license":{"id":"MIT"}},{"license":{"id":"Apache-2.0"}}]},
	    {"name":"c","version":"1","purl":"pkg:apk/c@1",
	      "licenses":[{"license":{"name":"Some Vendor EULA"}}]},
	    {"name":"d","version":"1","purl":"pkg:apk/d@1",
	      "licenses":[{"expression":"MIT OR AGPL-3.0-only"}]},
	    {"name":"e","version":"1","purl":"pkg:apk/e@1"},
	    {"name":"f","version":"1","purl":"pkg:apk/f@1",
	      "licenses":[{"license":{"id":"NOASSERTION"}}]},
	    {"name":"g","version":"1","purl":"pkg:apk/g@1",
	      "licenses":[{"license":{"id":"MIT"}},{"license":{"id":"mit"}}]}
	  ]
	}`)
	got, err := scanner.ParseSBOMComponents(doc)
	if err != nil {
		t.Fatalf("ParseSBOMComponents: %v", err)
	}

	cases := map[string]string{
		"pkg:apk/a@1": "MIT",
		"pkg:apk/b@1": "MIT,Apache-2.0",
		// An id is preferred, but a free-text name is kept when that is
		// all the document offered -- dropping it would lose the only
		// license information present.
		"pkg:apk/c@1": "Some Vendor EULA",
		// Stored WHOLE. Splitting on OR and matching AGPL-3.0-only
		// against a denylist would flag a package the expression
		// explicitly permits under MIT.
		"pkg:apk/d@1": "MIT OR AGPL-3.0-only",
		"pkg:apk/e@1": "",
		// "no information" placeholders are dropped rather than stored
		// as though NOASSERTION were a license.
		"pkg:apk/f@1": "",
		// Deduped case-insensitively, first spelling kept.
		"pkg:apk/g@1": "MIT",
	}
	for purl, want := range cases {
		if got := licenseOf(t, got, purl); got != want {
			t.Errorf("%s licenses = %q, want %q", purl, got, want)
		}
	}
}

// SPDX carries two fields. licenseConcluded is the producer's
// assessment and wins; declared is what the package claims about
// itself, and is kept alongside when it differs and adds information.
func TestParseSBOMComponents_SPDXLicenses(t *testing.T) {
	doc := []byte(`{
	  "spdxVersion": "SPDX-2.3",
	  "packages": [
	    {"name":"a","versionInfo":"1","licenseConcluded":"MIT","licenseDeclared":"MIT",
	      "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:apk/a@1"}]},
	    {"name":"b","versionInfo":"1","licenseConcluded":"Apache-2.0","licenseDeclared":"MIT",
	      "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:apk/b@1"}]},
	    {"name":"c","versionInfo":"1","licenseConcluded":"NOASSERTION","licenseDeclared":"GPL-2.0-only",
	      "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:apk/c@1"}]},
	    {"name":"d","versionInfo":"1","licenseConcluded":"NOASSERTION","licenseDeclared":"NONE",
	      "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:apk/d@1"}]}
	  ]
	}`)
	got, err := scanner.ParseSBOMComponents(doc)
	if err != nil {
		t.Fatalf("ParseSBOMComponents: %v", err)
	}

	cases := map[string]string{
		// Identical in both fields -- deduped to one.
		"pkg:apk/a@1": "MIT",
		// Concluded first, declared kept after it.
		"pkg:apk/b@1": "Apache-2.0,MIT",
		// A placeholder concluded must not hide a real declared value.
		"pkg:apk/c@1": "GPL-2.0-only",
		// Both placeholders -- nothing usable was said.
		"pkg:apk/d@1": "",
	}
	for purl, want := range cases {
		if got := licenseOf(t, got, purl); got != want {
			t.Errorf("%s licenses = %q, want %q", purl, got, want)
		}
	}
}

// The matching rule, which is the difference between this feature being
// useful and being quietly wrong in either direction.
func TestLicenseDenylist_Matching(t *testing.T) {
	deny := scanner.NewLicenseDenylist("AGPL-3.0-only, SSPL-1.0 ,")

	cases := []struct {
		licenses string
		want     bool
		why      string
	}{
		{"AGPL-3.0-only", true, "exact match"},
		{"agpl-3.0-only", true, "case-insensitive"},
		{"MIT,AGPL-3.0-only", true, "one of several identifiers"},
		{"  SSPL-1.0  ", true, "surrounding whitespace"},
		{"MIT", false, "not denied"},
		{"", false, "no license information"},
		// A substring test would wrongly flag both of these.
		{"LGPL-3.0-only", false, "a different license that merely contains the denied one as a substring"},
		{"MIT OR AGPL-3.0-only", false, "an expression whose OR permits a compliant choice"},
	}
	for _, tc := range cases {
		_, got := deny.Denies(artifact.Component{PURL: "pkg:test/x@1", Licenses: tc.licenses})
		if got != tc.want {
			t.Errorf("Denies(%q) = %v, want %v -- %s", tc.licenses, got, tc.want, tc.why)
		}
	}

	if scanner.NewLicenseDenylist("").Enabled() {
		t.Error("an empty denylist must deny nothing")
	}
	if scanner.NewLicenseDenylist(" , ,").Enabled() {
		t.Error("a denylist of only blanks must deny nothing -- otherwise it matches every unlicensed component")
	}
	// Declared bucket scope, even though nothing consults it today.
	if b := deny.Bucket(); b != "other" {
		t.Errorf("Bucket() = %q, want \"other\"", b)
	}
}

func TestLicenseDenylist_Findings(t *testing.T) {
	deny := scanner.NewLicenseDenylist("AGPL-3.0-only")
	findings := deny.Findings([]artifact.Component{
		{PURL: "pkg:npm/bad@1.0.0", Name: "bad", Licenses: "AGPL-3.0-only"},
		{PURL: "pkg:npm/fine@1.0.0", Name: "fine", Licenses: "MIT"},
	})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.ID != "license:pkg:npm/bad@1.0.0" {
		t.Errorf("ID = %q, want license:<purl>", f.ID)
	}
	if f.Severity != "medium" {
		t.Errorf("Severity = %q, want medium", f.Severity)
	}
	if f.Source != artifact.LicenseFindingSource {
		t.Errorf("Source = %q, want %q", f.Source, artifact.LicenseFindingSource)
	}
	if scanner.NewLicenseDenylist("").Findings([]artifact.Component{{Licenses: "AGPL-3.0-only"}}) != nil {
		t.Error("a disabled denylist must produce no findings")
	}
}
