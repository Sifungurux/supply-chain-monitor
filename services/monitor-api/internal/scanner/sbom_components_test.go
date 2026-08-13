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
