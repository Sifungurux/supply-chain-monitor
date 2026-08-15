package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// A minimal CycloneDX document with one denied package and one allowed
// one. Built here rather than mutating the shared fixture because these
// tests are about license values specifically, and the fixture carries
// none.
func licensedSBOM(badLicense string) []byte {
	return []byte(`{
	  "bomFormat": "CycloneDX",
	  "components": [
	    {"name":"bad","version":"1.0.0","purl":"pkg:npm/bad@1.0.0",
	      "licenses":[{"license":{"id":"` + badLicense + `"}}]},
	    {"name":"fine","version":"1.0.0","purl":"pkg:npm/fine@1.0.0",
	      "licenses":[{"license":{"id":"MIT"}}]}
	  ]
	}`)
}

func newLicenseRouter(t *testing.T, denylist string, scanners scanner.Registry) (http.Handler, *artifact.MemStore) {
	t.Helper()
	store := artifact.NewMemStore()
	return api.NewRouter(api.Config{
		Store:           store,
		Tracker:         pipeline.NewTracker([]string{"build", "scan"}),
		Scanners:        scanners,
		APIKey:          testAPIKey,
		LicenseDenylist: scanner.NewLicenseDenylist(denylist),
	}), store
}

func otherFindings(t *testing.T, store *artifact.MemStore, id string) []artifact.Finding {
	t.Helper()
	a, err := store.Get(id)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	return a.OtherFindings
}

func findByID(findings []artifact.Finding, id string) *artifact.Finding {
	for i := range findings {
		if findings[i].ID == id {
			return &findings[i]
		}
	}
	return nil
}

// The full lifecycle: a denied license opens a finding, stays open
// while it is still there, and resolves on its own once the package is
// relicensed -- the same open/fixed semantics every scanner finding has.
func TestLicenseDenylist_FindingLifecycle(t *testing.T) {
	h, store := newLicenseRouter(t, "AGPL-3.0-only", scanner.Registry{})
	a := mustCreate(t, store, "app:1.0", artifact.TypeImage)
	// Version-stripped: one finding per package -- see
	// artifact.LicenseFindingID.
	const findingID = "license:pkg:npm/bad"

	// 1. Indexed with a denied license -> one open finding.
	uploadSBOM(t, h, a.ID, licensedSBOM("AGPL-3.0-only"))
	f := findByID(otherFindings(t, store, a.ID), findingID)
	if f == nil {
		t.Fatalf("no license finding after indexing a denied package: %+v", otherFindings(t, store, a.ID))
	}
	if f.Status != artifact.FindingStatusOpen {
		t.Errorf("status = %q, want open", f.Status)
	}
	if f.Severity != "medium" || f.Source != artifact.LicenseFindingSource {
		t.Errorf("finding = %+v, want severity medium and source %q", f, artifact.LicenseFindingSource)
	}
	firstSeen := f.FirstSeenAt

	// 2. Re-indexed unchanged -> still open, and FirstSeenAt is not
	// restamped (it is when it was FIRST seen, not most recently).
	uploadSBOM(t, h, a.ID, licensedSBOM("AGPL-3.0-only"))
	f = findByID(otherFindings(t, store, a.ID), findingID)
	if f == nil || f.Status != artifact.FindingStatusOpen {
		t.Fatalf("finding did not stay open across a re-index: %+v", f)
	}
	if !f.FirstSeenAt.Equal(firstSeen) {
		t.Errorf("FirstSeenAt moved from %s to %s on a re-index", firstSeen, f.FirstSeenAt)
	}

	// 3. Relicensed to something allowed -> resolved, not deleted.
	uploadSBOM(t, h, a.ID, licensedSBOM("MIT"))
	f = findByID(otherFindings(t, store, a.ID), findingID)
	if f == nil {
		t.Fatal("the license finding disappeared instead of being marked fixed")
	}
	if f.Status != artifact.FindingStatusFixed {
		t.Errorf("status = %q, want fixed once the package is relicensed", f.Status)
	}
	if f.ResolvedAt == nil {
		t.Error("a fixed finding has no ResolvedAt")
	}
}

func TestLicenseDenylist_AllowedLicensesProduceNothing(t *testing.T) {
	h, store := newLicenseRouter(t, "AGPL-3.0-only", scanner.Registry{})
	a := mustCreate(t, store, "app:1.0", artifact.TypeImage)

	uploadSBOM(t, h, a.ID, licensedSBOM("MIT"))
	if got := otherFindings(t, store, a.ID); len(got) != 0 {
		t.Errorf("got %d other findings for an all-allowed SBOM: %+v", len(got), got)
	}
}

func TestLicenseDenylist_DisabledProducesNothing(t *testing.T) {
	h, store := newLicenseRouter(t, "", scanner.Registry{})
	a := mustCreate(t, store, "app:1.0", artifact.TypeImage)

	uploadSBOM(t, h, a.ID, licensedSBOM("AGPL-3.0-only"))
	if got := otherFindings(t, store, a.ID); len(got) != 0 {
		t.Errorf("an unconfigured denylist produced %d findings: %+v", len(got), got)
	}
}

// THE HALF THAT CORRUPTS DATA SILENTLY. "other" has two independent
// producers: SARIF/pluggable scanners during a scan, and the license
// evaluator during an SBOM index. Each reports nothing the other
// produces, so merging either against the WHOLE bucket marks all of the
// other's findings "fixed" -- the findings stay visible and simply
// claim to be resolved.
//
// Both directions are asserted here, because each is a different call
// site (scan.go and documents.go) and fixing one would look complete.
func TestLicenseFindings_SurviveAScanAndViceVersa(t *testing.T) {
	sarif := &fakeScanner{findings: []artifact.Finding{
		{ID: "SARIF-001", Severity: "high", Title: "a code smell", Source: "sarif"},
	}}
	h, store := newLicenseRouter(t, "AGPL-3.0-only", scanner.Registry{
		artifact.TypeImage: {sarif},
	})
	a := mustCreate(t, store, "app:1.0", artifact.TypeImage)
	const licenseID = "license:pkg:npm/bad"

	// A license finding exists first.
	uploadSBOM(t, h, a.ID, licensedSBOM("AGPL-3.0-only"))
	lf := findByID(otherFindings(t, store, a.ID), licenseID)
	if lf == nil {
		t.Fatal("setup: no license finding")
	}
	licenseFirstSeen := lf.FirstSeenAt

	// Direction 1: a scan writes to "other" and must not resolve it.
	if rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/scan", nil); rec.Code != http.StatusAccepted && rec.Code != http.StatusOK {
		t.Fatalf("scan status = %d: %s", rec.Code, rec.Body.String())
	}
	waitForScan(t, store, a.ID)

	after := otherFindings(t, store, a.ID)
	lf = findByID(after, licenseID)
	if lf == nil {
		t.Fatal("the license finding vanished during a scan")
	}
	if lf.Status != artifact.FindingStatusOpen {
		t.Errorf("a scan marked the license finding %q -- no scanner reports licenses, so it must be left alone", lf.Status)
	}
	// Its lifecycle metadata must be carried through verbatim, not
	// rebuilt: a partition that restamped it would look correct here
	// unless FirstSeenAt is checked.
	if !lf.FirstSeenAt.Equal(licenseFirstSeen) {
		t.Errorf("the scan restamped the license finding's FirstSeenAt: %s -> %s", licenseFirstSeen, lf.FirstSeenAt)
	}
	if findByID(after, "SARIF-001") == nil {
		t.Error("the scanner's own finding is missing")
	}

	// Direction 2: re-indexing the SBOM must not resolve the scanner's
	// finding, which the license evaluator never reports.
	uploadSBOM(t, h, a.ID, licensedSBOM("AGPL-3.0-only"))
	sf := findByID(otherFindings(t, store, a.ID), "SARIF-001")
	if sf == nil {
		t.Fatal("the scanner's finding vanished during an SBOM index")
	}
	if sf.Status == artifact.FindingStatusFixed {
		t.Error("indexing an SBOM marked the scanner's finding fixed -- the license evaluator reports no SARIF findings, so it must not speak for them")
	}
}

func TestComponents_LicenseFilter(t *testing.T) {
	h, store := newLicenseRouter(t, "", scanner.Registry{})
	denied := mustCreate(t, store, "app-denied:1.0", artifact.TypeImage)
	allowed := mustCreate(t, store, "app-allowed:1.0", artifact.TypeImage)

	uploadSBOM(t, h, denied.ID, licensedSBOM("AGPL-3.0-only"))
	uploadSBOM(t, h, allowed.ID, licensedSBOM("Apache-2.0"))

	get := func(license string) []artifact.Artifact {
		t.Helper()
		rec := doJSON(t, h, http.MethodGet, "/api/v1/components?license="+license, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		var out []artifact.Artifact
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	if got := get("AGPL-3.0-only"); len(got) != 1 || got[0].ID != denied.ID {
		t.Errorf("?license=AGPL-3.0-only returned %+v, want just %s", got, denied.ID)
	}
	// Case-insensitive, like the denylist.
	if got := get("agpl-3.0-only"); len(got) != 1 {
		t.Errorf("?license= should be case-insensitive, got %d results", len(got))
	}
	// MIT is on both (the "fine" package), so both artifacts match.
	if got := get("MIT"); len(got) != 2 {
		t.Errorf("?license=MIT returned %d artifacts, want 2", len(got))
	}
	// Not a substring test.
	if got := get("GPL-3.0-only"); len(got) != 0 {
		t.Errorf("?license=GPL-3.0-only matched %d artifacts -- it must not match LGPL/AGPL as substrings", len(got))
	}
	// A license nothing carries is an empty list, not an error.
	if got := get("Zlib"); len(got) != 0 {
		t.Errorf("an unmatched license returned %+v, want empty", got)
	}
}

// Licenses have to reach the picker, which is what the dashboard shows.
func TestComponents_SearchCarriesLicenses(t *testing.T) {
	h, store := newLicenseRouter(t, "", scanner.Registry{})
	a := mustCreate(t, store, "app:1.0", artifact.TypeImage)
	uploadSBOM(t, h, a.ID, licensedSBOM("AGPL-3.0-only"))

	rec := doJSON(t, h, http.MethodGet, "/api/v1/components?q=bad", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Packages []artifact.ComponentMatch `json:"packages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Packages) != 1 {
		t.Fatalf("got %d packages, want 1: %+v", len(out.Packages), out.Packages)
	}
	if out.Packages[0].Licenses != "AGPL-3.0-only" {
		t.Errorf("licenses = %q, want AGPL-3.0-only", out.Packages[0].Licenses)
	}
}

// licensedSBOMAt is licensedSBOM with the denied package at a chosen
// version, for exercising an upgrade.
func licensedSBOMAt(version, badLicense string) []byte {
	return []byte(`{
	  "bomFormat": "CycloneDX",
	  "components": [
	    {"name":"bad","version":"` + version + `","purl":"pkg:npm/bad@` + version + `",
	      "licenses":[{"license":{"id":"` + badLicense + `"}}]}
	  ]
	}`)
}

// THE REASON THE ID IS VERSION-STRIPPED. A denylisted package that
// bumps version is still the same unresolved compliance problem. Keyed
// on the full purl it resolved the old finding and opened a new one on
// every bump -- so a weekly-bumping dependency left a year of dimmed
// "fixed" rows for something nobody ever fixed, and FirstSeenAt read
// "since Tuesday" instead of "for eight months".
func TestLicenseFinding_SurvivesAVersionBump(t *testing.T) {
	h, store := newLicenseRouter(t, "AGPL-3.0-only", scanner.Registry{})
	a := mustCreate(t, store, "app:1.0", artifact.TypeImage)

	uploadSBOM(t, h, a.ID, licensedSBOMAt("1.0.0", "AGPL-3.0-only"))
	first := otherFindings(t, store, a.ID)
	if len(first) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(first), first)
	}
	firstSeen := first[0].FirstSeenAt

	// Three upgrades, still the same denied license.
	for _, v := range []string{"1.1.0", "1.2.0", "1.3.0"} {
		uploadSBOM(t, h, a.ID, licensedSBOMAt(v, "AGPL-3.0-only"))
	}

	after := otherFindings(t, store, a.ID)
	if len(after) != 1 {
		t.Fatalf("three version bumps produced %d findings, want 1 -- the problem never changed: %+v", len(after), after)
	}
	if after[0].Status != artifact.FindingStatusOpen {
		t.Errorf("status = %q, want open -- the package is still denylisted", after[0].Status)
	}
	if !after[0].FirstSeenAt.Equal(firstSeen) {
		t.Errorf("FirstSeenAt moved from %s to %s across version bumps -- it should say how long this has been true",
			firstSeen, after[0].FirstSeenAt)
	}
	// The Title tracks the CURRENT release, so the finding still says
	// which version is in there now.
	if !strings.Contains(after[0].Title, "AGPL-3.0-only") {
		t.Errorf("title = %q, want it to name the denied license", after[0].Title)
	}

	// And it still resolves when the package is actually relicensed.
	uploadSBOM(t, h, a.ID, licensedSBOMAt("2.0.0", "MIT"))
	resolved := otherFindings(t, store, a.ID)
	if len(resolved) != 1 || resolved[0].Status != artifact.FindingStatusFixed {
		t.Errorf("after relicensing: %+v, want the single finding marked fixed", resolved)
	}
}

// The other reason: VEX suppression keys on the finding ID, so an
// accepted exception ("this AGPL tool is dev-only, we accept it") used
// to evaporate at the next version bump. An exception that expires when
// the version changes is not an exception.
func TestLicenseFinding_VEXExceptionSurvivesAVersionBump(t *testing.T) {
	h, store := newLicenseRouter(t, "AGPL-3.0-only", scanner.Registry{})
	a := mustCreate(t, store, "app:1.0", artifact.TypeImage)

	uploadSBOM(t, h, a.ID, licensedSBOMAt("1.0.0", "AGPL-3.0-only"))

	// Accept it, keyed on the finding id the API reports.
	vexDoc := []byte(`{
	  "@context": "https://openvex.dev/ns/v0.2.0",
	  "statements": [
	    {"vulnerability": {"name": "license:pkg:npm/bad"},
	     "status": "not_affected",
	     "justification": "component_not_present"}
	  ]
	}`)
	if rec := doRaw(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/vex", "application/json", vexDoc); rec.Code != http.StatusOK {
		t.Fatalf("vex upload status = %d: %s", rec.Code, rec.Body.String())
	}
	suppressed := otherFindings(t, store, a.ID)
	if len(suppressed) != 1 || suppressed[0].Status != artifact.FindingStatusNotAffected {
		t.Fatalf("setup: finding not suppressed by VEX: %+v", suppressed)
	}

	// Bump the version. The exception must still hold.
	uploadSBOM(t, h, a.ID, licensedSBOMAt("1.1.0", "AGPL-3.0-only"))

	after := otherFindings(t, store, a.ID)
	if len(after) != 1 {
		t.Fatalf("got %d findings after a bump, want 1: %+v", len(after), after)
	}
	if after[0].Status != artifact.FindingStatusNotAffected {
		t.Errorf("status = %q after a version bump, want the accepted exception to still hold", after[0].Status)
	}
}
