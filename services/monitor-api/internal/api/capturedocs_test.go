package api_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// rawReportScanner stands in for the in-process TrivyScanner: it
// implements RawImageScanner by handing back a raw report alongside its
// findings. The existing fakeScanner cannot exercise this path, since
// the whole behaviour hangs off ScanWithRaw being present.
type rawReportScanner struct {
	raw      []byte
	findings []artifact.Finding
	err      error
}

func (r *rawReportScanner) Scan(context.Context, string) ([]artifact.Finding, error) {
	return r.findings, r.err
}

func (r *rawReportScanner) ScanWithRaw(context.Context, string) ([]artifact.Finding, []byte, error) {
	return r.findings, r.raw, r.err
}

// fakeTrivyOnPath puts a `trivy` on PATH that answers `convert` with a
// canned document. GenerateImageDocuments shells out to the real binary
// (exec.CommandContext(ctx, "trivy", ...), resolved via PATH), so
// without this the conversion fails and the test proves nothing about
// what happens AFTER a document is produced -- which is the whole point.
func fakeTrivyOnPath(t *testing.T, sbomJSON string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"# Answer `trivy convert --format cyclonedx ...` with a fixed SBOM,\n" +
		"# and anything else with an empty JSON object.\n" +
		"for a in \"$@\"; do\n" +
		"  if [ \"$a\" = \"cyclonedx\" ]; then cat <<'SBOM'\n" +
		sbomJSON + "\n" +
		"SBOM\n" +
		"    exit 0\n" +
		"  fi\n" +
		"done\n" +
		"echo '{}'\n"
	path := filepath.Join(dir, "trivy")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake trivy: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// THE GAP THIS CLOSES. Document capture used to live only in the scan
// worker's image branch, so an in-process scan (DISABLE_SCAN_ISOLATION,
// the local dev path) produced no SBOM document -- and since component
// indexing is triggered BY that document arriving, the artifact also
// got no components, no snapshot history and no license findings, while
// the scan itself reported complete success.
func TestScan_InProcessImageScanCapturesDocumentsAndIndexes(t *testing.T) {
	fakeTrivyOnPath(t, `{
	  "bomFormat": "CycloneDX",
	  "components": [
	    {"name":"openssl","version":"3.1.4-r5","purl":"pkg:apk/alpine/openssl@3.1.4-r5",
	      "licenses":[{"license":{"id":"Apache-2.0"}}]}
	  ]
	}`)

	store := artifact.NewMemStore()
	h := api.NewRouter(api.Config{
		Store:   store,
		Tracker: pipeline.NewTracker([]string{"build", "scan"}),
		APIKey:  testAPIKey,
		Scanners: scanner.Registry{artifact.TypeImage: {&rawReportScanner{
			raw:      []byte(`{"Results":[]}`),
			findings: []artifact.Finding{{ID: "CVE-2024-1", Severity: "high", Source: "trivy"}},
		}}},
	})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	if rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/scan", nil); rec.Code != http.StatusAccepted && rec.Code != http.StatusOK {
		t.Fatalf("scan status = %d: %s", rec.Code, rec.Body.String())
	}
	if got := waitForScan(t, store, a.ID); got.Status == artifact.StatusFailed {
		t.Fatalf("scan failed: %v", got.LastScanErrors)
	}

	// 1. The SBOM document exists, as it would after an isolated scan
	// uploaded one.
	waitForComponentSnapshots(t, store, a.ID, 1)
	doc, err := store.GetDocument(a.ID, artifact.DocumentKindSBOM)
	if err != nil {
		t.Fatalf("GetDocument: %v", err)
	}
	if doc == nil {
		t.Fatal("no SBOM document stored after an in-process image scan")
	}

	// 2. Its components are indexed and searchable -- the document
	// storing without indexing is the failure mode a parallel
	// persistence path would reintroduce.
	found, err := store.FindByComponentPURL("pkg:apk/alpine/openssl@3.1.4-r5")
	if err != nil {
		t.Fatalf("FindByComponentPURL: %v", err)
	}
	if len(found) != 1 || found[0].ID != a.ID {
		t.Errorf("component search found %+v, want the scanned artifact", found)
	}

	// 3. Licenses came through, so ?license= and the denylist work for
	// in-process scans too.
	if arts, err := store.FindByLicense("Apache-2.0"); err != nil || len(arts) != 1 {
		t.Errorf("FindByLicense = %v, %v -- want the scanned artifact", arts, err)
	}
}

// A second scan gives the diff endpoint the two snapshots it needs --
// the user-visible symptom that started this ("Not enough SBOM history
// yet" forever).
func TestScan_InProcessScansAccumulateSnapshotHistory(t *testing.T) {
	fakeTrivyOnPath(t, `{"bomFormat":"CycloneDX","components":[
	  {"name":"openssl","version":"3.1.4-r5","purl":"pkg:apk/alpine/openssl@3.1.4-r5"}]}`)

	store := artifact.NewMemStore()
	h := api.NewRouter(api.Config{
		Store:    store,
		Tracker:  pipeline.NewTracker([]string{"build", "scan"}),
		APIKey:   testAPIKey,
		Scanners: scanner.Registry{artifact.TypeImage: {&rawReportScanner{raw: []byte(`{"Results":[]}`)}}},
	})
	a := mustCreate(t, store, "alpine:3.19", artifact.TypeImage)

	for i := 0; i < 2; i++ {
		doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/scan", nil)
		waitForScan(t, store, a.ID)
		waitForComponentSnapshots(t, store, a.ID, i+1)
	}

	diff := fetchDiff(t, h, a.ID, "")
	if diff["from"] == nil || diff["to"] == nil {
		t.Errorf("after two scans the diff still has nothing to compare: %v", diff)
	}
}

// A non-image artifact must NOT be routed through image document
// generation: the raw report would not be an image trivy report, and
// converting it would produce garbage rather than nothing.
func TestScan_NonImageTypesSkipDocumentCapture(t *testing.T) {
	fakeTrivyOnPath(t, `{"bomFormat":"CycloneDX","components":[]}`)

	store := artifact.NewMemStore()
	h := api.NewRouter(api.Config{
		Store:    store,
		Tracker:  pipeline.NewTracker([]string{"build", "scan"}),
		APIKey:   testAPIKey,
		Scanners: scanner.Registry{artifact.TypeSARIF: {&rawReportScanner{raw: []byte(`{"Results":[]}`)}}},
	})
	a := mustCreate(t, store, "scm-registry:5000/report:1", artifact.TypeSARIF)

	doJSON(t, h, http.MethodPost, "/api/v1/artifacts/"+a.ID+"/scan", nil)
	waitForScan(t, store, a.ID)

	if doc, _ := store.GetDocument(a.ID, artifact.DocumentKindSBOM); doc != nil {
		t.Error("a sarif-type artifact got an image-derived SBOM document")
	}
}
