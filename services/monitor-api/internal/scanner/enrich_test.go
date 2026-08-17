package scanner

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

type fakeEnrichStore struct {
	kev       []string
	epss      map[string]float64
	at        time.Time
	replaced  int
	lookupErr error
	data      map[string]artifact.Enrichment
}

func (f *fakeEnrichStore) ReplaceEnrichment(kev []string, epss map[string]float64, at time.Time) error {
	f.replaced++
	if kev != nil {
		f.kev = kev
	}
	if epss != nil {
		f.epss = epss
	}
	f.at = at
	return nil
}

func (f *fakeEnrichStore) LookupEnrichment(ids []string) (map[string]artifact.Enrichment, error) {
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	out := map[string]artifact.Enrichment{}
	for _, id := range ids {
		if e, ok := f.data[strings.ToUpper(id)]; ok {
			out[strings.ToUpper(id)] = e
		}
	}
	return out, nil
}

func gzipped(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(body)); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	zw.Close()
	return buf.Bytes()
}

// The real EPSS file opens with a "#model_version" comment BEFORE the
// header row, which is why the parser cannot just take the first line
// as the header.
const sampleEPSS = `#model_version:v2025.03.14,score_date:2026-08-17T00:00:00Z
cve,epss,percentile
CVE-2024-1111,0.97231,0.99912
CVE-2024-2222,0.00042,0.10000
`

const sampleKEV = `{"title":"CISA KEV","count":2,"vulnerabilities":[
  {"cveID":"CVE-2024-1111","vendorProject":"Example"},
  {"cveID":"CVE-2023-9999","vendorProject":"Other"}
]}`

func feedServer(t *testing.T, kev string, epss []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "kev"):
			if kev == "" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(kev))
		default:
			if epss == nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(epss)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEnricher_Refresh(t *testing.T) {
	t.Run("parses both feeds", func(t *testing.T) {
		srv := feedServer(t, sampleKEV, gzipped(t, sampleEPSS))
		t.Setenv(KEVFeedURLEnv, srv.URL+"/kev.json")
		t.Setenv(EPSSFeedURLEnv, srv.URL+"/epss.csv.gz")

		store := &fakeEnrichStore{}
		if err := NewEnricher(store).Refresh(context.Background(), time.Now()); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if len(store.kev) != 2 {
			t.Fatalf("kev = %v, want 2 entries", store.kev)
		}
		// Read by COLUMN NAME: percentile (0.99912) must not be
		// mistaken for the score (0.97231).
		if got := store.epss["CVE-2024-1111"]; got != 0.97231 {
			t.Fatalf("epss[CVE-2024-1111] = %v, want 0.97231 (the score column, not percentile)", got)
		}
		if got := store.epss["CVE-2024-2222"]; got != 0.00042 {
			t.Fatalf("epss[CVE-2024-2222] = %v, want 0.00042", got)
		}
	})

	// A failed download must NOT be reported as success: the CronJob's
	// exit status is the only signal anyone watches, and enrichment
	// that silently stops updating is a red badge that never appears --
	// which reads as good news.
	t.Run("one feed failing still stores the other and still errors", func(t *testing.T) {
		srv := feedServer(t, "", gzipped(t, sampleEPSS)) // KEV 500s
		t.Setenv(KEVFeedURLEnv, srv.URL+"/kev.json")
		t.Setenv(EPSSFeedURLEnv, srv.URL+"/epss.csv.gz")

		store := &fakeEnrichStore{}
		err := NewEnricher(store).Refresh(context.Background(), time.Now())
		if err == nil {
			t.Fatal("Refresh reported success with a failed KEV download")
		}
		if !strings.Contains(err.Error(), "kev") {
			t.Errorf("error = %v, want it to name the feed that failed", err)
		}
		if len(store.epss) == 0 {
			t.Error("the EPSS feed downloaded fine but was discarded because KEV failed")
		}
		if store.kev != nil {
			t.Error("a failed KEV download still replaced the stored catalog")
		}
	})

	// Replacing a good catalogue with an empty one would clear every
	// known_exploited flag -- worse than keeping yesterday's data.
	t.Run("refuses an empty catalog rather than wiping the stored one", func(t *testing.T) {
		srv := feedServer(t, `{"vulnerabilities":[]}`, gzipped(t, sampleEPSS))
		t.Setenv(KEVFeedURLEnv, srv.URL+"/kev.json")
		t.Setenv(EPSSFeedURLEnv, srv.URL+"/epss.csv.gz")

		store := &fakeEnrichStore{}
		err := NewEnricher(store).Refresh(context.Background(), time.Now())
		if err == nil {
			t.Fatal("an empty KEV catalog was accepted")
		}
		if store.kev != nil {
			t.Error("an empty catalog replaced the stored one")
		}
	})

	t.Run("refuses an empty EPSS feed too", func(t *testing.T) {
		srv := feedServer(t, sampleKEV, gzipped(t, "#comment\ncve,epss,percentile\n"))
		t.Setenv(KEVFeedURLEnv, srv.URL+"/kev.json")
		t.Setenv(EPSSFeedURLEnv, srv.URL+"/epss.csv.gz")

		store := &fakeEnrichStore{}
		if err := NewEnricher(store).Refresh(context.Background(), time.Now()); err == nil {
			t.Fatal("an empty EPSS feed was accepted")
		}
		if store.epss != nil {
			t.Error("an empty feed replaced the stored scores")
		}
	})
}

func TestEnricher_Apply(t *testing.T) {
	store := &fakeEnrichStore{data: map[string]artifact.Enrichment{
		"CVE-2024-1111": {EPSSScore: 0.97231, KnownExploited: true},
		"CVE-2024-2222": {EPSSScore: 0.00042},
	}}
	e := NewEnricher(store)

	t.Run("annotates known CVEs", func(t *testing.T) {
		findings := []artifact.Finding{
			{ID: "CVE-2024-1111"},
			{ID: "CVE-2024-2222"},
		}
		if err := e.Apply(findings); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if !findings[0].KnownExploited || findings[0].EPSSScore != 0.97231 {
			t.Fatalf("findings[0] = %+v", findings[0])
		}
		if findings[1].KnownExploited || findings[1].EPSSScore != 0.00042 {
			t.Fatalf("findings[1] = %+v", findings[1])
		}
	})

	// "No row for this CVE" is not "this CVE scores 0". A scan that ran
	// before the first refresh must not permanently stamp findings as
	// not-exploited -- a later refresh plus a re-scan fills them in.
	t.Run("leaves unknown CVEs untouched", func(t *testing.T) {
		findings := []artifact.Finding{{ID: "CVE-1999-0001", EPSSScore: 0.5, KnownExploited: true}}
		if err := e.Apply(findings); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if findings[0].EPSSScore != 0.5 || !findings[0].KnownExploited {
			t.Fatalf("an unknown CVE was overwritten with zeroes: %+v", findings[0])
		}
	})

	// Both feeds are keyed on CVE ids only. Secret findings carry ids
	// like "secret:/app/.env:aws-access-key-id:3"; looking those up
	// queries a 300k-row table for something that can never match.
	t.Run("skips non-CVE findings entirely", func(t *testing.T) {
		spy := &fakeEnrichStore{data: map[string]artifact.Enrichment{}}
		findings := []artifact.Finding{
			{ID: "secret:/app/.env:aws-access-key-id:3"},
			{ID: "clamav-signature-match"},
		}
		if err := NewEnricher(spy).Apply(findings); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if findings[0].KnownExploited || findings[1].KnownExploited {
			t.Fatal("a non-CVE finding was enriched")
		}
	})

	t.Run("a nil enricher is a no-op, not a panic", func(t *testing.T) {
		var nilE *Enricher
		if err := nilE.Apply([]artifact.Finding{{ID: "CVE-2024-1111"}}); err != nil {
			t.Fatalf("Apply on a nil enricher: %v", err)
		}
	})
}
