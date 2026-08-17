package scanner

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// Enrichment feeds. Both are configurable for the same reason
// TRIVY_DB_REPOSITORY is: an air-gapped cluster mirrors them somewhere
// reachable and points these at the mirror, rather than having the
// feature simply not work.
const (
	KEVFeedURLEnv  = "KEV_FEED_URL"
	EPSSFeedURLEnv = "EPSS_FEED_URL"

	// CISA's Known Exploited Vulnerabilities catalogue -- CVEs with
	// exploitation OBSERVED in the wild, not predicted.
	DefaultKEVFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	// FIRST's EPSS scores, published daily as a gzipped CSV.
	DefaultEPSSFeedURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
)

// feedTimeout bounds one download. Generous because the EPSS CSV is a
// few MB gzipped and the refresh is a daily CronJob, not a request
// path -- but bounded, because a hung download that never returns is
// a CronJob that never completes and never alerts.
const feedTimeout = 5 * time.Minute

// maxFeedBytes caps what will be read from either feed after
// decompression. The parsers below build a map per row, so an
// unbounded response -- a mirror misconfigured to serve something
// else, or a redirect to a large file -- is an OOM in a pod with a
// 1Gi limit rather than a download error. EPSS is ~15MB uncompressed
// today with ~280k rows.
const maxFeedBytes = 256 << 20 // 256MB

// EnrichmentStore is the part of artifact.Store the enricher needs.
type EnrichmentStore interface {
	ReplaceEnrichment(kev []string, epss map[string]float64, at time.Time) error
	LookupEnrichment(cveIDs []string) (map[string]artifact.Enrichment, error)
}

// Enricher annotates CVE findings with CISA KEV and FIRST EPSS data.
//
// Severity alone is a poor triage signal: it describes how bad
// exploitation WOULD be, not whether anyone is doing it. A
// medium-severity CVE with a working exploit in the wild is more
// urgent than a critical that has never been exploited, and until
// something says which is which every list is sorted by the wrong
// thing.
//
// The feeds are refreshed by a separate CronJob (`monitor-api
// enrich-refresh`) into the database, not fetched on a request path:
// they are a few MB, shared by every replica, and change daily.
type Enricher struct {
	store EnrichmentStore
	// client is exposed for tests; nil uses a default with feedTimeout.
	client *http.Client
}

func NewEnricher(store EnrichmentStore) *Enricher {
	return &Enricher{store: store}
}

func (e *Enricher) httpClient() *http.Client {
	if e.client != nil {
		return e.client
	}
	return &http.Client{Timeout: feedTimeout}
}

// Apply annotates findings in place with whatever the feeds know.
//
// LEAVES UNKNOWN CVES ALONE rather than writing zeroes. "No row for
// this CVE" and "this CVE scores 0" are different facts, and a scan
// that ran before the first successful refresh must not permanently
// stamp every finding as not-exploited -- a later refresh plus a
// re-scan fills them in.
//
// Non-CVE findings are skipped entirely: secret findings carry ids
// like "secret:/app/.env:aws-access-key-id:3" and malware findings
// carry signature names, and neither feed is keyed on anything but
// CVE ids.
//
// An error from the store is returned but is NOT fatal to a scan --
// see the caller in internal/api/scan.go. Enrichment failing must not
// discard a scan's actual findings.
func (e *Enricher) Apply(findings []artifact.Finding) error {
	if e == nil || e.store == nil || len(findings) == 0 {
		return nil
	}
	ids := make([]string, 0, len(findings))
	seen := make(map[string]bool, len(findings))
	for _, f := range findings {
		if !artifact.IsCVEID(f.ID) || seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		ids = append(ids, f.ID)
	}
	if len(ids) == 0 {
		return nil
	}

	found, err := e.store.LookupEnrichment(ids)
	if err != nil {
		return err
	}
	for i := range findings {
		if !artifact.IsCVEID(findings[i].ID) {
			continue
		}
		if enr, ok := found[strings.ToUpper(findings[i].ID)]; ok {
			findings[i].EPSSScore = enr.EPSSScore
			findings[i].KnownExploited = enr.KnownExploited
		}
	}
	return nil
}

// Refresh downloads both feeds and replaces the stored copies.
//
// A failure on ONE feed does not discard the other: each is passed to
// the store only if its own download and parse succeeded, and the
// store leaves a nil feed untouched. But the error is still returned,
// so `monitor-api enrich-refresh` exits non-zero and the CronJob's
// failure is a real signal -- a refresh that half-worked and reported
// success is how enrichment silently rots.
func (e *Enricher) Refresh(ctx context.Context, now time.Time) error {
	var errs []error

	kev, err := e.fetchKEV(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("kev: %w", err))
		kev = nil
	}
	epss, err := e.fetchEPSS(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("epss: %w", err))
		epss = nil
	}

	if kev != nil || epss != nil {
		if err := e.store.ReplaceEnrichment(kev, epss, now); err != nil {
			errs = append(errs, fmt.Errorf("store: %w", err))
		}
	}
	return errors.Join(errs...)
}

// kevCatalog is the subset of CISA's JSON this reads.
type kevCatalog struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

func (e *Enricher) fetchKEV(ctx context.Context) ([]string, error) {
	body, err := e.get(ctx, getenvOr(KEVFeedURLEnv, DefaultKEVFeedURL))
	if err != nil {
		return nil, err
	}
	defer body.Close()

	var cat kevCatalog
	if err := json.NewDecoder(io.LimitReader(body, maxFeedBytes)).Decode(&cat); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}
	if len(cat.Vulnerabilities) == 0 {
		// An empty catalogue is never correct -- CISA's has well over a
		// thousand entries -- so this is a mirror serving the wrong
		// thing, or a feed that changed shape. Storing it would clear
		// every known_exploited flag we have.
		return nil, errors.New("catalog contained no vulnerabilities, refusing to replace the stored one")
	}
	out := make([]string, 0, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		if id := strings.TrimSpace(v.CVEID); id != "" {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

// fetchEPSS parses the daily gzipped CSV.
//
// The file starts with a comment line ("#model_version:...") before the
// real header, which is why this cannot just be handed to csv.Reader
// with FieldsPerRecord defaulted.
func (e *Enricher) fetchEPSS(ctx context.Context) (map[string]float64, error) {
	body, err := e.get(ctx, getenvOr(EPSSFeedURLEnv, DefaultEPSSFeedURL))
	if err != nil {
		return nil, err
	}
	defer body.Close()

	gz, err := gzip.NewReader(io.LimitReader(body, maxFeedBytes))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()

	r := csv.NewReader(io.LimitReader(gz, maxFeedBytes))
	r.Comment = '#'
	r.FieldsPerRecord = -1 // the header and data rows are read the same way

	out := make(map[string]float64)
	var header []string
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse csv: %w", err)
		}
		if header == nil {
			header = rec
			continue
		}
		cve, score, ok := epssRow(header, rec)
		if !ok {
			continue
		}
		out[cve] = score
	}
	if len(out) == 0 {
		// Same reasoning as the empty KEV catalogue: replacing every
		// score with nothing is worse than keeping yesterday's.
		return nil, errors.New("feed contained no scores, refusing to replace the stored ones")
	}
	return out, nil
}

// epssRow reads one CSV row by COLUMN NAME rather than position.
// The feed's column order is not something this controls, and a
// silent shift would turn percentiles into scores.
func epssRow(header, rec []string) (string, float64, bool) {
	var cve string
	var score float64
	var haveCVE, haveScore bool
	for i, name := range header {
		if i >= len(rec) {
			break
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "cve":
			cve = strings.ToUpper(strings.TrimSpace(rec[i]))
			haveCVE = artifact.IsCVEID(cve)
		case "epss":
			v, err := strconv.ParseFloat(strings.TrimSpace(rec[i]), 64)
			if err == nil {
				score, haveScore = v, true
			}
		}
	}
	return cve, score, haveCVE && haveScore
}

func (e *Enricher) get(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}

func getenvOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
