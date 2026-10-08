package api

import (
	"bytes"
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// csvPageSize is how many artifacts are loaded at a time while building
// the export. Findings live on the artifact, so this bounds how much is
// in memory at once rather than how much the caller receives.
const csvPageSize = 200

// csvMaxRows caps the export.
//
// The cap exists so that TRUNCATION IS IMPOSSIBLE TO MISTAKE FOR
// COMPLETENESS. A CSV has no end-of-file marker: a response that stopped
// early because something failed mid-stream is byte-for-byte a shorter,
// perfectly valid CSV, and a spreadsheet opens it without complaint.
// That is the failure this whole file is shaped around -- hence
// buffering to a bound and failing loudly, rather than streaming rows as
// they are read and hoping the connection holds.
//
// 200k rows is roughly 4x this fleet's current 46,728 open findings and
// about 40MB of text, which is affordable to hold once. A caller who
// trips it is told to narrow with ?active=true rather than handed a
// partial file.
const csvMaxRows = 200_000

// exportFindingsCSV writes every finding in the fleet as one row per
// (artifact, finding), for triage in a spreadsheet.
//
// Every bucket, not just cve: the point of a flat export is that
// somebody can sort and filter it themselves, and malware or a leaked
// secret is exactly what they would sort to the top. The bucket is a
// column so that stays possible.
func (h *handler) exportFindingsCSV(w http.ResponseWriter, r *http.Request) {
	activeOnly := r.URL.Query().Get("active") == "true"
	now := time.Now()

	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	_ = cw.Write([]string{
		"artifact_id", "ref", "source_ref", "artifact_type", "artifact_status",
		"current_stage", "last_scan_at", "provenance",
		"bucket", "finding_id", "severity", "source", "title",
		"finding_status", "first_seen_at", "resolved_at",
		"justification", "accepted_until", "accepted_by", "acceptance_reason",
		"epss_score", "known_exploited",
	})

	rows := 0
	for offset := 0; ; offset += csvPageSize {
		page, total, err := h.store.ListPage(csvPageSize, offset, "", "", "")
		if err != nil {
			// Nothing has been written to the ResponseWriter yet, so a
			// failure here can still be an honest 500 rather than a
			// short file.
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, a := range page {
			for _, b := range findingBuckets(a) {
				for _, f := range b.findings {
					if activeOnly && !f.IsActive() {
						continue
					}
					if rows >= csvMaxRows {
						writeError(w, http.StatusRequestEntityTooLarge,
							"this fleet has more than "+strconv.Itoa(csvMaxRows)+
								" findings to export; narrow it with ?active=true rather than accepting a partial file")
						return
					}
					rows++
					_ = cw.Write(csvRow(a, b.name, f))
				}
			}
		}
		if len(page) == 0 || offset+len(page) >= total {
			break
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not encode the export: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition",
		`attachment; filename="scm-findings-`+now.UTC().Format("20060102T150405Z")+`.csv"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

type namedBucket struct {
	name     string
	findings []artifact.Finding
}

func findingBuckets(a *artifact.Artifact) []namedBucket {
	return []namedBucket{
		{"cve", a.CVEFindings},
		{"malware", a.MalwareFindings},
		{"misconfiguration", a.MisconfigFindings},
		{"secret", a.SecretFindings},
		{"other", a.OtherFindings},
	}
}

func csvRow(a *artifact.Artifact, bucket string, f artifact.Finding) []string {
	// Every free-text column goes through csvSafe. The timestamps and
	// numbers are formatted by this process and cannot lead with a
	// formula character, so they are left alone -- but anything a
	// caller, a scanner or an uploaded document can set is neutralised.
	return []string{
		csvSafe(a.ID), csvSafe(a.Ref), csvSafe(a.SourceRef), csvSafe(string(a.Type)), csvSafe(string(a.Status)),
		csvSafe(a.CurrentStage), utcOrEmpty(a.LastScanAt), csvSafe(a.Provenance),
		bucket, csvSafe(f.ID), csvSafe(f.Severity), csvSafe(f.Source), csvSafe(f.Title),
		csvSafe(f.Status), f.FirstSeenAt.UTC().Format(time.RFC3339), utcOrEmpty(f.ResolvedAt),
		csvSafe(f.Justification), utcOrEmpty(f.AcceptedUntil), csvSafe(f.AcceptedBy), csvSafe(f.AcceptanceReason),
		strconv.FormatFloat(f.EPSSScore, 'f', -1, 64), strconv.FormatBool(f.KnownExploited),
	}
}

// csvSafe neutralises spreadsheet formula injection.
//
// Excel, LibreOffice and Google Sheets evaluate a cell beginning with
// =, +, -, @, tab or CR as a FORMULA, and a formula can exfiltrate the
// rest of the sheet or trigger a command prompt. This export exists to
// be opened in exactly those programs, so the risk is not theoretical
// for it.
//
// The inputs are caller-controlled, within this system's own stated
// threat model rather than in spite of it:
//
//   - Artifact.Ref arrives on POST /artifacts
//   - Finding.Title, Severity and Source arrive on POST
//     /artifacts/{id}/findings, whose whole point is that a CI scanner
//     reports them -- and scanner output is treated as untrusted
//     everywhere else in this codebase, which is why scans run in
//     isolated Jobs at all
//   - Justification arrives inside an uploaded VEX document
//
// A leading apostrophe is the accepted mitigation: the spreadsheet
// shows the original text and does not evaluate it. It is mildly lossy
// for a value that genuinely starts with "-", which is the price of the
// cell not being a program.
//
// Quoting is NOT a fix -- csv.Writer already quotes anything containing
// a comma or newline, and the spreadsheet evaluates the quoted contents
// regardless.
func csvSafe(s string) string {
	// The check is on the first NON-WHITESPACE rune, not on s[0].
	//
	// Testing s[0] directly is bypassed by one leading space: " =1+1"
	// does not start with a formula character, so it would go through
	// unprefixed, and an importer that trims leading whitespace then
	// sees =1+1 and evaluates it. The same holds for a leading newline
	// or a non-breaking space.
	//
	// Which whitespace a given spreadsheet trims is not something worth
	// knowing precisely -- Excel, LibreOffice, Sheets and whatever
	// somebody pipes this through all differ. Trimming everything
	// unicode calls a space before deciding makes the answer not depend
	// on that.
	trimmed := strings.TrimLeftFunc(s, unicode.IsSpace)
	if trimmed == "" {
		// Empty, or whitespace only. Nothing to evaluate.
		return s
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		// The apostrophe goes on the ORIGINAL, not the trimmed value:
		// the export should still show what the field actually said,
		// whitespace included.
		return "'" + s
	}
	return s
}

func utcOrEmpty(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
