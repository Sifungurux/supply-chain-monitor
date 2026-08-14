package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// maxComponentMatches bounds one package-search response. A search for
// a common substring ("go", "lib") legitimately matches thousands of
// distinct packages, and neither a picker list nor the person reading
// it wants all of them -- the total is always reported alongside, so a
// truncated answer says so rather than looking complete. 200 is far
// more than anyone scrolls and still a small JSON body.
const maxComponentMatches = 200

// componentSearchResponse is the ?q= (discovery) answer: distinct
// packages, not artifacts. Total is how many matched before the cap, so
// the caller can render "showing 200 of 4,312" instead of quietly
// dropping the rest.
type componentSearchResponse struct {
	Total    int                       `json:"total"`
	Packages []artifact.ComponentMatch `json:"packages"`
}

// listByComponent answers two different questions from one endpoint,
// because they're two steps of the same task:
//
//   - ?purl=pkg:apk/alpine/openssl@3.1.4-r5 -- EXACT: every artifact
//     containing precisely that package. The component-inventory
//     counterpart to findByFindingID's "every artifact affected by this
//     CVE" (findings.go), and it shares that endpoint's conventions: the
//     artifacts themselves rather than bare IDs, and an empty list
//     rather than a 404 when nothing matches (a package nothing ships is
//     a valid, non-error answer).
//   - ?q=openssl -- DISCOVERY: the distinct packages whose name or purl
//     contains that substring, each with the number of artifacts
//     containing it.
//
// Both exist because exact matching is the right contract for an answer
// and a useless one for a search box. Nobody knows they want
// "pkg:apk/alpine/openssl@3.1.4-r6?arch=x86_64&distro=3.19.1"; they know
// "openssl". So ?q= finds the handful of purls that actually exist, with
// enough weight (name, version, artifact count) to tell which one is
// meant, and the chosen purl goes back through ?purl= for the exact
// answer. The exactness is preserved where it matters -- in what an
// answer means -- rather than being softened into a fuzzy match that
// might quietly include a package you didn't ask about.
//
//   - ?license=AGPL-3.0-only -- EXACT, by license: every artifact
//     containing a component carrying that identifier. Matched per
//     identifier and case-insensitively, never as a substring of the
//     comma-joined column: "GPL-3.0-only" must not match
//     "LGPL-3.0-only", and must not match inside the expression
//     "MIT OR AGPL-3.0-only", where the OR is the permissive escape.
//     Same rule scanner.LicenseDenylist applies, so what this finds is
//     what the denylist would flag.
//
// purl wins if more than one is supplied, then license, then q: each is
// more specific than the next, and a caller sending several has already
// made its choice.
//
// The purl/query arrives as a query parameter rather than a path
// segment: a purl contains slashes, "@", and often a query string of its
// own, none of which survive a path segment without the caller
// percent-encoding it into something unreadable.
func (h *handler) listByComponent(w http.ResponseWriter, r *http.Request) {
	purl := r.URL.Query().Get("purl")
	if purl != "" {
		list, err := h.store.FindByComponentPURL(purl)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, list)
		return
	}

	if license := r.URL.Query().Get("license"); license != "" {
		list, err := h.store.FindByLicense(license)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, list)
		return
	}

	if q := r.URL.Query().Get("q"); q != "" {
		matches, total, err := h.store.SearchComponents(q, maxComponentMatches)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, componentSearchResponse{Total: total, Packages: matches})
		return
	}

	writeError(w, http.StatusBadRequest,
		`one of "purl" (exact, returns artifacts), "license" (exact SPDX identifier, returns artifacts) or "q" (substring, returns matching packages) is required, e.g. ?q=openssl`)
}

// componentDiffResponse is the /components/diff answer. From/To are the
// snapshots actually compared, echoed back because the caller usually
// didn't name them -- the default is "the two most recent" and a
// dashboard has to be able to say which two that was.
//
// Both are null, with three empty lists, when there is nothing to
// compare yet. See listComponentDiff.
type componentDiffResponse struct {
	From *time.Time `json:"from"`
	To   *time.Time `json:"to"`
	// The three keys of artifact.ComponentDiff, spelled out rather than
	// embedded so this struct reads as the documented response shape.
	Added          []artifact.Component              `json:"added"`
	Removed        []artifact.Component              `json:"removed"`
	VersionChanged []artifact.ComponentVersionChange `json:"version_changed"`
}

// listComponentDiff answers "what changed in this artifact's SBOM"
// between two component snapshots -- by default the two most recent,
// or the pair named by ?from= and ?to= (RFC3339 timestamps from
// ComponentSnapshots).
//
// This is the payoff of components_history existing at all. The
// components table holds only the CURRENT inventory (SaveComponents
// replaces it wholesale, matching artifact_documents' latest-only
// contract), so before the snapshot log there was no previous state to
// compare against -- a rescan simply overwrote what an upgrade would
// have been measured from.
//
// Fewer than two snapshots is a 200 with null from/to and three empty
// lists, NOT a 404: "this artifact has only ever been indexed once, so
// nothing has changed yet" is a real and extremely common answer, and
// the same convention findByFindingID and listByComponent already use
// for their own empty results. A 404 here would make a brand-new
// artifact look broken on the dashboard.
func (h *handler) listComponentDiff(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := h.store.Get(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	from, to, err := parseDiffRange(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if from == nil || to == nil {
		// No explicit pair: use the two most recent snapshots.
		snapshots, err := h.store.ComponentSnapshots(id, 2)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(snapshots) < 2 {
			writeJSON(w, http.StatusOK, componentDiffResponse{
				Added:          []artifact.Component{},
				Removed:        []artifact.Component{},
				VersionChanged: []artifact.ComponentVersionChange{},
			})
			return
		}
		// ComponentSnapshots is newest-first, and a diff reads
		// oldest -> newest.
		to, from = &snapshots[0], &snapshots[1]
	}

	older, err := h.store.ComponentsAt(id, *from)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	newer, err := h.store.ComponentsAt(id, *to)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	diff := artifact.DiffComponents(older, newer)
	writeJSON(w, http.StatusOK, componentDiffResponse{
		From:           from,
		To:             to,
		Added:          diff.Added,
		Removed:        diff.Removed,
		VersionChanged: diff.VersionChanged,
	})
}

// parseDiffRange reads the optional ?from=/?to= pair. Both or neither:
// one alone has no sensible reading -- "changes since X" would silently
// mean "up to whenever the newest snapshot happens to be", which is a
// different question than the caller asked and one whose answer changes
// under them between two identical requests.
func parseDiffRange(r *http.Request) (*time.Time, *time.Time, error) {
	rawFrom := r.URL.Query().Get("from")
	rawTo := r.URL.Query().Get("to")
	if rawFrom == "" && rawTo == "" {
		return nil, nil, nil
	}
	if rawFrom == "" || rawTo == "" {
		return nil, nil, errors.New(`"from" and "to" must be given together (or neither, to compare the two most recent snapshots)`)
	}

	from, err := time.Parse(time.RFC3339Nano, rawFrom)
	if err != nil {
		return nil, nil, fmt.Errorf(`"from" must be an RFC3339 timestamp from this artifact's snapshot list: %v`, err)
	}
	to, err := time.Parse(time.RFC3339Nano, rawTo)
	if err != nil {
		return nil, nil, fmt.Errorf(`"to" must be an RFC3339 timestamp from this artifact's snapshot list: %v`, err)
	}
	fromUTC, toUTC := from.UTC(), to.UTC()
	return &fromUTC, &toUTC, nil
}
