package api

import (
	"net/http"

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
// purl wins if both are supplied: it's the more specific request, and a
// caller sending both has already made its choice.
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
		`one of "purl" (exact, returns artifacts) or "q" (substring, returns matching packages) is required, e.g. ?q=openssl`)
}
