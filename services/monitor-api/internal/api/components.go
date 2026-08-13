package api

import (
	"net/http"
)

// listByComponent answers "every artifact containing this package" --
// the component-inventory counterpart to findByFindingID's "every
// artifact affected by this CVE" (findings.go), and the query the
// components table exists to make possible. The two share their
// conventions deliberately: an empty list rather than a 404 when
// nothing matches (a package nothing ships is a valid, non-error
// answer), and the artifacts themselves rather than bare IDs, so a
// caller can render the answer without a second round trip per row.
//
// The purl arrives as a query parameter rather than a path segment, the
// one place this deviates from findByFindingID: a purl contains
// slashes, "@", and often a query string of its own
// ("pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64"), none of which
// survive a path segment without the caller percent-encoding it into
// something unreadable.
//
// Matched exactly, including any qualifiers -- see
// Store.FindByComponentPURL on why "any version of this package" is a
// different question than this one answers.
func (h *handler) listByComponent(w http.ResponseWriter, r *http.Request) {
	purl := r.URL.Query().Get("purl")
	if purl == "" {
		writeError(w, http.StatusBadRequest, "purl query parameter is required, e.g. ?purl=pkg:apk/alpine/openssl@3.1.4-r5")
		return
	}

	list, err := h.store.FindByComponentPURL(purl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}
