package api

import (
	"net/http"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/policy"
)

// getPolicy answers "would this artifact pass the gate", for a
// pipeline that wants one call instead of fetching every finding and
// re-deriving the rules for itself (which is how two pipelines reading
// the same artifact end up disagreeing).
//
// ALWAYS 200 WHEN THE ARTIFACT EXISTS, pass or fail. A failing policy
// is a successful answer to the question asked, not an HTTP error, and
// the distinction is load-bearing for the intended caller: a CI step
// doing `curl --fail` on a non-2xx cannot tell "this artifact violates
// the policy" from "the API is down, the id is wrong, or my key is
// invalid" -- and the first of those must block a release while the
// others must be investigated, not silently treated as a failed gate.
// The caller reads .pass out of the body. See README's "Gating a
// pipeline on policy" for the curl form this is designed around.
//
// A missing artifact is still a 404: that is a question about an id
// that does not exist, not a policy outcome.
func (h *handler) getPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := h.store.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, policy.Evaluate(h.policy, *a, time.Now().UTC()))
}
