package api

import (
	"context"
	"net/http"
	"sort"
	"strings"
)

// Scope names what a key is allowed to do. Report item H1.
//
// A single all-powerful credential is the root of several findings in
// that report: the dashboard, the sweep CronJob and (before per-Job
// tokens) every scan worker all held the same key, so compromising the
// least of them was compromising all of them.
//
// Seven scopes, deliberately coarse. A permission model nobody can hold
// in their head gets set to "everything" by the first person in a
// hurry, and then it is worse than none because it looks like there is
// one.
const (
	// ScopeRead is every GET. Reading is separated from writing because
	// most consumers -- dashboards, reporting, a CI step that only asks
	// "did this pass" -- never need anything else.
	ScopeRead = "read"
	// ScopeRegister creates artifacts (POST /artifacts, /artifacts/bulk).
	ScopeRegister = "register"
	// ScopeScan ASKS FOR A SCAN and nothing else (POST
	// /artifacts/{id}/scan).
	//
	// It used to also cover submitting scan RESULTS. That made "may
	// request a rescan" and "may declare a finding suppressed" the same
	// permission, so the dashboard key -- held by anyone who can reach
	// the dashboard -- could silence findings across the whole fleet.
	// Triggering work is a request; asserting its outcome is an
	// assertion about risk. See ScopeResultsWrite.
	ScopeScan = "scan"
	// ScopeResultsWrite submits scan RESULTS: findings, per-artifact VEX
	// and fleet-wide VEX.
	//
	// Separate from ScopeAdmin rather than folded into it because an
	// external scanner genuinely needs to post what it found, and
	// requiring admin for that would hand every CI scanner full
	// authority -- worse than no scopes at all. Separate from ScopeScan
	// because suppressing a finding is not the same act as asking for
	// one to be looked for.
	ScopeResultsWrite = "results:write"
	// ScopeStageWrite moves an artifact through pipeline stages
	// (POST /artifacts/{id}/stage).
	//
	// Carved out of ScopeAdmin so a CI pipeline can report "this
	// reached staging" without also being able to delete artifacts,
	// reassign maintainers or accept risk. That is the whole set a
	// build pipeline needs beyond register/scan/read.
	ScopeStageWrite = "stage:write"
	// ScopeDocumentsWrite uploads generated SBOM/SARIF documents. This
	// is what a scan worker would need if it used a key at all; it uses
	// a per-Job token instead (see scantoken.go), which is narrower
	// still.
	ScopeDocumentsWrite = "documents:write"
	// ScopeAdmin implies every other scope, and is required on its own
	// for anything destructive or identity-changing.
	ScopeAdmin = "admin"
)

// AllScopes is every scope, in a stable order for logging.
var AllScopes = []string{ScopeAdmin, ScopeDocumentsWrite, ScopeRead, ScopeRegister, ScopeResultsWrite, ScopeScan, ScopeStageWrite}

func validScope(s string) bool {
	for _, known := range AllScopes {
		if s == known {
			return true
		}
	}
	return false
}

// Scopes is one client's permissions.
type Scopes struct {
	set map[string]bool
	// unrestricted marks a client that was never given scopes while
	// enforcement is on -- it behaves as admin, and says so at startup.
	// Distinct from actually holding ScopeAdmin so the warning can name
	// the difference.
	unrestricted bool
}

// Allows reports whether this client may perform an action.
//
// ScopeAdmin implies everything EXPLICITLY, not as an emergent property
// of the route table: an admin key that failed some route because
// nobody thought to list it would be a permission model that cannot be
// reasoned about.
func (s Scopes) Allows(scope string) bool {
	if s.unrestricted || s.set[ScopeAdmin] {
		return true
	}
	return s.set[scope]
}

// List returns the granted scopes, sorted, for logging.
func (s Scopes) List() []string {
	if s.unrestricted {
		return []string{"(unrestricted)"}
	}
	out := make([]string, 0, len(s.set))
	for k := range s.set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// KeyScopes maps client names to their scopes (API_KEY_SCOPES /
// monitorApi.apiKeyScopes).
//
// THE ZERO VALUE DISABLES ENFORCEMENT ENTIRELY: no scopes configured
// means every key does what it did before this existed.
//
// That used to be where every upgrading deployment landed. It is not
// any more -- the chart ships scopes for every client it generates, and
// main.go refuses to start into this state when several clients
// authenticate, since all of them would be unrestricted and differ only
// in the audit log. The zero value survives for the single-key case,
// where scoping one consumer against itself is ceremony.
type KeyScopes struct {
	byClient map[string]Scopes
}

// Enforced reports whether any scopes are configured at all.
func (k KeyScopes) Enforced() bool { return len(k.byClient) > 0 }

// ParseKeyScopes reads "name=scope|scope;name2=scope".
//
// SEMICOLON-separated between clients for the same reason API_KEYS is
// (Flux resolves valuesFrom through Helm's strvals, where a comma is a
// delimiter and tears the value apart -- see ParseAPIKeys). PIPE between
// scopes rather than a comma for exactly the same reason.
//
// An unparseable or unknown scope is DROPPED rather than ignored
// silently at request time: a typo'd "reader" that granted nothing
// would look like a working configuration until somebody hit a 403 they
// could not explain. Invalid names are returned so the caller can
// refuse to start.
func ParseKeyScopes(raw string) (KeyScopes, []string) {
	out := KeyScopes{byClient: map[string]Scopes{}}
	var invalid []string

	for _, entry := range strings.FieldsFunc(raw, func(r rune) bool { return r == ';' }) {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, list, found := strings.Cut(entry, "=")
		name = strings.TrimSpace(name)
		if !found || name == "" {
			invalid = append(invalid, entry)
			continue
		}
		set := map[string]bool{}
		for _, s := range strings.FieldsFunc(list, func(r rune) bool { return r == '|' || r == ',' }) {
			s = strings.ToLower(strings.TrimSpace(s))
			if s == "" {
				continue
			}
			if !validScope(s) {
				invalid = append(invalid, name+"="+s)
				continue
			}
			set[s] = true
		}
		// A client listed with NO valid scopes gets none -- an explicit
		// entry means somebody thought about this client, so the safe
		// reading of "name=" is "nothing", not "everything".
		out.byClient[name] = Scopes{set: set}
	}
	if len(out.byClient) == 0 {
		return KeyScopes{}, invalid
	}
	return out, invalid
}

// For returns a client's scopes.
//
// A client with no entry while enforcement is ON gets NOTHING. This is
// DEFAULT-CLOSED, and it is the opposite of what this used to do.
//
// The old behaviour -- unlisted means unrestricted -- was a deliberate
// compatibility path: it meant switching scopes on could not lock out a
// consumer whose entry had not caught up. The cost is that the failure
// mode ran the wrong way. A consumer added and forgotten did not break
// loudly; it quietly held full authority, which is precisely the state
// scopes exist to prevent, and nothing in a working deployment ever
// revealed it.
//
// Default-closed inverts that: a missing entry now costs the consumer
// its access instead of costing everyone else their isolation. The
// migration is carried by configuration rather than by code -- the
// chart ships scopes for every client it generates, and main.go refuses
// to start a multi-client deployment with no scopes at all rather than
// letting one drift into this path unnoticed.
func (k KeyScopes) For(client string) Scopes {
	if !k.Enforced() {
		return Scopes{unrestricted: true}
	}
	// Zero value: no scopes, and NOT unrestricted. Allows() then denies
	// everything, and requireScope answers 403.
	return k.byClient[client]
}

// Unscoped returns the configured client names that have no entry --
// i.e. the ones that can now do NOTHING while enforcement is on.
//
// Still worth naming at startup, but the warning it feeds says the
// opposite of what it used to: these keys authenticate and then fail
// every route with 403, which is a configuration mistake that looks
// like a broken consumer.
func (k KeyScopes) Unscoped(clients []string) []string {
	if !k.Enforced() {
		return nil
	}
	var out []string
	for _, c := range clients {
		if _, ok := k.byClient[c]; !ok {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// scopesContextKey is unexported so nothing outside this package can
// forge scopes into a request context. Separate from clientContextKey
// rather than widening it: withAudit reads the client name and must
// keep getting a string.
type scopesContextKey struct{}

// WithScopes returns ctx carrying the authenticated client's scopes.
func WithScopes(ctx context.Context, s Scopes) context.Context {
	return context.WithValue(ctx, scopesContextKey{}, s)
}

// ScopesFromContext returns the authenticated client's scopes.
//
// Absent scopes read as UNRESTRICTED, which matters for the scan-worker
// token path: it authenticates without a key at all, and is already
// narrowed to one artifact and one document kind by the token itself.
func ScopesFromContext(ctx context.Context) Scopes {
	s, ok := ctx.Value(scopesContextKey{}).(Scopes)
	if !ok {
		return Scopes{unrestricted: true}
	}
	return s
}

// requireScope gates one route.
//
// Applied at REGISTRATION rather than inside each handler, so the whole
// permission model is one readable block in NewRouter -- "what can this
// key do" is answered by reading the route list, not by grepping
// nineteen handlers. A route added without a scope is a compile-time
// change to that block, which is the moment to think about it.
func requireScope(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ScopesFromContext(r.Context()).Allows(scope) {
			// 403, not 401: the credential is valid and identified, it
			// simply may not do this. A 401 would tell a caller to go
			// and fix its key, which is the wrong instruction.
			writeError(w, http.StatusForbidden,
				"this API key is not permitted to "+scope+" -- see monitorApi.apiKeyScopes")
			return
		}
		next(w, r)
	}
}
