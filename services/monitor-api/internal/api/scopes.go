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
// Five scopes, deliberately coarse. A permission model nobody can hold
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
	// ScopeScan triggers scans, and covers submitting scan RESULTS
	// (findings, VEX) -- see routeScopes for why those are here rather
	// than under admin.
	ScopeScan = "scan"
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
var AllScopes = []string{ScopeAdmin, ScopeDocumentsWrite, ScopeRead, ScopeRegister, ScopeScan}

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
// THE ZERO VALUE DISABLES ENFORCEMENT ENTIRELY, and that is the state
// every existing deployment upgrades into: no scopes configured means
// every key does what it did before this existed. Enforcement turning
// itself on during an upgrade would lock out the dashboard, the sweep
// CronJob and every CI consumer at once.
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
// A client with no entry while enforcement is ON is UNRESTRICTED, not
// denied. That is the compatibility path the report asks for -- the
// legacy API_KEY authenticates as "default" and is what the dashboard,
// the sweep CronJob and every existing consumer present -- but it is
// also a hole, so NewRouter warns about each one by name at startup
// rather than letting it pass quietly.
func (k KeyScopes) For(client string) Scopes {
	if !k.Enforced() {
		return Scopes{unrestricted: true}
	}
	if s, ok := k.byClient[client]; ok {
		return s
	}
	return Scopes{unrestricted: true}
}

// Unscoped returns the configured client names that have no entry --
// i.e. the ones running unrestricted while enforcement is on.
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
