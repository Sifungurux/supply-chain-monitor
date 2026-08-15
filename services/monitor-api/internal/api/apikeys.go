package api

import (
	"context"
	"crypto/subtle"
	"sort"
	"strings"
)

// namedKey pairs a client name with the key it presents.
type namedKey struct {
	name string
	key  string
}

// APIKeys is the set of keys this deployment accepts, each attributed to
// a named client (API_KEYS / monitorApi.apiKeys).
//
// Named rather than anonymous because a single shared key cannot answer
// three questions that matter the moment more than one thing calls this
// API: who made this request, can I revoke one consumer without
// re-keying every other, and which consumer is responsible for a spike
// of 401s. The name travels into the request context and the access log
// (see ClientFromContext) so the answer is in the logs rather than
// inferred from timing.
//
// The zero value accepts nothing, which is what a deployment with no
// keys configured should do -- see Enabled and its use in NewRouter.
type APIKeys struct {
	keys []namedKey
}

// ParseAPIKeys reads a comma-separated "name:key" list.
//
// An entry with an EMPTY KEY IS SKIPPED, and that is a security
// property, not tidiness: an empty key would otherwise be compared
// against the empty string a caller presents with a bare "Bearer ",
// match, and authenticate every anonymous request as that client. The
// chart can legitimately render a blank entry for an account that was
// removed, so this is a real input, not a hypothetical one.
//
// An entry with no ":" is also skipped rather than treated as an
// unnamed key -- a key that reached this function through a
// misconfigured template should fail closed and be absent, not silently
// work while logging an empty client name.
func ParseAPIKeys(raw string) APIKeys {
	var keys []namedKey
	seen := make(map[string]bool)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// SplitN with 2, so a key containing ":" survives intact. Keys
		// this project generates are hex and never contain one, but a
		// hand-supplied key is not this function's business to mangle.
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		key := strings.TrimSpace(parts[1])
		if name == "" || key == "" {
			continue
		}
		// Later duplicates lose. Two entries sharing a name would make
		// attribution ambiguous, and two sharing a key would make
		// revocation ambiguous -- neither is worth guessing about.
		if seen[name] || seen[key] {
			continue
		}
		seen[name] = true
		seen[key] = true
		keys = append(keys, namedKey{name: name, key: key})
	}
	// Stable order so Lookup's work is identical run to run.
	sort.Slice(keys, func(i, j int) bool { return keys[i].name < keys[j].name })
	return APIKeys{keys: keys}
}

// WithKey returns a copy that also accepts key under name. Used for the
// legacy single API_KEY, which stays valid alongside any named keys so
// that adding this feature cannot lock out an existing deployment
// mid-upgrade.
func (k APIKeys) WithKey(name, key string) APIKeys {
	if name == "" || key == "" {
		return k
	}
	for _, existing := range k.keys {
		if existing.name == name || existing.key == key {
			return k
		}
	}
	out := APIKeys{keys: append(append([]namedKey(nil), k.keys...), namedKey{name: name, key: key})}
	sort.Slice(out.keys, func(i, j int) bool { return out.keys[i].name < out.keys[j].name })
	return out
}

// Enabled reports whether any key is configured.
func (k APIKeys) Enabled() bool { return len(k.keys) > 0 }

// Names lists the configured client names, for a startup log line. It
// deliberately returns only names -- logging a key, even at debug, puts
// a live credential in a log aggregator forever.
func (k APIKeys) Names() []string {
	out := make([]string, 0, len(k.keys))
	for _, nk := range k.keys {
		out = append(out, nk.name)
	}
	return out
}

// Lookup returns the client name for a presented key.
//
// CONSTANT TIME WITH RESPECT TO WHICH KEY MATCHED, and it must stay
// that way. The obvious implementation -- a map keyed by the credential,
// or a loop that returns on first match -- leaks through timing which
// key was presented, and with named keys that is more interesting to an
// attacker than with one: it turns "is this key valid" into an oracle
// that can be walked. So every configured key is compared on every call
// and the loop never exits early; the winning index is selected without
// branching.
//
// subtle.ConstantTimeCompare returns 0 immediately when lengths differ,
// so length is still observable. That is inherent to comparing strings
// of unequal length and is why the keys this project generates are all
// the same width.
func (k APIKeys) Lookup(presented string) (string, bool) {
	found := 0
	idx := 0
	for i, nk := range k.keys {
		eq := subtle.ConstantTimeCompare([]byte(presented), []byte(nk.key))
		found |= eq
		idx = subtle.ConstantTimeSelect(eq, i, idx)
	}
	if found != 1 {
		return "", false
	}
	return k.keys[idx].name, true
}

// clientContextKey is unexported so nothing outside this package can
// forge a client name into a request context.
type clientContextKey struct{}

// WithClient returns r's context carrying the authenticated client name.
func WithClient(ctx context.Context, client string) context.Context {
	return context.WithValue(ctx, clientContextKey{}, client)
}

// ClientFromContext returns the authenticated client name, or "" on an
// unauthenticated path (/healthz and friends, which withAuth exempts).
func ClientFromContext(ctx context.Context) string {
	client, _ := ctx.Value(clientContextKey{}).(string)
	return client
}
