package api

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// rateLimiter is a small per-key token bucket limiter. Each distinct key
// (in practice, the caller's API key -- see withRateLimit) gets its own
// bucket that refills at ratePerSecond tokens/sec, holding at most burst
// tokens at once.
//
// This is implemented by hand rather than pulling in
// golang.org/x/time/rate: the algorithm is small and well understood,
// and this project deliberately keeps monitor-api on the stdlib (see
// docs/architecture.md) rather than adding a dependency for the one
// thing here that needs it.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    float64 // tokens added per second
	burst   float64 // max tokens a bucket can hold (and its starting level)
	// maxKeys bounds the bucket map. Zero means unbounded, which is
	// correct when the key space is bounded by something else: the
	// original caller here keys on the Authorization header of an
	// ALREADY-AUTHENTICATED request (withRateLimit runs inside
	// withAuth), so only real API keys can create a bucket.
	//
	// A limiter keyed on anything a stranger chooses -- a client IP, an
	// arbitrary header -- must set this, or the map is a memory leak an
	// attacker controls the size of.
	maxKeys int
}

type tokenBucket struct {
	tokens   float64
	lastSeen time.Time
}

// newRateLimiter builds a limiter allowing ratePerSecond sustained
// requests per key, with bursts up to burst. Callers should treat
// ratePerSecond <= 0 as "disabled" (see withRateLimit) rather than
// constructing a limiter with a nonsensical zero rate.
func newRateLimiter(ratePerSecond float64, burst float64) *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*tokenBucket),
		rate:    ratePerSecond,
		burst:   burst,
	}
}

// newBoundedRateLimiter is newRateLimiter with a cap on how many keys it
// will track at once -- required whenever the key space is chosen by
// the caller rather than by this deployment.
func newBoundedRateLimiter(ratePerSecond float64, burst float64, maxKeys int) *rateLimiter {
	l := newRateLimiter(ratePerSecond, burst)
	l.maxKeys = maxKeys
	return l
}

// allow reports whether a request identified by key may proceed right
// now, consuming one token from that key's bucket if so. Buckets start
// full (at burst) so a key's first requests after startup aren't
// throttled waiting for tokens to accumulate.
func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		// Only a NEW key can grow the map, so that is the only place
		// eviction needs to run.
		l.evictLocked(now)
		b = &tokenBucket{tokens: l.burst, lastSeen: now}
		l.buckets[key] = b
	} else {
		elapsed := now.Sub(b.lastSeen).Seconds()
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.lastSeen = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictLocked keeps the bucket map under maxKeys. Caller holds l.mu.
//
// Two passes, because the first one is free and usually enough.
//
// A bucket that has refilled to burst is INDISTINGUISHABLE from one
// that does not exist: allow() starts a new bucket at burst. So idle
// keys can be dropped without losing any state at all, and under normal
// traffic that alone keeps the map small.
//
// Only if every tracked key is still actively throttled does the second
// pass run, dropping the oldest down to a low-water mark rather than to
// exactly maxKeys. Evicting one entry per insert would make every
// request past the cap pay for a full scan; going to 90% means the scan
// happens once per maxKeys/10 new keys instead.
//
// THE TRADE-OFF THIS ACCEPTS: evicting a throttled bucket forgives
// whoever owned it. An attacker with enough distinct source addresses
// can therefore push their own penalty out of the map and start fresh.
// That is inherent to bounding memory at all -- the alternative is an
// unbounded map, which is a far more reliable way to take the process
// down than credential stuffing is. See withAuth for why this limiter
// is a speed bump rather than a security boundary.
func (l *rateLimiter) evictLocked(now time.Time) {
	if l.maxKeys <= 0 || len(l.buckets) < l.maxKeys {
		return
	}

	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.lastSeen).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
	if len(l.buckets) < l.maxKeys {
		return
	}

	type aged struct {
		key      string
		lastSeen time.Time
	}
	all := make([]aged, 0, len(l.buckets))
	for k, b := range l.buckets {
		all = append(all, aged{key: k, lastSeen: b.lastSeen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].lastSeen.Before(all[j].lastSeen) })

	lowWater := l.maxKeys * 9 / 10
	for i := 0; i < len(all)-lowWater; i++ {
		delete(l.buckets, all[i].key)
	}
}

// size reports how many keys are currently tracked. Test-facing: the
// bound is a correctness property, and a property nothing can observe
// is a property nothing can catch regressing.
func (l *rateLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// TrustedProxies is the set of peer addresses whose X-Forwarded-For
// header is believed (TRUSTED_PROXY_CIDRS / monitorApi.trustedProxyCIDRs).
//
// WHY THIS EXISTS. X-Forwarded-For is written by whoever connects, so
// honouring it unconditionally lets a client rotate the header and get a
// fresh throttle bucket per request -- the failed-auth limiter then
// throttles nobody. Ignoring it unconditionally is worse in the other
// direction: every request through the Gateway arrives with Traefik's
// pod IP, all callers share one bucket, and one attacker locks out every
// legitimate client behind the proxy.
//
// Conditional trust resolves it: believe the header only when the DIRECT
// SOCKET PEER is a proxy this deployment put there. A forged header from
// anywhere else is ignored and that caller is throttled on the address it
// actually connected from, which it cannot spoof without spoofing TCP.
//
// The zero value is "not configured", which deliberately preserves the
// original behaviour -- see ClientAddress.
type TrustedProxies struct {
	nets []*net.IPNet
}

// ParseTrustedProxies reads a comma-separated CIDR list.
//
// An unparseable entry is an ERROR rather than a skip, and that matters:
// dropping a bad entry silently could empty the set, and an empty set
// means "trust every peer's X-Forwarded-For". A typo would therefore
// WIDEN trust while looking like a narrowing -- the exact failure a
// security setting must not have. main.go turns this into a startup
// failure.
func ParseTrustedProxies(raw string) (TrustedProxies, error) {
	var t TrustedProxies
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		_, n, err := net.ParseCIDR(entry)
		if err != nil {
			return TrustedProxies{}, fmt.Errorf("%q is not a CIDR (want e.g. 10.42.0.0/16): %w", entry, err)
		}
		t.nets = append(t.nets, n)
	}
	return t, nil
}

// Configured reports whether any CIDR was supplied. False means every
// peer's X-Forwarded-For is honoured, which is the pre-existing
// behaviour and the documented trade-off.
func (t TrustedProxies) Configured() bool { return len(t.nets) > 0 }

// Trusts reports whether ip is one of the configured proxies.
func (t TrustedProxies) Trusts(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range t.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientAddress is the key the failed-auth throttle buckets on.
//
// Rules, in order:
//
//   - No trusted CIDRs configured: X-Forwarded-For's first value when
//     present, else the socket address. Unchanged from before this
//     setting existed, so enabling the feature is opt-in and an
//     unconfigured deployment behaves exactly as it did.
//   - Socket peer inside a trusted CIDR: X-Forwarded-For's first value
//     when present, else the socket address. The first value is the
//     original client; later entries are proxies that appended
//     themselves.
//   - Socket peer NOT trusted: the socket address, and the header is
//     ignored entirely. A forged X-Forwarded-For buys nothing.
//
// Returns the socket address on any parse failure, which is the
// conservative direction: a caller shares a bucket rather than escaping
// one.
func ClientAddress(r *http.Request, trusted TrustedProxies) string {
	host := r.RemoteAddr
	// RemoteAddr is "host:port"; the port would make every connection
	// from one host look like a different client.
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}

	if trusted.Configured() && !trusted.Trusts(net.ParseIP(host)) {
		return host
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}
	if i := strings.IndexByte(xff, ','); i >= 0 {
		xff = xff[:i]
	}
	if first := strings.TrimSpace(xff); first != "" {
		return first
	}
	return host
}
