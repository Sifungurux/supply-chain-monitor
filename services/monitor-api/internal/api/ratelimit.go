package api

import (
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
