package api

import (
	"testing"
	"time"
)

func TestRateLimiter_AllowsUpToBurstThenDenies(t *testing.T) {
	l := newRateLimiter(1, 3) // 1/sec sustained, burst of 3

	for i := 0; i < 3; i++ {
		if !l.allow("key-a") {
			t.Fatalf("request %d: expected allow (within burst), got denied", i)
		}
	}
	if l.allow("key-a") {
		t.Fatal("expected the 4th immediate request to be denied once the burst is exhausted")
	}
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	l := newRateLimiter(100, 1) // fast refill so the test doesn't need to sleep long

	if !l.allow("key-a") {
		t.Fatal("expected the first request to be allowed")
	}
	if l.allow("key-a") {
		t.Fatal("expected the second immediate request to be denied (burst of 1, already spent)")
	}

	time.Sleep(20 * time.Millisecond) // at 100 tokens/sec, ~2 tokens accumulate

	if !l.allow("key-a") {
		t.Fatal("expected a request to be allowed again after enough time passed to refill")
	}
}

func TestRateLimiter_KeysAreIndependent(t *testing.T) {
	l := newRateLimiter(1, 1)

	if !l.allow("key-a") {
		t.Fatal("expected key-a's first request to be allowed")
	}
	if l.allow("key-a") {
		t.Fatal("expected key-a's second immediate request to be denied")
	}
	if !l.allow("key-b") {
		t.Fatal("expected key-b to have its own independent bucket, unaffected by key-a's usage")
	}
}

func TestRateLimiter_DoesNotExceedBurstAfterLongIdle(t *testing.T) {
	l := newRateLimiter(1000, 2)

	if !l.allow("key-a") {
		t.Fatal("expected the first request to be allowed")
	}

	// At 1000 tokens/sec, 50ms is enough elapsed time to add 50 tokens if
	// capping were broken -- far more than enough to fully refill the 1
	// token spent above back up to a full bucket of 2. That's the correct,
	// intended behavior of a token bucket: unlike a fixed quota, a long
	// enough idle period always earns back up to the full burst, no
	// matter how much was spent before it, and the cap below exists only
	// to stop it going *past* burst (i.e. accumulating all 50 potential
	// tokens), not to keep it perpetually reduced by past spend.
	time.Sleep(50 * time.Millisecond)

	allowed := 0
	for i := 0; i < 10; i++ {
		if l.allow("key-a") {
			allowed++
		}
	}
	if allowed != 2 {
		t.Fatalf("expected exactly 2 more allowed requests (bucket fully refilled to burst after the idle, then capped there), got %d", allowed)
	}
}

// The bound is the whole point of the bounded variant: the auth-failure
// limiter is keyed by client IP, which a stranger chooses, so an
// unbounded map is a memory leak whose size an attacker controls.
func TestBoundedRateLimiter_MapStaysBounded(t *testing.T) {
	const maxKeys = 100
	l := newBoundedRateLimiter(1, 10, maxKeys)

	// Far more distinct keys than the cap, each used once -- exactly the
	// shape of an attacker rotating source addresses.
	for i := 0; i < maxKeys*50; i++ {
		l.allow("attacker-" + itoa(i))
		if got := l.size(); got > maxKeys {
			t.Fatalf("after %d distinct keys the map holds %d, cap is %d", i+1, got, maxKeys)
		}
	}
	if got := l.size(); got == 0 {
		t.Fatal("map is empty -- eviction cannot be so eager that nothing is tracked at all")
	}
}

// Eviction is LRU by last use, so a SUSTAINED attacker is never
// forgiven: every attempt refreshes their bucket, keeping it off the
// eviction list while genuinely idle keys are dropped around them.
//
// Worth being precise about what this does NOT claim. A key that is
// drained and then goes quiet WILL eventually be evicted -- and that is
// correct, not a hole: at 1 token/sec it would have refilled on its own
// in a few seconds anyway, so dropping it forgives nothing that time
// was not about to forgive. What must not happen is forgiving someone
// who is still hammering.
func TestBoundedRateLimiter_SustainedAttackerIsNotForgivenByEviction(t *testing.T) {
	const maxKeys = 50
	l := newBoundedRateLimiter(1, 5, maxKeys)

	for i := 0; i < 5; i++ {
		l.allow("attacker")
	}
	if l.allow("attacker") {
		t.Fatal("precondition: the attacker should be out of tokens")
	}

	// Flood with unrelated keys, forcing eviction repeatedly, while the
	// attacker keeps trying -- which is what a real one does.
	for i := 0; i < maxKeys*10; i++ {
		l.allow("other-" + itoa(i))
		if l.allow("attacker") {
			t.Fatalf("attacker was forgiven after %d evictions while still actively trying", i+1)
		}
	}
}

// maxKeys 0 means unbounded, which is what the original per-API-key
// limiter relies on -- its key space is already bounded by withAuth
// running first.
func TestRateLimiter_UnboundedByDefault(t *testing.T) {
	l := newRateLimiter(1, 1)
	for i := 0; i < 500; i++ {
		l.allow("key-" + itoa(i))
	}
	if got := l.size(); got != 500 {
		t.Errorf("tracked %d keys, want 500 -- an unbounded limiter must not evict", got)
	}
}

// itoa avoids pulling strconv into this file for one use.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
