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
