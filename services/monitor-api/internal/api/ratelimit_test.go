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

	time.Sleep(50 * time.Millisecond) // far more than enough to overfill past burst if capping were broken

	allowed := 0
	for i := 0; i < 10; i++ {
		if l.allow("key-a") {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("expected exactly 1 more allowed request (burst of 2, one already spent), got %d", allowed)
	}
}
