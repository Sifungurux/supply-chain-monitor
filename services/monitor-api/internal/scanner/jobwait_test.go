package scanner

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeStatusChecker struct {
	calls    int32
	statuses []struct {
		succeeded, failed bool
		err               error
	}
}

func (f *fakeStatusChecker) JobStatus(_ context.Context, _ string) (bool, bool, error) {
	i := int(atomic.AddInt32(&f.calls, 1)) - 1
	if i >= len(f.statuses) {
		i = len(f.statuses) - 1
	}
	s := f.statuses[i]
	return s.succeeded, s.failed, s.err
}

func steps(in ...any) []struct {
	succeeded, failed bool
	err               error
} {
	var out []struct {
		succeeded, failed bool
		err               error
	}
	for _, v := range in {
		var s struct {
			succeeded, failed bool
			err               error
		}
		switch t := v.(type) {
		case error:
			s.err = t
		case string:
			if t == "ok" {
				s.succeeded = true
			} else if t == "failed" {
				s.failed = true
			}
		}
		out = append(out, s)
	}
	return out
}

// A transient status-check error must NOT fail the scan. This is the
// defect that turned a busy API server into 12 failed scans in a load
// test, on Jobs that were running perfectly.
func TestWaitForJob_RetriesTransientStatusErrors(t *testing.T) {
	c := &fakeStatusChecker{statuses: steps(
		errors.New("context deadline exceeded"),
		errors.New("context deadline exceeded"),
		"running",
		"ok",
	)}
	if err := waitForJob(context.Background(), c, "scm-scan-x", "scan job", time.Millisecond); err != nil {
		t.Fatalf("waitForJob: %v -- transient status errors must not fail a healthy Job", err)
	}
	if n := atomic.LoadInt32(&c.calls); n < 4 {
		t.Fatalf("checked status %d times, want at least 4 (2 errors, then progress)", n)
	}
}

// ...but a persistently unreachable API server must still give up,
// rather than spinning until the scan timeout.
func TestWaitForJob_GivesUpAfterConsecutiveErrors(t *testing.T) {
	c := &fakeStatusChecker{statuses: steps(errors.New("boom"))}
	err := waitForJob(context.Background(), c, "scm-scan-x", "scan job", time.Millisecond)
	if err == nil {
		t.Fatal("expected an error when every status check fails")
	}
	if !strings.Contains(err.Error(), "consecutive") {
		t.Fatalf("error should say it gave up after repeated failures: %v", err)
	}
	if n := atomic.LoadInt32(&c.calls); int(n) != maxConsecutiveStatusErrors {
		t.Fatalf("checked status %d times, want exactly %d", n, maxConsecutiveStatusErrors)
	}
}

// A recovery resets the budget: an error early on must not count
// against an error twenty minutes later.
func TestWaitForJob_ErrorBudgetResetsOnSuccess(t *testing.T) {
	seq := []any{}
	for i := 0; i < maxConsecutiveStatusErrors-1; i++ {
		seq = append(seq, errors.New("blip"))
	}
	seq = append(seq, "running")
	for i := 0; i < maxConsecutiveStatusErrors-1; i++ {
		seq = append(seq, errors.New("blip"))
	}
	seq = append(seq, "ok")

	c := &fakeStatusChecker{statuses: steps(seq...)}
	if err := waitForJob(context.Background(), c, "scm-scan-x", "scan job", time.Millisecond); err != nil {
		t.Fatalf("waitForJob: %v -- a successful check must reset the consecutive-error count", err)
	}
}

func TestWaitForJob_ReportsJobFailure(t *testing.T) {
	c := &fakeStatusChecker{statuses: steps("failed")}
	err := waitForJob(context.Background(), c, "scm-scan-x", "trivy scan job", time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "trivy scan job failed to run") {
		t.Fatalf("err = %v, want the caller's noun and a failure message", err)
	}
}

func TestWaitForJob_HonoursContextDeadline(t *testing.T) {
	c := &fakeStatusChecker{statuses: steps("running")}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := waitForJob(ctx, c, "scm-scan-x", "scan job", time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out waiting") {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("took %v to honour a 60ms deadline", elapsed)
	}
}

// The interval must grow, or 24 concurrent pollers keep hammering the
// API server at the initial rate for the whole scan -- the load that
// caused this change.
func TestWaitForJob_BacksOffToCeiling(t *testing.T) {
	c := &fakeStatusChecker{statuses: steps("running")}
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()

	// Start at 100ms: without backoff that is ~12 checks in 1.2s;
	// with doubling toward the ceiling it is far fewer.
	_ = waitForJob(ctx, c, "scm-scan-x", "scan job", 100*time.Millisecond)
	if n := atomic.LoadInt32(&c.calls); n > 6 {
		t.Fatalf("made %d status checks in 1.2s starting at 100ms -- the interval is not backing off", n)
	}
}
