package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// JobStatusChecker is the slice of k8sjob.Client the wait loop needs --
// narrow on purpose, so this file has no dependency on the rest of the
// client and the three isolated scanners can share one implementation.
type JobStatusChecker interface {
	JobStatus(ctx context.Context, name string) (succeeded, failed bool, err error)
}

// Polling bounds. The interval grows from initial to max: a scan runs
// for 30-300s, so the first few checks are worth making promptly while
// the rest are almost always "still running".
//
// Why this matters beyond politeness: every isolated scanner polls its
// own Job, so the API-server load is (concurrent scans x scanners per
// scan) requests per interval. At SCAN_CONCURRENCY=8 with the chart's
// default cveScanner "both", that is 24 pollers -- roughly 12 GET/s
// sustained at a flat 2s interval, on top of Job create/delete and
// normal kubelet traffic. On this project's k3s cluster that was enough
// to saturate the API server: monitor-api's own status checks started
// timing out ("context deadline exceeded ... awaiting headers"), which
// (see maxConsecutiveStatusErrors) then failed the scans outright.
const (
	pollIntervalMax   = 10 * time.Second
	pollBackoffFactor = 2
)

// maxConsecutiveStatusErrors is how many status checks in a row may fail
// before the wait gives up on the Job.
//
// It used to be effectively 1: a single error returned immediately and
// failed the scan. That turned a transient, self-correcting condition --
// a busy API server -- into 12 failed scans in one load test, on Jobs
// that were running perfectly. A status check failing says nothing about
// the Job; it says something about the caller's ability to ask right
// now. ctx still bounds the total wait, so retrying cannot hang: the
// deadline arrives regardless.
const maxConsecutiveStatusErrors = 5

// waitForJob blocks until the named Job succeeds, fails, or ctx expires.
// noun is used in error messages ("trivy scan job", "scan job") so the
// three callers keep the wording they had.
func waitForJob(ctx context.Context, client JobStatusChecker, name, noun string, initialInterval time.Duration) error {
	interval := initialInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	consecutiveErrors := 0

	for {
		succeeded, failed, err := client.JobStatus(ctx, name)
		switch {
		case err != nil:
			consecutiveErrors++
			if consecutiveErrors >= maxConsecutiveStatusErrors {
				return fmt.Errorf("check job status (%d consecutive failures): %w", consecutiveErrors, err)
			}
			// Logged, not returned: this is the condition that used to
			// fail scans silently-looking-like-scanner-errors, and an
			// operator needs to see it happening even when it recovers.
			slog.Warn("job status check failed, retrying",
				"job", name, "consecutive_errors", consecutiveErrors,
				"max_consecutive_errors", maxConsecutiveStatusErrors, "err", err)
		case failed:
			return fmt.Errorf("%s failed to run (crashed or was killed before producing a result)", noun)
		case succeeded:
			return nil
		default:
			consecutiveErrors = 0
		}

		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for %s to complete: %w", noun, ctx.Err())
		}

		// Back off toward the ceiling. A Job that finishes quickly is
		// still noticed quickly; a long one stops costing a request
		// every couple of seconds for its whole duration.
		if interval < pollIntervalMax {
			interval *= pollBackoffFactor
			if interval > pollIntervalMax {
				interval = pollIntervalMax
			}
		}
	}
}
