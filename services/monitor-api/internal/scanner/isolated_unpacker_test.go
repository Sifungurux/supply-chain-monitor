package scanner

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/k8sjob"
)

// fakeJobClient is an in-memory stand-in for *k8sjob.Client, letting
// IsolatedUnpackerScanner's orchestration logic (create, poll, find
// pod, read logs, parse, always clean up) be tested without a real
// Kubernetes API server -- that's covered separately, and for real,
// by internal/k8sjob's own httptest.Server-backed tests.
type fakeJobClient struct {
	namespace string

	createErr error

	// statusSequence is returned in order, one entry per JobStatus
	// call, to simulate polling ("still running" a few times, then
	// finished). The last entry repeats if JobStatus is called more
	// times than there are entries.
	statusSequence []jobStatusResult
	statusCalls    int32

	podName string
	findPodErr error

	logs    string
	logsErr error

	deleteCalled int32
}

type jobStatusResult struct {
	succeeded, failed bool
	err               error
}

func (f *fakeJobClient) Namespace() string { return f.namespace }

func (f *fakeJobClient) CreateJob(_ context.Context, _ *k8sjob.Job) error { return f.createErr }

func (f *fakeJobClient) JobStatus(_ context.Context, _ string) (bool, bool, error) {
	i := atomic.AddInt32(&f.statusCalls, 1) - 1
	if int(i) >= len(f.statusSequence) {
		i = int32(len(f.statusSequence) - 1)
	}
	r := f.statusSequence[i]
	return r.succeeded, r.failed, r.err
}

func (f *fakeJobClient) FindPodForJob(_ context.Context, _ string) (string, error) {
	return f.podName, f.findPodErr
}

func (f *fakeJobClient) PodLogs(_ context.Context, _ string) (string, error) {
	return f.logs, f.logsErr
}

func (f *fakeJobClient) DeleteJob(_ context.Context, _ string) error {
	atomic.AddInt32(&f.deleteCalled, 1)
	return nil
}

func newScanner(t *testing.T, client *fakeJobClient) *IsolatedUnpackerScanner {
	t.Helper()
	return NewIsolatedUnpackerScanner(client, IsolatedUnpackerConfig{
		Image:        "monitor-api:dev",
		PollInterval: time.Millisecond, // fast polling in tests
	})
}

func TestIsolatedUnpackerScanner_Scan_HappyPath(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "test-ns",
		statusSequence: []jobStatusResult{{}, {}, {succeeded: true}}, // "still running" twice, then done
		podName:        "scm-scan-abc-xyz",
		logs:           `{"findings":[{"id":"clamav-signature-match","severity":"critical","title":"eicar","source":"clamav"}]}`,
	}
	s := newScanner(t, client)

	findings, err := s.Scan(context.Background(), "alpine:3.19")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "clamav-signature-match" {
		t.Fatalf("findings = %+v", findings)
	}
	if atomic.LoadInt32(&client.deleteCalled) != 1 {
		t.Fatal("expected the job to be deleted exactly once after a successful scan")
	}
}

func TestIsolatedUnpackerScanner_Scan_CleansUpEvenOnFailure(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "test-ns",
		statusSequence: []jobStatusResult{{failed: true}},
	}
	s := newScanner(t, client)

	if _, err := s.Scan(context.Background(), "alpine:3.19"); err == nil {
		t.Fatal("expected an error when the job itself fails")
	}
	if atomic.LoadInt32(&client.deleteCalled) != 1 {
		t.Fatal("expected cleanup (DeleteJob) even when the scan fails")
	}
}

func TestIsolatedUnpackerScanner_Scan_CreateJobError(t *testing.T) {
	client := &fakeJobClient{
		namespace: "test-ns",
		createErr: errors.New("jobs.batch is forbidden"),
	}
	s := newScanner(t, client)

	if _, err := s.Scan(context.Background(), "alpine:3.19"); err == nil {
		t.Fatal("expected an error when the job can't even be created")
	}
	// Nothing to clean up if creation itself failed -- but DeleteJob
	// runs anyway (harmless no-op against a job that never existed,
	// simpler than adding a special case).
	if atomic.LoadInt32(&client.deleteCalled) != 1 {
		t.Fatal("expected DeleteJob to still run as a harmless cleanup attempt")
	}
}

func TestIsolatedUnpackerScanner_Scan_WorkerReportedError(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "test-ns",
		statusSequence: []jobStatusResult{{succeeded: true}},
		podName:        "scm-scan-abc-xyz",
		logs:           `{"findings":null,"error":"unpacker failed for \"alpine:3.19\": pull failed"}`,
	}
	s := newScanner(t, client)

	_, err := s.Scan(context.Background(), "alpine:3.19")
	if err == nil {
		t.Fatal("expected the worker-reported error to surface")
	}
}

func TestIsolatedUnpackerScanner_Scan_UnparseableLogs(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "test-ns",
		statusSequence: []jobStatusResult{{succeeded: true}},
		podName:        "scm-scan-abc-xyz",
		logs:           "not json at all",
	}
	s := newScanner(t, client)

	if _, err := s.Scan(context.Background(), "alpine:3.19"); err == nil {
		t.Fatal("expected an error when the job's logs aren't valid WorkerResult JSON")
	}
}

func TestIsolatedUnpackerScanner_Scan_TimesOutIfNeverFinishes(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "test-ns",
		statusSequence: []jobStatusResult{{}}, // always "still running"
	}
	s := newScanner(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	if _, err := s.Scan(ctx, "alpine:3.19"); err == nil {
		t.Fatal("expected a timeout error when the job never finishes")
	}
	if atomic.LoadInt32(&client.deleteCalled) != 1 {
		t.Fatal("expected cleanup even after a timeout -- cleanup must use its own context, not the expired one")
	}
}

// TestIsolatedUnpackerScanner_Bucket confirms IsolatedUnpackerScanner
// declares BucketAffinity as "malware" -- it just runs UnpackerScanner's
// own code (always Source: "clamav") inside a Job.
func TestIsolatedUnpackerScanner_Bucket(t *testing.T) {
	s := newScanner(t, &fakeJobClient{namespace: "test-ns"})
	if got := s.Bucket(); got != "malware" {
		t.Errorf("Bucket() = %q, want %q", got, "malware")
	}
}
