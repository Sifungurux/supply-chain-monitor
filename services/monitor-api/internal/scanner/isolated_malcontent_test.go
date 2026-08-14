package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/k8sjob"
)

func envOf(t *testing.T, job *k8sjob.Job) map[string]string {
	t.Helper()
	if job == nil {
		t.Fatal("no Job was created")
	}
	containers := job.Spec.Template.Spec.Containers
	if len(containers) != 1 {
		t.Fatalf("job has %d containers, want 1", len(containers))
	}
	out := make(map[string]string, len(containers[0].Env))
	for _, e := range containers[0].Env {
		out[e.Name] = e.Value
	}
	return out
}

func TestIsolatedMalcontentScanner_Scan_HappyPath(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "supply-chain-monitor",
		statusSequence: []jobStatusResult{{succeeded: true}},
		podName:        "scm-scan-abc-xyz",
		logs: `{"Files":{"/bin/busybox":{"Path":"/bin/busybox","Behaviors":[
			{"ID":"exec/shell/busybox_exec","Description":"runs atypical busybox programs","RiskLevel":"HIGH"}]}}}`,
	}
	s := NewIsolatedMalcontentScanner(client, IsolatedMalcontentConfig{MinRisk: "high"})

	findings, err := s.Scan(context.Background(), "alpine:3.19")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "exec/shell/busybox_exec" {
		t.Fatalf("findings = %+v", findings)
	}
	if client.deleteCalled == 0 {
		t.Error("the Job must be deleted after a successful scan")
	}
}

// The severity floor has to be applied on THIS side of the Job. The
// flag handed to malcontent does not filter (measured: --min-risk
// critical, high and any return identical output in scan mode), so if
// the isolated path skipped FilterBySeverity, every deployment would
// get the noise the default exists to prevent -- and the unit tests
// covering the in-process path would still pass.
func TestIsolatedMalcontentScanner_AppliesTheSeverityFloor(t *testing.T) {
	logs := `{"Files":{"/bin/busybox":{"Path":"/bin/busybox","Behaviors":[
		{"ID":"exec/shell/busybox_exec","Description":"d","RiskLevel":"HIGH"}]}}}`

	high := &fakeJobClient{namespace: "n", statusSequence: []jobStatusResult{{succeeded: true}}, podName: "p", logs: logs}
	got, err := NewIsolatedMalcontentScanner(high, IsolatedMalcontentConfig{MinRisk: "high"}).Scan(context.Background(), "alpine:3.19")
	if err != nil || len(got) != 1 {
		t.Fatalf("at threshold high: %+v, %v -- want the HIGH finding kept", got, err)
	}

	critical := &fakeJobClient{namespace: "n", statusSequence: []jobStatusResult{{succeeded: true}}, podName: "p", logs: logs}
	got, err = NewIsolatedMalcontentScanner(critical, IsolatedMalcontentConfig{MinRisk: "critical"}).Scan(context.Background(), "alpine:3.19")
	if err != nil || len(got) != 0 {
		t.Fatalf("at threshold critical: %+v, %v -- want the HIGH finding dropped", got, err)
	}
}

// This Job does not run `monitor-api scan-worker` like every other
// isolated scanner -- there is no monitor-api in Chainguard's image. So
// what it runs is the command line, and getting that wrong (flags after
// the subcommand, or the wrong image) fails at run time in a pod, which
// is the slowest possible place to find out.
func TestIsolatedMalcontentScanner_RunsUpstreamImageWithTheSameArgs(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "supply-chain-monitor",
		statusSequence: []jobStatusResult{{succeeded: true}},
		podName:        "p",
		logs:           `{"Files":{}}`,
	}
	s := NewIsolatedMalcontentScanner(client, IsolatedMalcontentConfig{MinRisk: "critical"})
	if _, err := s.Scan(context.Background(), "alpine:3.19"); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	spec := client.created.Spec.Template.Spec
	if got := spec.Containers[0].Image; got != DefaultMalcontentImage {
		t.Errorf("image = %q, want upstream's pinned image (monitor-api's own cannot run this binary)", got)
	}
	want := append([]string{"/usr/bin/mal"}, NewMalcontentScanner("", "critical", "").args("alpine:3.19")...)
	got := spec.Containers[0].Command
	if len(got) != len(want) {
		t.Fatalf("command = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("command = %v, want %v", got, want)
		}
	}
}

// The report is carved out of a combined stdout+stderr stream, so
// anything malcontent logs around it must not break parsing.
func TestIsolatedMalcontentScanner_ParsesReportAmidOtherOutput(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "supply-chain-monitor",
		statusSequence: []jobStatusResult{{succeeded: true}},
		podName:        "p",
		logs: "time=2026-08-14 level=INFO msg=\"scanning\"\n" +
			`{"Files":{"/bin/x":{"Path":"/bin/x","Behaviors":[{"ID":"exec/shell/busybox_exec","Description":"d","RiskLevel":"CRITICAL"}]}}}` +
			"\ntime=2026-08-14 level=INFO msg=\"done\"\n",
	}
	s := NewIsolatedMalcontentScanner(client, IsolatedMalcontentConfig{})

	findings, err := s.Scan(context.Background(), "alpine:3.19")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "exec/shell/busybox_exec" || findings[0].Severity != "critical" {
		t.Fatalf("findings = %+v", findings)
	}
}

// malcontent pulls and extracts the image, exactly like the trivy,
// grype and unpacker Jobs -- so it needs their ephemeral-storage
// sizing. The "sbom" numbers (128Mi/256Mi) would kill this Job on
// anything but a tiny image, and the eviction message for that names
// the pod limit, not the code that set it.
func TestIsolatedMalcontentScanner_UsesImageSizedEphemeralStorage(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "supply-chain-monitor",
		statusSequence: []jobStatusResult{{succeeded: true}},
		podName:        "p",
		logs:           `{"findings":[]}`,
	}
	if _, err := NewIsolatedMalcontentScanner(client, IsolatedMalcontentConfig{}).Scan(context.Background(), "alpine:3.19"); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	res := client.created.Spec.Template.Spec.Containers[0].Resources
	if got, want := res.Limits["ephemeral-storage"], ephemeralStorageLimitFor("image"); got != want {
		t.Errorf("ephemeral-storage limit = %q, want the image sizing %q", got, want)
	}
	if got, want := res.Requests["ephemeral-storage"], ephemeralStorageRequestFor("image"); got != want {
		t.Errorf("ephemeral-storage request = %q, want the image sizing %q", got, want)
	}
}

func TestIsolatedMalcontentScanner_CleansUpEvenOnFailure(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "supply-chain-monitor",
		statusSequence: []jobStatusResult{{failed: true}},
		podName:        "p",
	}
	s := NewIsolatedMalcontentScanner(client, IsolatedMalcontentConfig{PollInterval: time.Millisecond})

	if _, err := s.Scan(context.Background(), "alpine:3.19"); err == nil {
		t.Fatal("expected an error when the Job fails")
	}
	if client.deleteCalled == 0 {
		t.Error("a failed Job must still be deleted -- otherwise every failure leaks a pod")
	}
}

// A Job that produced no report at all (crashed before printing,
// wrong image, flags rejected) must be an error naming what was seen --
// not an empty, successful-looking scan that would mark every existing
// malware finding fixed.
func TestIsolatedMalcontentScanner_NoReportIsAnError(t *testing.T) {
	client := &fakeJobClient{
		namespace:      "supply-chain-monitor",
		statusSequence: []jobStatusResult{{succeeded: true}},
		podName:        "p",
		logs:           "flag provided but not defined: -min-risk\n",
	}
	s := NewIsolatedMalcontentScanner(client, IsolatedMalcontentConfig{})

	if _, err := s.Scan(context.Background(), "alpine:3.19"); err == nil {
		t.Fatal("expected an error when the Job printed no report")
	}
}

func TestIsolatedMalcontentScanner_Bucket(t *testing.T) {
	var s any = NewIsolatedMalcontentScanner(&fakeJobClient{}, IsolatedMalcontentConfig{})
	ba, ok := s.(BucketAffinity)
	if !ok || ba.Bucket() != "malware" {
		t.Fatalf("want a malware BucketAffinity, got %v (ok=%v)", s, ok)
	}
}
