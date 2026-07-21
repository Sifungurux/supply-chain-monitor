package k8sjob

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// These tests fake the Kubernetes API server with a plain
// httptest.Server -- Client only ever speaks plain REST/JSON, so this
// is a real, runnable test of every method without needing an actual
// cluster or a mounted ServiceAccount.

func TestClient_CreateJob(t *testing.T) {
	var gotPath, gotMethod, gotAuth string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := newTestClient(srv.Client(), srv.URL, "test-ns", "test-token")
	job := NewScanJob(ScanJobConfig{Name: "scm-scan-1", Namespace: "test-ns", Image: "monitor-api:dev"})

	if err := c.CreateJob(context.Background(), job); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/apis/batch/v1/namespaces/test-ns/jobs" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization header = %q", gotAuth)
	}
	if gotBody["kind"] != "Job" {
		t.Errorf("posted body kind = %v, want Job", gotBody["kind"])
	}
}

func TestClient_CreateJob_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message":"jobs.batch is forbidden"}`)
	}))
	defer srv.Close()

	c := newTestClient(srv.Client(), srv.URL, "test-ns", "test-token")
	err := c.CreateJob(context.Background(), NewScanJob(ScanJobConfig{Name: "x", Namespace: "test-ns"}))
	if err == nil {
		t.Fatal("expected an error on a 403 response")
	}
}

func TestClient_JobStatus(t *testing.T) {
	cases := []struct {
		name          string
		body          string
		wantSucceeded bool
		wantFailed    bool
	}{
		{"still running", `{"status":{}}`, false, false},
		{"succeeded", `{"status":{"succeeded":1}}`, true, false},
		{"failed", `{"status":{"failed":1}}`, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/apis/batch/v1/namespaces/test-ns/jobs/scm-scan-1" {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()

			c := newTestClient(srv.Client(), srv.URL, "test-ns", "test-token")
			succeeded, failed, err := c.JobStatus(context.Background(), "scm-scan-1")
			if err != nil {
				t.Fatalf("JobStatus: %v", err)
			}
			if succeeded != tc.wantSucceeded || failed != tc.wantFailed {
				t.Fatalf("(succeeded, failed) = (%v, %v), want (%v, %v)", succeeded, failed, tc.wantSucceeded, tc.wantFailed)
			}
		})
	}
}

func TestClient_FindPodForJob(t *testing.T) {
	t.Run("returns the first matching pod", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("labelSelector"); got != "job-name=scm-scan-1" {
				t.Errorf("labelSelector = %q", got)
			}
			fmt.Fprint(w, `{"items":[{"metadata":{"name":"scm-scan-1-abcde"}}]}`)
		}))
		defer srv.Close()

		c := newTestClient(srv.Client(), srv.URL, "test-ns", "test-token")
		pod, err := c.FindPodForJob(context.Background(), "scm-scan-1")
		if err != nil {
			t.Fatalf("FindPodForJob: %v", err)
		}
		if pod != "scm-scan-1-abcde" {
			t.Fatalf("pod = %q", pod)
		}
	})

	t.Run("no pod yet is an error, not an empty string", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"items":[]}`)
		}))
		defer srv.Close()

		c := newTestClient(srv.Client(), srv.URL, "test-ns", "test-token")
		if _, err := c.FindPodForJob(context.Background(), "scm-scan-1"); err == nil {
			t.Fatal("expected an error when no pod exists yet")
		}
	})
}

func TestClient_PodLogs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/test-ns/pods/scm-scan-1-abcde/log" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		fmt.Fprint(w, `{"findings":[],"error":""}`)
	}))
	defer srv.Close()

	c := newTestClient(srv.Client(), srv.URL, "test-ns", "test-token")
	logs, err := c.PodLogs(context.Background(), "scm-scan-1-abcde")
	if err != nil {
		t.Fatalf("PodLogs: %v", err)
	}
	if logs != `{"findings":[],"error":""}` {
		t.Fatalf("logs = %q", logs)
	}
}

func TestClient_DeleteJob(t *testing.T) {
	cases := []struct {
		status  int
		wantErr bool
	}{
		{http.StatusOK, false},
		{http.StatusAccepted, false},
		{http.StatusNotFound, false}, // already gone counts as success
		{http.StatusInternalServerError, true},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete {
				t.Errorf("method = %q, want DELETE", r.Method)
			}
			if got := r.URL.Query().Get("propagationPolicy"); got != "Background" {
				t.Errorf("propagationPolicy = %q, want Background (so the job's pod is cleaned up too)", got)
			}
			w.WriteHeader(tc.status)
		}))

		c := newTestClient(srv.Client(), srv.URL, "test-ns", "test-token")
		err := c.DeleteJob(context.Background(), "scm-scan-1")
		if (err != nil) != tc.wantErr {
			t.Errorf("status %d: err = %v, wantErr = %v", tc.status, err, tc.wantErr)
		}
		srv.Close()
	}
}
