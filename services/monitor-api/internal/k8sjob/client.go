package k8sjob

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// serviceAccountDir is where Kubernetes mounts a pod's ServiceAccount
// token/CA cert/namespace when automountServiceAccountToken: true (see
// k8s/monitor-api/serviceaccount.yaml).
const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// Client is a minimal Kubernetes API client scoped to exactly the
// calls IsolatedUnpackerScanner needs: create/get/delete a Job, find
// its pod, read that pod's logs. See the package doc comment (job.go)
// for why this isn't client-go.
type Client struct {
	httpClient *http.Client
	baseURL    string
	namespace  string
	tokenPath  string
	// staticToken bypasses tokenPath -- set only by newTestClient, so
	// tests can point Client at an httptest.Server without a real
	// ServiceAccount token file on disk.
	staticToken string
}

// NewInClusterClient builds a Client from the standard in-cluster
// ServiceAccount mount: the API server address from
// KUBERNETES_SERVICE_HOST/PORT (set automatically in every pod), the
// cluster's CA cert, this pod's namespace, and its token (read fresh
// per request in doRequest, so token rotation -- Kubernetes rotates
// projected ServiceAccount tokens periodically -- is handled for
// free rather than needing an explicit refresh timer).
func NewInClusterClient() (*Client, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("KUBERNETES_SERVICE_HOST/KUBERNETES_SERVICE_PORT not set -- not running inside a kubernetes pod")
	}

	caPath := filepath.Join(serviceAccountDir, "ca.crt")
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certificates found in %s", caPath)
	}

	nsPath := filepath.Join(serviceAccountDir, "namespace")
	nsBytes, err := os.ReadFile(nsPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", nsPath, err)
	}

	return &Client{
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		},
		baseURL:   "https://" + net.JoinHostPort(host, port),
		namespace: strings.TrimSpace(string(nsBytes)),
		tokenPath: filepath.Join(serviceAccountDir, "token"),
	}, nil
}

// newTestClient bypasses NewInClusterClient's file/env reads
// entirely, so client_test.go can exercise every method against a
// plain httptest.Server. Not exported: real callers always go through
// NewInClusterClient.
func newTestClient(httpClient *http.Client, baseURL, namespace, staticToken string) *Client {
	return &Client{httpClient: httpClient, baseURL: baseURL, namespace: namespace, staticToken: staticToken}
}

func (c *Client) Namespace() string { return c.namespace }

func (c *Client) token() (string, error) {
	if c.staticToken != "" {
		return c.staticToken, nil
	}
	b, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return "", fmt.Errorf("read service account token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func (c *Client) doRequest(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	tok, err := c.token()
	if err != nil {
		return nil, err
	}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.httpClient.Do(req)
}

func readBodySnippet(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(b)
}

// CreateJob POSTs job to the batch/v1 Jobs endpoint in c.Namespace().
func (c *Client) CreateJob(ctx context.Context, job *Job) error {
	body, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshal job: %w", err)
	}
	path := fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs", c.namespace)
	resp, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return fmt.Errorf("create job: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("create job: unexpected status %d: %s", resp.StatusCode, readBodySnippet(resp))
	}
	return nil
}

type jobStatusResponse struct {
	Status struct {
		Succeeded int `json:"succeeded"`
		Failed    int `json:"failed"`
	} `json:"status"`
}

// JobStatus reports whether the named Job has finished, and if so,
// whether it succeeded or failed. Both false means it's still running
// (or the status subresource hasn't been populated yet).
func (c *Client) JobStatus(ctx context.Context, name string) (succeeded, failed bool, err error) {
	path := fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs/%s", c.namespace, name)
	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return false, false, fmt.Errorf("get job: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, false, fmt.Errorf("get job: unexpected status %d: %s", resp.StatusCode, readBodySnippet(resp))
	}
	var out jobStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, false, fmt.Errorf("decode job status: %w", err)
	}
	return out.Status.Succeeded > 0, out.Status.Failed > 0, nil
}

type podListResponse struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	} `json:"items"`
}

// FindPodForJob looks up the pod Kubernetes created for jobName, via
// the "job-name" label it automatically attaches. Returns an error if
// no pod exists yet (e.g. called immediately after CreateJob, before
// the Job controller has reacted) -- callers should retry rather than
// treat this as fatal.
func (c *Client) FindPodForJob(ctx context.Context, jobName string) (string, error) {
	q := url.Values{}
	q.Set("labelSelector", "job-name="+jobName)
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods?%s", c.namespace, q.Encode())

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", fmt.Errorf("list pods for job %q: %w", jobName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("list pods for job %q: unexpected status %d: %s", jobName, resp.StatusCode, readBodySnippet(resp))
	}
	var list podListResponse
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return "", fmt.Errorf("decode pod list: %w", err)
	}
	if len(list.Items) == 0 {
		return "", fmt.Errorf("no pod found yet for job %q", jobName)
	}
	return list.Items[0].Metadata.Name, nil
}

// PodLogs fetches the full current log output of podName's (only)
// container.
func (c *Client) PodLogs(ctx context.Context, podName string) (string, error) {
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log", c.namespace, podName)
	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", fmt.Errorf("get logs for pod %q: %w", podName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("get logs for pod %q: unexpected status %d: %s", podName, resp.StatusCode, readBodySnippet(resp))
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read logs for pod %q: %w", podName, err)
	}
	return string(b), nil
}

// DeleteJob removes a Job and (via Background propagation) its pod(s).
// A 404 is treated as success -- the Job is gone either way, which is
// all callers of this actually care about.
func (c *Client) DeleteJob(ctx context.Context, name string) error {
	q := url.Values{}
	q.Set("propagationPolicy", "Background")
	path := fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs/%s?%s", c.namespace, name, q.Encode())

	resp, err := c.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("delete job %q: %w", name, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusNotFound:
		return nil
	default:
		return fmt.Errorf("delete job %q: unexpected status %d: %s", name, resp.StatusCode, readBodySnippet(resp))
	}
}
