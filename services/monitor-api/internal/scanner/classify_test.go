package scanner

import "testing"

func TestClassifyScanError(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		reason string
	}{
		{
			name:   "not found",
			raw:    `trivy scan failed for "cosign:latest": image tag or digest not found in the registry -- check that the ref is correct`,
			reason: "not_found",
		},
		{
			name:   "registry auth failure via cleaned message",
			raw:    `trivy scan failed for "private/app:latest": registry authentication failed -- check the configured registry credentials`,
			reason: "registry_auth_failed",
		},
		{
			name:   "registry auth failure via raw stderr",
			raw:    `oras pull failed: GET https://scm-registry/v2/private/app/manifests/latest: UNAUTHORIZED: authentication required`,
			reason: "registry_auth_failed",
		},
		{
			name:   "unsupported artifact type",
			raw:    `trivy scan failed for "ai/gemma4:e4b": exit status 1 (* remote error: unsupported artifact type "application/vnd.cncf.model.manifest.v1+json" for image "ai/gemma4:e4b")`,
			reason: "unsupported_artifact",
		},
		{
			name:   "job timeout",
			raw:    `trivy scan job for "cosign:latest": timed out waiting for trivy scan job to complete: context deadline exceeded`,
			reason: "scan_timeout",
		},
		{
			name:   "job crashed",
			raw:    `trivy scan job for "cosign:latest": trivy scan job failed to run (crashed or was killed before producing a result)`,
			reason: "scan_crashed",
		},
		{
			name:   "job create failure",
			raw:    `create trivy scan job for "cosign:latest": jobs.batch is forbidden`,
			reason: "scan_infra_error",
		},
		{
			name:   "unpacker job create failure",
			raw:    `create scan job for "myapp:latest": jobs.batch is forbidden`,
			reason: "scan_infra_error",
		},
		{
			name:   "find pod failure",
			raw:    `find pod for finished trivy scan job "scm-scan-abc123": pod not found`,
			reason: "scan_infra_error",
		},
		{
			name:   "read logs failure",
			raw:    `read logs for trivy scan job "scm-scan-abc123": connection refused`,
			reason: "scan_infra_error",
		},
		{
			name:   "worker result parse failure",
			raw:    `trivy scan job "scm-scan-abc123" did not contain a valid result: unexpected end of JSON input (output: ...)`,
			reason: "scan_infra_error",
		},
		{
			name:   "sbom fetch failure",
			raw:    `fetch sbom artifact "scm-registry/sboms/app:latest": connection refused`,
			reason: "fetch_failed",
		},
		{
			name:   "scanner panic",
			raw:    `scanner panicked: runtime error: index out of range`,
			reason: "scanner_error",
		},
		{
			name:   "unrecognized failure",
			raw:    "some completely novel trivy failure nobody has seen before",
			reason: "unknown",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, message := ClassifyScanError(tc.raw)
			if reason != tc.reason {
				t.Errorf("ClassifyScanError(%q) reason = %q, want %q", tc.raw, reason, tc.reason)
			}
			if message == "" {
				t.Errorf("ClassifyScanError(%q) returned an empty message", tc.raw)
			}
			if message == tc.raw {
				t.Errorf("ClassifyScanError(%q) returned the raw text verbatim, want a friendly message", tc.raw)
			}
		})
	}
}

// TestClassifyScanError_UnsupportedArtifactNotNotFound guards against
// over-matching, the same concern
// TestWrapTrivyScanError_UnsupportedArtifactTypeIsNotManifestUnknown
// guards one layer down: an unsupported-artifact-type failure must
// never get classified as "not_found" just because both originate from
// trivy's "remote error" line.
func TestClassifyScanError_UnsupportedArtifactNotNotFound(t *testing.T) {
	raw := `trivy scan failed for "ai/gemma4:e4b": exit status 1 (* remote error: unsupported artifact type "application/vnd.cncf.model.manifest.v1+json" for image "ai/gemma4:e4b")`
	reason, _ := ClassifyScanError(raw)
	if reason == "not_found" {
		t.Errorf("ClassifyScanError(%q) reason = %q, want anything but not_found", raw, reason)
	}
}
