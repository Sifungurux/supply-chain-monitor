package scanner

// Ephemeral-storage sizing shared by the isolated trivy and grype
// scan-worker Jobs (isolated_trivy.go, isolated_grype.go).
//
// Both tools, in "image" mode, pull the image being scanned and extract
// its layers to a scratch dir under /tmp before they analyse anything --
// that scratch dir is the Job pod's emptyDir, so every extracted byte
// counts against the pod's own ephemeral-storage limit. The old flat
// 256Mi limit was written on the assumption that nothing in these Jobs
// touches disk (--cache-backend memory keeps the *scan cache* in memory,
// and the vulnerability DB is a read-only PVC mount) -- true of the DB
// and the cache, but not of the image itself.
//
// Measured on the k3d cluster with `du -sk /tmp` sampled inside live
// scan-worker pods during a 100-image run (cluster/load-test-clamav.sh,
// PARALLELISM=10):
//
//	unpacker  rust:1.79     1909Mi     grype  ruby:3.3     895Mi
//	unpacker  python:3.12   1504Mi     grype  rust:1.79    875Mi
//	unpacker  ruby:3.3      1493Mi     grype  grafana:10.4 466Mi
//
// Every grype/trivy "image" Job that got past 256Mi was killed with
// "Pod ephemeral local storage usage exceeds the total limit of
// containers 256Mi" -- a per-pod limit eviction, not node DiskPressure,
// so the fix is the limit, not the request. Sized to match the unpacker
// Job (isolated_unpacker.go), which does the same pull-and-extract work
// against the same images and has held at 2Gi.
//
// "sbom" mode keeps the old small numbers: that Job fetches one JSON
// document and scans it, so there is genuinely nothing on disk to grow.
//
// The ceiling worth knowing: all four k3d nodes share one ~39Gi host
// filesystem, and a loaded run already sits at ~7Gi free, so these
// limits are deliberately not raised further -- concurrent scans are
// bounded only by the client today. If a legitimately larger image
// starts hitting 2Gi, cap scan concurrency in monitor-api before
// raising this, or node-wide DiskPressure will start evicting the
// long-lived pods (clamav, postgres) instead of just a retriable Job.
func ephemeralStorageRequestFor(subCommand string) string {
	if subCommand == "sbom" {
		return "128Mi"
	}
	return "512Mi"
}

func ephemeralStorageLimitFor(subCommand string) string {
	if subCommand == "sbom" {
		return "256Mi"
	}
	return "2Gi"
}
