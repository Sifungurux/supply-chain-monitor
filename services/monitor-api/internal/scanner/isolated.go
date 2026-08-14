package scanner

import "github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/k8sjob"

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
//	unpacker  playwright:v1.44  2395Mi   grype  playwright:v1.44  1838Mi
//	unpacker  mssql:2022        2171Mi   grype  rust:1.79         1685Mi
//	unpacker  rust:1.79         1909Mi   grype  mssql:2022        1614Mi
//	unpacker  python:3.12       1504Mi   grype  ruby:3.3           895Mi
//
// Every grype/trivy "image" Job that got past 256Mi was killed with
// "Pod ephemeral local storage usage exceeds the total limit of
// containers 256Mi" -- a per-pod limit eviction, not node DiskPressure,
// so the fix is the limit, not the request. Sized against the largest
// image in that batch (2395Mi) rather than the old 2Gi the unpacker Job
// happened to carry, which the same run showed two images already
// exceed.
//
// "sbom" mode keeps the old small numbers: that Job fetches one JSON
// document and scans it, so there is genuinely nothing on disk to grow.
//
// The ceiling worth knowing before raising this further: all four k3d
// nodes share one ~39Gi host filesystem, and a PARALLELISM=10 run takes
// it down to ~3Gi free at peak. Concurrent scans have no server-side
// cap -- the client is the only bound today -- so the next increase
// should be a scan-concurrency limit in monitor-api, not a bigger
// per-pod limit. Past a certain point that trades one retriable Job
// failure for node-wide DiskPressure, which evicts clamav and postgres
// too (see clamav.resources in the chart's values.yaml).
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
	return "3Gi"
}

// scratchClassFor decides where one Job's /tmp comes from, and it is
// the same "sbom mode spills nothing" judgement the sizing helpers
// above already make -- kept beside them so the two cannot drift into
// disagreeing about which modes touch disk.
//
// An "image"-mode Job pulls and extracts the whole image (up to 2395Mi
// measured), so it takes whatever the deployment configured -- an
// emptyDir on the node by default, or a per-Job PVC where scan scratch
// space has been moved onto storage.
//
// An "sbom"-mode Job fetches a single JSON document and scans it. It
// already carries the small 128Mi/256Mi sizing for that reason, and
// giving it a PVC would add per-scan provisioning latency and a
// volume-attach round trip to buy storage it never writes to. So it
// opts out explicitly (k8sjob.ScratchNone), even where a StorageClass
// is configured process-wide.
func scratchClassFor(subCommand string) string {
	if subCommand == "sbom" {
		return k8sjob.ScratchNone
	}
	return ""
}
