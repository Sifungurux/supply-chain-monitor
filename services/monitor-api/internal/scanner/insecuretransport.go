package scanner

import (
	"os"
)

// RegistryAddrEnv names the in-cluster registry (REGISTRY_ADDR, e.g.
// "scm-registry.supply-chain-monitor.svc.cluster.local:5000"). Set by
// the chart's monitor-api ConfigMap and forwarded into every scan-worker
// Job that pulls (see IsolatedUnpackerScanner/IsolatedGrypeScanner).
const RegistryAddrEnv = "REGISTRY_ADDR"

// InsecureTransportAllowed reports whether the deployment's
// insecure/plain-HTTP switch may actually be applied when pulling this
// particular ref.
//
// THE SWITCHES ARE DEPLOYMENT-WIDE; THE HOSTS ARE NOT. UNPACKER_INSECURE,
// FETCH_PLAIN_HTTP and GRYPE_REGISTRY_INSECURE_USE_HTTP exist for one
// reason: scm-registry runs plain HTTP inside the cluster in a dev
// setup. But each of them was applied to EVERY pull the process made,
// so turning on "my in-cluster registry has no TLS" also turned off
// transport security for docker.io, ghcr.io and every other public
// registry -- silently, on the same code path, with nothing in the
// output saying so (report S4, leg 3).
//
// This narrows those switches to the hosts they were meant for:
//
//   - the host in REGISTRY_ADDR, and
//   - anything an operator listed in REF_HOST_ALLOWLIST, which is
//     already how they declare "these hosts are mine and internal"
//     (see refvalidate.go).
//
// Everything else keeps TLS regardless of how the switch is set, so a
// dev cluster pulling from a plain-HTTP scm-registry no longer means a
// downgraded connection to Docker Hub in the same process.
//
// EVERY candidate host must qualify, not just one. refHosts returns up
// to two readings of an ambiguous ref (a bare "alpine:3.19" qualified
// to docker.io, plus the raw first segment when they differ), and
// which one a given tool will actually dial is exactly the ambiguity
// that makes guessing unsafe here. Any doubt means TLS -- the same
// direction validateRefHost fails in.
//
// Reads the environment on each call rather than caching, matching
// refHostAllowed: this is a handful of string comparisons on a path
// that is about to make a network round trip anyway, and caching would
// only make it untestable.
func InsecureTransportAllowed(ref string) bool {
	hosts := refHosts(ref)
	if len(hosts) == 0 {
		// No host to reason about (a local path, or a ref this package
		// could not read as one). Nothing to downgrade, and refusing is
		// the safe reading either way.
		return false
	}
	for _, host := range hosts {
		if !insecureHost(host) {
			return false
		}
	}
	return true
}

// insecureHost reports whether one host is one this deployment has
// declared its own.
func insecureHost(host string) bool {
	if host == "" {
		return false
	}
	if addr := os.Getenv(RegistryAddrEnv); addr != "" && hostOf(addr) == host {
		return true
	}
	// REF_HOST_ALLOWLIST already means "I know what this host is and it
	// is internal" -- the same statement plain-HTTP needs. An operator
	// running a second internal registry lists it there today to get
	// past validateRefHost at all, and would otherwise have to list it
	// somewhere else again for this.
	return refHostAllowed(host)
}
