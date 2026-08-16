package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"
)

// RefHostAllowlistEnv is the environment variable (REF_HOST_ALLOWLIST)
// holding a comma-separated list of registry hosts that are exempt from
// every check below -- the escape hatch for the one case this
// deployment genuinely needs: its own in-cluster registry. scm-registry
// is reached as scm-registry:5000 / scm-registry.<ns>.svc.cluster.local
// :5000, which is BOTH a cluster-DNS name and a ClusterIP in RFC1918
// space, so without an allowlist entry every file/sbom/sarif artifact
// in a normal install would be refused. The chart fills this in for
// exactly those hosts -- see charts/supply-chain-monitor's
// monitor-api/configmap.yaml and monitorApi.refHostAllowlist.
//
// Entries are matched on host only; a port is accepted and ignored
// ("scm-registry:5000" and "scm-registry" mean the same thing), since
// nothing here can bound which port a ref uses anyway.
const RefHostAllowlistEnv = "REF_HOST_ALLOWLIST"

// refResolveTimeout bounds the DNS lookup one ValidateRef call makes.
// Registration resolves a digest under its own 8s budget (see the API's
// digestResolveTimeout); this runs before that and must not be able to
// hang a request on its own if the cluster's resolver is unhealthy.
const refResolveTimeout = 5 * time.Second

// ValidateRef refuses an artifact ref before anything makes an outbound
// request with it. A ref is attacker-controlled input at a trust
// boundary -- POST /api/v1/artifacts hands it straight to `oras` (digest
// resolution, blob pull) and to trivy/grype/unpacker, each of which will
// happily connect wherever the ref's host points. Without this, the ref
// is an SSRF primitive: "169.254.169.254/v2/..." reaches the cloud
// instance metadata service from inside the pod, and any RFC1918 or
// *.svc.cluster.local host reaches a service that is only reachable
// because monitor-api is the one making the call.
//
// The rules, in order:
//
//   - a scheme ("https://...", "file://...") is not a registry
//     reference at all -- an OCI ref is host/repo:tag, never a URL;
//   - a local filesystem path makes no outbound request, so there is no
//     host to judge -- it is held to localpath.go's policy instead,
//     which refuses it outright unless an operator enabled local paths
//     and it falls inside their declared root;
//   - a host in REF_HOST_ALLOWLIST passes everything below it;
//   - *.svc.cluster.local is refused by NAME, before any lookup, since
//     that suffix means "in-cluster service" whatever it resolves to;
//   - everything else is resolved, and refused if any address it
//     resolves to is loopback, link-local (169.254.0.0/16 and fe80::/10
//     -- the cloud metadata address lives here), private (RFC1918 and
//     IPv6 ULA), or unspecified.
//
// Errors are safe to return to a caller: they name the class of address
// refused, never the address it resolved to (that would turn a 400 into
// an internal-DNS oracle). The resolved address is logged instead.
//
// ponytail: resolve-then-connect is inherently TOCTOU -- a hostile DNS
// server can answer this lookup with a public address and oras's with
// 169.254.169.254 (classic rebinding). Closing that needs the
// connection itself pinned to the address validated here, which means
// dialing the registry in-process instead of shelling out to oras.
// Calling this again at each point of use (fetch.go, digest.go) shrinks
// the window rather than closing it; pin the dial if the registry
// client ever moves in-process.
func ValidateRef(ctx context.Context, ref string) error {
	if scheme, _, ok := strings.Cut(ref, "://"); ok {
		return fmt.Errorf("ref must be an OCI registry reference (host/repo:tag), not a %q URL", scheme)
	}
	// Not trimmed, refused: this has to judge the exact string the
	// callers below hand to oras, and a ref that only passes because
	// validation quietly normalized it first is the same parse-versus-use
	// gap refHosts exists to close.
	if strings.TrimSpace(ref) != ref {
		return fmt.Errorf("ref must not have leading or trailing whitespace")
	}
	// ARGUMENT INJECTION. Every scanner hands the ref to an external
	// tool as a POSITIONAL argument (trivy image <ref>, oras pull
	// <ref>, unpacker <ref>, ...), so a ref beginning with "-" is
	// parsed by that tool as a FLAG rather than a reference.
	//
	// "--cache-dir" or "-o" reaching trivy redirects where it writes
	// inside the scan worker. That is not remote code execution, but it
	// breaks exactly the boundary the isolated-Job design exists to
	// hold, and any caller able to register an artifact can do it.
	//
	// Checked here, before the host logic, because the host checks
	// cannot see it: refHosts treats "-o" as a hostless single-segment
	// ref, Docker Hub qualification gives it a legitimate-looking host,
	// and validation returns nil. Measured before this was written --
	// "-o", "--cache-dir", "-o.x/foo" and "--output=/tmp/x" all passed.
	//
	// Placed after the local-path branch would be wrong: a local path is
	// absolute (see checkLocalArtifactPath), so it can never begin with
	// "-", and checking first keeps the rule ahead of every branch.
	// NOT a full OCI distribution grammar check, deliberately. A
	// reference regexp would reject more, but it also rejects more
	// FALSELY -- real-world refs carry ports, digests, nested paths and
	// unusual tags, and a scanner that refuses a legitimate image is a
	// worse failure here than one that accepts an odd-looking name the
	// registry will reject anyway. The specific hazard is
	// flag-injection, so that is what is checked; the scheme, whitespace
	// and host rules above cover the rest of the reported surface.
	// Revisit if a concrete ref shape gets through that a grammar would
	// have caught.
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("ref %q must not begin with \"-\" -- it would be parsed as a command-line flag by the scanner it is passed to", ref)
	}
	if looksLikeLocalPath(ref) {
		// A local path has no host to check -- but it does have a policy
		// to satisfy, and refusing it here means an artifact nothing
		// could ever legally open is refused at registration instead of
		// failing every scan forever. Lexical only (see
		// checkLocalArtifactPath): requiring the file to exist would
		// break registering an artifact before it lands in the volume.
		_, _, err := checkLocalArtifactPath(ref)
		return err
	}

	hosts := refHosts(ref)
	if len(hosts) == 0 {
		return fmt.Errorf("ref %q has no registry host", ref)
	}
	for _, host := range hosts {
		if err := validateRefHost(ctx, ref, host); err != nil {
			return err
		}
	}
	return nil
}

// validateRefHost applies the rules to one candidate host.
func validateRefHost(ctx context.Context, ref, host string) error {
	if refHostAllowed(host) {
		return nil
	}
	if strings.HasSuffix(host, ".svc.cluster.local") {
		return fmt.Errorf("ref host %q is an in-cluster service address -- refused (set %s to permit it)", host, RefHostAllowlistEnv)
	}

	rctx, cancel := context.WithTimeout(ctx, refResolveTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(rctx, host)
	if err != nil {
		// Deliberately open: a host that doesn't resolve has no address
		// to reach, so there is nothing to protect against here, and
		// refusing would break a case this service already supports on
		// purpose -- registering an artifact whose registry is down,
		// air-gapped, or simply not resolvable from this pod is routine
		// (see findDuplicate's comment in internal/api/artifacts.go),
		// and the fetch/scan that follows fails honestly on its own.
		slog.Warn("ref host did not resolve -- allowing registration, the fetch will fail on its own if it stays unresolvable", "host", host, "err", err)
		return nil
	}
	for _, a := range addrs {
		if class := blockedAddrClass(a.IP); class != "" {
			slog.Warn("refused ref", "ref", ref, "host", host, "ip", a.IP, "class", class)
			return fmt.Errorf("ref host %q resolves to a %s address -- refused (set %s to permit it)", host, class, RefHostAllowlistEnv)
		}
	}
	return nil
}

// refHosts returns every host this ref could actually be fetched from,
// because this package's two consumers of a ref do NOT agree on which
// token is the host:
//
//   - OrasDigestResolver.Resolve qualifies first, so
//     "vault/sboms/app:1.0" is docker.io/vault/sboms/app:1.0 to it;
//   - RegistryFetcher.Fetch hands the ref to `oras pull` raw, and oras
//     parses the first segment as the registry host -- the behaviour
//     qualifyDockerHubRef's own comment documents for "bitnami".
//
// So that one ref means docker.io to one caller and a single-label host
// "vault" to the other -- and a single-label host inside a pod is
// exactly what the resolver's search domains turn into
// vault.<ns>.svc.cluster.local, a ClusterIP, an in-cluster service.
// Validating only the qualified host would leave the fetch path open
// through the very case this exists to refuse, so both are checked and
// each must pass on its own.
//
// The cost is that a Docker Hub org name colliding with a Service name
// in this namespace ("postgres/foo:1" where a postgres Service exists)
// is refused. That collision is genuinely ambiguous -- oras would pull
// from the Service -- so refusing is the right answer, and
// REF_HOST_ALLOWLIST is there for an operator who means the org.
func refHosts(ref string) []string {
	qualified := hostOf(firstSegment(qualifyDockerHubRef(ref)))
	hosts := []string{qualified}
	// Only a ref WITH a path separator has a first segment oras would
	// treat as a host at all; a bare "alpine:3.19" is not a reference
	// oras pulls from anywhere, so there's no second candidate to check
	// (and no pointless second DNS lookup on the common path).
	if first, _, ok := strings.Cut(ref, "/"); ok {
		if h := hostOf(first); h != "" && h != qualified {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

func firstSegment(ref string) string {
	first, _, _ := strings.Cut(ref, "/")
	return first
}

// hostOf normalizes one host[:port] token: lower-cased, port stripped,
// IPv6 brackets removed.
func hostOf(hostPort string) string {
	hostPort = strings.ToLower(hostPort)
	// SplitHostPort also unwraps the brackets around an IPv6 literal
	// ("[::1]:5000" -> "::1"); it errors when there's no port at all,
	// which leaves the bracket-stripping below to handle a bare "[::1]".
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		return h
	}
	return strings.Trim(hostPort, "[]")
}

// refHostAllowed reports whether host is exempted by
// REF_HOST_ALLOWLIST. Read from the environment on every call rather
// than cached once: this is a handful of string comparisons on a
// registration path that is about to make a network round trip anyway,
// and caching would only make the value untestable.
func refHostAllowed(host string) bool {
	for _, entry := range strings.Split(os.Getenv(RefHostAllowlistEnv), ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if h, _, err := net.SplitHostPort(entry); err == nil {
			entry = h
		}
		if strings.Trim(entry, "[]") == host {
			return true
		}
	}
	return false
}

// blockedAddrClass names why an address is off limits, or "" if it
// isn't. The stdlib already knows every one of these ranges -- and
// knows them for IPv6 and IPv4-in-IPv6 too, which is why this doesn't
// hand-roll CIDR matching: IsLinkLocalUnicast covers 169.254.0.0/16
// (the cloud metadata address) and fe80::/10, IsPrivate covers RFC1918
// and IPv6 ULA (fc00::/7), IsLoopback covers 127.0.0.0/8 and ::1.
func blockedAddrClass(ip net.IP) string {
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local"
	case ip.IsPrivate():
		return "private"
	case ip.IsUnspecified():
		return "unspecified"
	}
	return ""
}
