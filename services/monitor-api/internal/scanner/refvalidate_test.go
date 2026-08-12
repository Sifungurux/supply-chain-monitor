package scanner

import (
	"context"
	"strings"
	"testing"
)

// Every case below is deliberately DNS-free, because `make test-api`
// runs this in a container that may or may not have working DNS and the
// answer must not depend on which: an IP literal is returned by
// LookupIPAddr without a query, *.svc.cluster.local is refused by name
// before any lookup happens, and "localhost" comes out of /etc/hosts.
// The one accepted case is a public IP literal for the same reason.
func TestValidateRef_RefusesRefsPointingInward(t *testing.T) {
	cases := []struct {
		name    string
		ref     string
		wantErr string // substring of the expected error; "" means "must be accepted"
	}{
		// The one that matters most: every major cloud serves instance
		// credentials at this address, to anything inside the pod that
		// can be talked into making the request for it.
		{name: "cloud metadata IP", ref: "169.254.169.254/latest/meta-data:1", wantErr: "link-local"},
		{name: "cloud metadata IP with port", ref: "169.254.169.254:80/latest/meta-data:1", wantErr: "link-local"},
		{name: "metadata IP as IPv4-mapped IPv6", ref: "[::ffff:169.254.169.254]:80/x:1", wantErr: "link-local"},
		{name: "other link-local", ref: "169.254.1.1:5000/x:1", wantErr: "link-local"},

		{name: "cluster DNS", ref: "scm-registry.supply-chain-monitor.svc.cluster.local:5000/sboms/app:1.0", wantErr: "in-cluster"},
		{name: "cluster DNS, no port", ref: "kubernetes.default.svc.cluster.local/x:1", wantErr: "in-cluster"},

		{name: "RFC1918 10/8", ref: "10.0.0.5:5000/app:1.0", wantErr: "private"},
		{name: "RFC1918 172.16/12", ref: "172.16.0.1:5000/app:1.0", wantErr: "private"},
		{name: "RFC1918 192.168/16", ref: "192.168.1.10:5000/app:1.0", wantErr: "private"},
		{name: "IPv6 unique-local", ref: "[fd00::1]:5000/app:1.0", wantErr: "private"},

		{name: "loopback", ref: "127.0.0.1:5000/app:1.0", wantErr: "loopback"},
		{name: "loopback by name", ref: "localhost:5000/app:1.0", wantErr: "loopback"},
		{name: "IPv6 loopback", ref: "[::1]:5000/app:1.0", wantErr: "loopback"},
		{name: "unspecified", ref: "0.0.0.0:5000/app:1.0", wantErr: "unspecified"},

		// A ref is host/repo:tag -- a URL means the caller is aiming at
		// something that isn't a registry at all.
		{name: "https URL", ref: "https://169.254.169.254/latest/meta-data", wantErr: "not a"},
		{name: "file URL", ref: "file:///etc/shadow", wantErr: "not a"},

		// Refused rather than trimmed: what gets validated has to be the
		// exact string that gets used.
		{name: "leading whitespace", ref: " 169.254.169.254/latest/meta-data:1", wantErr: "whitespace"},

		// A local path has no host to judge, so it is held to
		// localpath.go's policy instead -- off by default, hence
		// refused here. See TestValidateRef_LocalPathsFollowTheSamePolicy.
		{name: "local path", ref: "/tmp/report.sarif", wantErr: "not an accepted artifact ref"},
		{name: "relative local path", ref: "./report.sarif", wantErr: "not an accepted artifact ref"},

		// Accepted: a public address is exactly what this is meant to
		// let through.
		{name: "public IP literal", ref: "8.8.8.8:5000/app:1.0"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRef(context.Background(), tc.ref)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateRef(%q) = %v, want accepted", tc.ref, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateRef(%q) = nil, want refused (%s)", tc.ref, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateRef(%q) = %q, want an error mentioning %q", tc.ref, err, tc.wantErr)
			}
			// The class is safe to return; the address it resolved to is
			// not -- that would make a 400 an internal-DNS oracle.
			if strings.Contains(err.Error(), "169.254.169.254") && !strings.Contains(tc.ref, "169.254.169.254") {
				t.Fatalf("error leaks a resolved address: %q", err)
			}
		})
	}
}

// The two consumers of a ref in this package disagree about which
// token is the registry host -- Resolve qualifies first and sees
// docker.io, Fetch hands the ref to `oras pull` raw and oras reads the
// first segment. Validating only one of them leaves the other open: a
// single-label host like "vault" is docker.io to the first and, inside
// a pod whose resolver appends search domains, an in-cluster Service to
// the second.
//
// Asserted on refHosts directly rather than through ValidateRef,
// because whether "vault" resolves to anything at all depends on being
// inside a cluster -- which is exactly the environment a unit test
// isn't, and exactly the environment the attack needs.
func TestRefHosts_CoversWhatEitherConsumerWouldFetchFrom(t *testing.T) {
	for ref, want := range map[string][]string{
		"vault/sboms/app:1.0":             {"docker.io", "vault"},
		"bitnami/redis:7.2.5":             {"docker.io", "bitnami"},
		"alpine:3.19":                     {"docker.io"},
		"ghcr.io/org/app:1.0":             {"ghcr.io"},
		"scm-registry:5000/sboms/app:1.0": {"scm-registry"},
		"[::1]:5000/app:1.0":              {"::1"},
		"GHCR.IO/Org/App:1.0":             {"ghcr.io"},
	} {
		if got := refHosts(ref); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("refHosts(%q) = %v, want %v", ref, got, want)
		}
	}
}

// The in-cluster registry this chart ships trips two rules at once (a
// cluster-DNS name AND a ClusterIP in RFC1918 space), so the allowlist
// isn't a nicety here -- without it a default install can't fetch a
// single sbom/file/sarif artifact. See RefHostAllowlistEnv.
func TestValidateRef_Allowlist(t *testing.T) {
	const clusterRef = "scm-registry.supply-chain-monitor.svc.cluster.local:5000/sboms/app:1.0"

	if err := ValidateRef(context.Background(), clusterRef); err == nil {
		t.Fatal("the in-cluster registry ref should be refused with no allowlist set -- otherwise this test proves nothing")
	}

	// Entries are matched on host: with a port, without a port, and
	// with surrounding whitespace all mean the same host.
	t.Setenv(RefHostAllowlistEnv, " scm-registry.supply-chain-monitor.svc.cluster.local:5000 ,scm-registry")
	if err := ValidateRef(context.Background(), clusterRef); err != nil {
		t.Fatalf("allowlisted cluster registry = %v, want accepted", err)
	}
	if err := ValidateRef(context.Background(), "scm-registry:5000/sboms/app:1.0"); err != nil {
		t.Fatalf("allowlisted short-form registry = %v, want accepted", err)
	}
	// An allowlist is not an off switch: anything not on it is still
	// refused.
	if err := ValidateRef(context.Background(), "169.254.169.254/latest/meta-data:1"); err == nil {
		t.Fatal("the metadata IP must stay refused while an unrelated host is allowlisted")
	}
}

// An operator who really does run a registry on a private address can
// say so -- including for an IP literal, which never goes near DNS.
func TestValidateRef_AllowlistPermitsPrivateAddress(t *testing.T) {
	t.Setenv(RefHostAllowlistEnv, "10.0.0.5")
	if err := ValidateRef(context.Background(), "10.0.0.5:5000/app:1.0"); err != nil {
		t.Fatalf("allowlisted private registry = %v, want accepted", err)
	}
}

// A ref whose host doesn't resolve is allowed through on purpose (see
// ValidateRef): there is no address to reach, and registering an
// artifact whose registry is unreachable from this pod is routine
// behaviour this service already supports -- several existing handler
// tests depend on it.
func TestValidateRef_UnresolvableHostIsAllowed(t *testing.T) {
	if err := ValidateRef(context.Background(), "unreachable-registry.invalid/app:1.0"); err != nil {
		t.Fatalf("unresolvable host = %v, want accepted (fail open -- nothing to reach)", err)
	}
}

// Fetch and Resolve validate their own input rather than trusting the
// API layer to have done it -- they are what actually makes the
// outbound request, and the scan-worker Job reaches them without ever
// passing through a handler.
func TestFetchAndResolve_ValidateRefThemselves(t *testing.T) {
	const metadataRef = "169.254.169.254/latest/meta-data:1"

	_, cleanup, err := NewRegistryFetcher(true, "", "").Fetch(context.Background(), metadataRef)
	cleanup()
	if err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("Fetch(%q) = %v, want it refused before oras ever ran", metadataRef, err)
	}

	digest, err := NewOrasDigestResolver().Resolve(context.Background(), metadataRef, false)
	if err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("Resolve(%q) = (%q, %v), want it refused before oras ever ran", metadataRef, digest, err)
	}
}
