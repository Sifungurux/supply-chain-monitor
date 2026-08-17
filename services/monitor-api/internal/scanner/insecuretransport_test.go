package scanner

import "testing"

// TestInsecureTransportAllowed is report S4 leg 3 at the level the
// decision is actually made.
//
// UNPACKER_INSECURE / FETCH_PLAIN_HTTP /
// GRYPE_REGISTRY_INSECURE_USE_HTTP exist for one reason: scm-registry
// serves plain HTTP inside a dev cluster. Each was applied to EVERY
// pull the process made, so switching on "my in-cluster registry has no
// TLS" also turned off transport security for docker.io, ghcr.io and
// everything else -- silently, with nothing in the output saying so.
func TestInsecureTransportAllowed(t *testing.T) {
	const addr = "scm-registry.supply-chain-monitor.svc.cluster.local:5000"

	cases := []struct {
		name      string
		ref       string
		addr      string
		allowlist string
		want      bool
	}{
		// The hosts this exists for.
		{name: "the configured registry, with its port", ref: addr + "/app:v1", addr: addr, want: true},
		{name: "the configured registry, ref without a port", ref: "scm-registry.supply-chain-monitor.svc.cluster.local/app:v1", addr: addr, want: true},
		{name: "a host an operator listed in REF_HOST_ALLOWLIST", ref: "registry.internal.example:5000/app:v1", allowlist: "registry.internal.example", want: true},

		// Everything else keeps TLS regardless of how the switch is set.
		{name: "docker.io", ref: "docker.io/library/alpine:3.19", addr: addr, want: false},
		{name: "a bare ref, which means docker hub", ref: "alpine:3.19", addr: addr, want: false},
		{name: "ghcr.io", ref: "ghcr.io/aquasecurity/trivy-db:2", addr: addr, want: false},
		{name: "public.ecr.aws", ref: "public.ecr.aws/docker/library/mongo:7", addr: addr, want: false},

		// A host that merely CONTAINS the registry name is a different
		// host. Matching on substring here would hand plain HTTP to
		// anyone who can register a suffixed domain.
		//
		// Note the suffixed case is written WITHOUT a port. With one
		// ("...local:5000.evil.test") hostOf reads the trusted host back
		// out, because net.SplitHostPort splits on the last colon
		// without checking the port is numeric. That is not a bypass:
		// the resulting authority has a non-numeric port and cannot be
		// dialled at all, so there is no connection to downgrade. The
		// form that IS dialable is this one, and it is rejected.
		{name: "a suffixed lookalike", ref: "scm-registry.supply-chain-monitor.svc.cluster.local.evil.test/app:v1", addr: addr, want: false},
		{name: "a prefixed lookalike", ref: "evil-scm-registry.supply-chain-monitor.svc.cluster.local/app:v1", addr: addr, want: false},

		// With nothing configured there is no host to trust, so the
		// switch does nothing at all rather than applying everywhere --
		// which is the pre-change behaviour, inverted.
		{name: "no REGISTRY_ADDR and no allowlist", ref: "anything.example/app:v1", want: false},
		{name: "empty REGISTRY_ADDR does not match an empty host", ref: "/app:v1", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(RegistryAddrEnv, tc.addr)
			t.Setenv(RefHostAllowlistEnv, tc.allowlist)
			if got := InsecureTransportAllowed(tc.ref); got != tc.want {
				t.Fatalf("InsecureTransportAllowed(%q) = %v, want %v (REGISTRY_ADDR=%q REF_HOST_ALLOWLIST=%q)",
					tc.ref, got, tc.want, tc.addr, tc.allowlist)
			}
		})
	}
}

// A ref this package cannot read as a registry reference has no host to
// reason about, so there is nothing to downgrade. Refusing is the safe
// reading either way.
func TestInsecureTransportAllowed_NonRegistryRefs(t *testing.T) {
	t.Setenv(RegistryAddrEnv, "scm-registry:5000")
	for _, ref := range []string{"", "/mnt/artifacts/thing.tar", "./relative/path"} {
		if InsecureTransportAllowed(ref) {
			t.Errorf("InsecureTransportAllowed(%q) = true; a non-registry ref has no host to trust", ref)
		}
	}
}
