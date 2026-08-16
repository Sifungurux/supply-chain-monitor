package scanner

import (
	"context"
	"os"
	"path/filepath"
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

	digest, err := NewOrasDigestResolver("", "").Resolve(context.Background(), metadataRef, false)
	if err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("Resolve(%q) = (%q, %v), want it refused before oras ever ran", metadataRef, digest, err)
	}
}

// The scan-worker Job runs these in its own process, reached through
// main.go's runScanWorker rather than through any HTTP handler -- so
// the API's scan-time check never executes for them and they have to
// refuse a bad ref themselves. Asserted for the exact entry point each
// one is actually called through, which is not always Scan:
// TrivyScanner is reached via ScanWithRaw in image mode, and both it
// and Scan funnel into ScanRaw, so ScanRaw is what must hold the line.
func TestImageScannersRefuseRefsPointingInward(t *testing.T) {
	const metadataRef = "169.254.169.254/latest/meta-data:1"
	ctx := context.Background()

	t.Run("trivy ScanRaw", func(t *testing.T) {
		_, err := NewTrivyScanner("", TrivyDBConfig{}).ScanRaw(ctx, metadataRef)
		requireLinkLocalRefusal(t, err)
	})
	// The path the scan-worker actually uses for image mode. Separate
	// case on purpose: validating in Scan alone would leave this one
	// open, since it does not call Scan.
	t.Run("trivy ScanWithRaw (the worker's entry point)", func(t *testing.T) {
		_, _, err := NewTrivyScanner("", TrivyDBConfig{}).ScanWithRaw(ctx, metadataRef)
		requireLinkLocalRefusal(t, err)
	})
	t.Run("trivy Scan", func(t *testing.T) {
		_, err := NewTrivyScanner("", TrivyDBConfig{}).Scan(ctx, metadataRef)
		requireLinkLocalRefusal(t, err)
	})
	t.Run("grype ScanRaw", func(t *testing.T) {
		_, err := NewGrypeScanner(GrypeDBConfig{}, false, "").ScanRaw(ctx, metadataRef)
		requireLinkLocalRefusal(t, err)
	})
	t.Run("unpacker Scan", func(t *testing.T) {
		_, err := NewUnpackerScanner("127.0.0.1:1", "unpacker", true, true, 1024, "").Scan(ctx, metadataRef)
		requireLinkLocalRefusal(t, err)
	})
	t.Run("pluggable Scan", func(t *testing.T) {
		s := NewPluggableScanner(PluggableScannerConfig{
			Name: "probe", Command: "/bin/false", ArtifactTypes: []string{"image"},
		})
		_, err := s.Scan(ctx, metadataRef)
		requireLinkLocalRefusal(t, err)
	})
}

// requireLinkLocalRefusal insists the error is the ref check firing,
// not the tool being absent or a connection failing. Without this the
// tests above would pass on any machine with no trivy binary installed
// -- proving nothing at all.
func requireLinkLocalRefusal(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected the ref to be refused, got nil")
	}
	if !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("refused for the wrong reason: %v -- want the ValidateRef link-local refusal, not a missing binary or a failed connection", err)
	}
}

// Every isolated scanner whose worker runs "monitor-api scan-worker"
// must forward REF_HOST_ALLOWLIST into that Job.
//
// The worker calls the same RegistryFetcher -> ValidateRef this process
// does, reading the same variable, so without it the Job refuses the
// in-cluster registry it exists to pull from -- before any pull is
// attempted.
//
// Asserted over the SOURCE rather than by building each scanner,
// because the bug this catches is a NEW scanner being added that
// forgets the line. Two of the three had it; the unpacker one did not,
// so malware scanning of any scm-registry image failed while CVE
// scanning of the same image succeeded -- which looked like a partial
// success rather than a missing variable.
func TestIsolatedScanners_ForwardRefHostAllowlist(t *testing.T) {
	files, err := filepath.Glob("isolated_*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no isolated_*.go files found -- this test would pass vacuously")
	}

	var checked int
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		text := string(src)
		// Only scanners that run the in-process worker validate refs.
		// malcontent runs its own binary directly and never calls
		// ValidateRef, so it has nothing to forward.
		if !strings.Contains(text, `"scan-worker"`) {
			continue
		}
		checked++
		if !strings.Contains(text, "RefHostAllowlistEnv") {
			t.Errorf("%s builds a scan-worker Job but never forwards %s -- that Job will refuse the in-cluster registry it exists to pull from", f, RefHostAllowlistEnv)
		}
	}
	if checked == 0 {
		t.Fatal("no scan-worker-based scanners were checked -- the test is not looking at anything")
	}
	t.Logf("checked %d scan-worker-based isolated scanners", checked)
}

// ARGUMENT INJECTION. Every scanner passes the ref to an external tool
// as a POSITIONAL argument, so a ref beginning with "-" is parsed as a
// flag by that tool -- "--cache-dir" reaching trivy redirects where it
// writes inside the scan worker.
//
// Measured before the guard existed: "-o", "--cache-dir", "-o.x/foo"
// and "--output=/tmp/x" ALL returned nil from ValidateRef. The host
// checks cannot catch it -- refHosts reads "-o" as a hostless
// single-segment ref and Docker Hub qualification gives it a
// legitimate-looking host.
func TestValidateRef_RejectsFlagShapedRefs(t *testing.T) {
	cases := []struct {
		name   string
		ref    string
		reject bool
	}{
		{name: "short flag", ref: "-o", reject: true},
		{name: "long flag", ref: "--cache-dir", reject: true},
		{name: "flag that also looks like a ref", ref: "-o.x/foo", reject: true},
		{name: "flag with inline value", ref: "--output=/tmp/x", reject: true},
		{name: "single dash alone", ref: "-", reject: true},
		// A dash INSIDE the ref is entirely legitimate and must not be
		// caught -- plenty of real images have one.
		{name: "dash inside the repo name", ref: "docker.io/library/my-app:1.0", reject: false},
		{name: "dash inside the host", ref: "my-registry.example.com/app:1", reject: false},
		{name: "ordinary ref", ref: "alpine:3.19", reject: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRef(context.Background(), tc.ref)
			if tc.reject && err == nil {
				t.Errorf("ValidateRef(%q) = nil, want rejection -- this ref becomes a FLAG when handed to trivy/oras", tc.ref)
			}
			if !tc.reject && err != nil {
				t.Errorf("ValidateRef(%q) = %v, want nil -- a dash inside a ref is legitimate", tc.ref, err)
			}
		})
	}
}
