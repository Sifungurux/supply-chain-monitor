package scanner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func baseCfg() SigstoreConfig {
	return SigstoreConfig{
		CertIdentityRegexp: "^https://github.com/acme/.*$",
		CertOIDCIssuer:     "https://token.actions.githubusercontent.com",
	}
}

// writeFakeCosign puts a stub `cosign` on PATH that records its argv and
// replays a canned exit status/output -- the same shape unpacker_test.go
// uses for its stub.
func writeFakeCosign(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "cosign")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatalf("write fake cosign: %v", err)
	}
	return path
}

func TestNewSigstoreScanner_RefusesMeaninglessConfig(t *testing.T) {
	// Without an identity and issuer, `cosign verify` checks only that
	// SOMEBODY signed the image and it chains to the trust root --
	// which anybody can arrange for any image. Reporting that as a pass
	// would be worse than not verifying at all, because it looks like
	// verification.
	for _, tc := range []struct {
		name string
		cfg  SigstoreConfig
	}{
		{"nothing configured", SigstoreConfig{}},
		{"issuer without identity", SigstoreConfig{CertOIDCIssuer: "https://issuer.example"}},
		{"identity without issuer", SigstoreConfig{CertIdentityRegexp: ".*"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if s := NewSigstoreScanner(tc.cfg); s != nil {
				t.Fatal("scanner was built from a config that cannot verify anything meaningful")
			}
		})
	}
	if NewSigstoreScanner(baseCfg()) == nil {
		t.Fatal("a fully configured scanner was refused")
	}
}

func TestSigstoreScanner_Args(t *testing.T) {
	t.Run("public sigstore passes no trust flags", func(t *testing.T) {
		s := NewSigstoreScanner(baseCfg())
		got := s.verifyArgs("alpine:3.19")
		want := []string{
			"verify",
			"--certificate-identity-regexp", "^https://github.com/acme/.*$",
			"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
			"--", "alpine:3.19",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("args = %#v, want %#v", got, want)
		}
	})

	// The on-prem path. cosign v3 has no --rekor-url/--fulcio-url on
	// verify at all, so this flag is how a private Sigstore is
	// expressed -- and getting it wrong means silently verifying
	// against the PUBLIC root while reporting a pass.
	t.Run("a trusted root is passed for a private sigstore", func(t *testing.T) {
		cfg := baseCfg()
		cfg.TrustedRootPath = "/etc/sigstore/trusted_root.json"
		got := strings.Join(NewSigstoreScanner(cfg).verifyArgs("alpine:3.19"), " ")
		if !strings.Contains(got, "--trusted-root /etc/sigstore/trusted_root.json") {
			t.Fatalf("args = %q, want a --trusted-root flag", got)
		}
	})

	t.Run("attestation verification asks for slsaprovenance", func(t *testing.T) {
		got := strings.Join(NewSigstoreScanner(baseCfg()).verifyAttestationArgs("alpine:3.19"), " ")
		if !strings.HasPrefix(got, "verify-attestation --type slsaprovenance ") {
			t.Fatalf("args = %q", got)
		}
	})
}

// THE distinction this scanner exists to make: cosign exits non-zero
// both when an image is genuinely unsigned and when verification could
// not be completed. Conflating them turns a registry outage into a
// false accusation that looks exactly like a true one.
func TestClassifyCosignResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		output string
		want   cosignResult
	}{
		{"success", nil, "Verified OK", cosignOK},
		{"no signatures", errFake, "Error: no signatures found for image", cosignNotSigned},
		{"no matching signatures", errFake, "Error: no matching signatures:\n", cosignNotSigned},
		{"no attestations", errFake, "Error: no matching attestations:", cosignNotSigned},
		{"registry unreachable", errFake, "Error: GET https://registry.example/v2/: dial tcp: i/o timeout", cosignError},
		{"trust root unusable", errFake, "Error: failed to load trusted root: no such file or directory", cosignError},
		// An unrecognised failure must fall to "could not verify", never
		// to "unsigned" -- accusing an image is the costlier mistake.
		{"unknown failure", errFake, "Error: something nobody has seen before", cosignError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyCosignResult(tc.err, tc.output); got != tc.want {
				t.Fatalf("classify(%q) = %v, want %v", tc.output, got, tc.want)
			}
		})
	}
}

var errFake = &fakeExitError{}

type fakeExitError struct{}

func (e *fakeExitError) Error() string { return "exit status 1" }

func TestSigstoreScanner_Scan(t *testing.T) {
	t.Setenv(RefHostAllowlistEnv, "registry.internal.example")
	const ref = "registry.internal.example/app:v1"

	t.Run("a verified image produces no findings", func(t *testing.T) {
		s := NewSigstoreScanner(baseCfg())
		s.bin = writeFakeCosign(t, `echo "Verified OK"; exit 0`)
		got, err := s.Scan(context.Background(), ref)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("findings = %+v, want none -- a signed image is the expected state", got)
		}
	})

	// Unsigned is a FINDING, not an error. An error would block
	// fix-detection for the whole bucket and read as a broken scanner;
	// the first unsigned image in a fleet would switch provenance
	// checking off for everything.
	t.Run("an unsigned image is a high-severity finding, not an error", func(t *testing.T) {
		s := NewSigstoreScanner(baseCfg())
		s.bin = writeFakeCosign(t, `echo "Error: no signatures found for image"; exit 1`)
		got, err := s.Scan(context.Background(), ref)
		if err != nil {
			t.Fatalf("Scan returned an error for an unsigned image: %v", err)
		}
		if len(got) != 1 || got[0].ID != findingUnsigned {
			t.Fatalf("findings = %+v, want one %q", got, findingUnsigned)
		}
		if got[0].Severity != "high" {
			t.Errorf("severity = %q, want high", got[0].Severity)
		}
		if got[0].Source != ProvenanceFindingSource {
			t.Errorf("source = %q, want %q", got[0].Source, ProvenanceFindingSource)
		}
		// The title must say WHICH Sigstore judged it, or "unsigned" is
		// ambiguous between "not signed by us" and "not signed by
		// anyone the public instance knows".
		if !strings.Contains(got[0].Title, "public Sigstore") {
			t.Errorf("title = %q, want it to name the trust root", got[0].Title)
		}
	})

	t.Run("a private sigstore is named in the finding", func(t *testing.T) {
		cfg := baseCfg()
		cfg.TrustedRootPath = "/etc/sigstore/trusted_root.json"
		s := NewSigstoreScanner(cfg)
		s.bin = writeFakeCosign(t, `echo "Error: no signatures found for image"; exit 1`)
		got, _ := s.Scan(context.Background(), ref)
		if len(got) != 1 || !strings.Contains(got[0].Title, "private Sigstore") {
			t.Fatalf("findings = %+v, want the private trust root named", got)
		}
	})

	// "Could not verify" must not be reported as "unsigned".
	t.Run("an unreachable registry is reported as not-verified, not unsigned", func(t *testing.T) {
		s := NewSigstoreScanner(baseCfg())
		s.bin = writeFakeCosign(t, `echo "Error: GET https://registry/v2/: dial tcp: i/o timeout"; exit 1`)
		got, err := s.Scan(context.Background(), ref)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if len(got) != 1 || got[0].ID != findingVerifyFailed {
			t.Fatalf("findings = %+v, want %q -- an outage must not accuse the image", got, findingVerifyFailed)
		}
		if got[0].Severity == "high" {
			t.Error("a failure to verify is reported at the same severity as a genuinely unsigned image")
		}
	})

	t.Run("attestation is only checked when required", func(t *testing.T) {
		// The stub fails everything; with RequireAttestation off, only
		// the signature check should have run.
		countFile := filepath.Join(t.TempDir(), "calls")
		script := `echo "$@" >> ` + countFile + `; echo "Error: no signatures found"; exit 1`

		s := NewSigstoreScanner(baseCfg())
		s.bin = writeFakeCosign(t, script)
		if _, err := s.Scan(context.Background(), ref); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		data, _ := os.ReadFile(countFile)
		if strings.Contains(string(data), "verify-attestation") {
			t.Error("attestation was verified without RequireAttestation")
		}
	})

	t.Run("a missing attestation is its own finding", func(t *testing.T) {
		cfg := baseCfg()
		cfg.RequireAttestation = true
		s := NewSigstoreScanner(cfg)
		// Signature verifies; attestation does not.
		s.bin = writeFakeCosign(t, `
case "$1" in
  verify-attestation) echo "Error: no matching attestations:"; exit 1 ;;
  *) echo "Verified OK"; exit 0 ;;
esac`)
		got, err := s.Scan(context.Background(), ref)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if len(got) != 1 || got[0].ID != findingNoAttestation {
			t.Fatalf("findings = %+v, want one %q", got, findingNoAttestation)
		}
	})

	// A signature that could not be verified makes the attestation
	// check meaningless -- it fails for the same reason and would
	// report the same thing twice.
	t.Run("a failed signature check skips the attestation check", func(t *testing.T) {
		cfg := baseCfg()
		cfg.RequireAttestation = true
		s := NewSigstoreScanner(cfg)
		s.bin = writeFakeCosign(t, `echo "Error: dial tcp: i/o timeout"; exit 1`)
		got, _ := s.Scan(context.Background(), ref)
		if len(got) != 1 {
			t.Fatalf("findings = %+v, want exactly one -- the same outage reported twice is noise", got)
		}
	})

	t.Run("an invalid ref is refused before cosign runs", func(t *testing.T) {
		s := NewSigstoreScanner(baseCfg())
		s.bin = writeFakeCosign(t, `echo "should not run"; exit 0`)
		if _, err := s.Scan(context.Background(), "-oh-no"); err == nil {
			t.Fatal("a ref that would be parsed as a flag was accepted")
		}
	})
}

func TestSigstoreScanner_BucketAndKind(t *testing.T) {
	s := NewSigstoreScanner(baseCfg())
	if got := s.Bucket(); got != "other" {
		t.Errorf("Bucket() = %q, want %q", got, "other")
	}
	if got := s.Kind(); got != "cosign" {
		t.Errorf("Kind() = %q, want %q", got, "cosign")
	}
}

// TestSigstoreScanner_AlwaysSetsTUFRoot guards a bug that every stubbed
// test missed and only the real binary revealed.
//
// cosign needs a writable TUF cache for EVERY verification, public
// Sigstore included -- it defaults to $HOME/.sigstore and creates it on
// first use. monitor-api runs with a read-only root filesystem, so
// without TUF_ROOT pointed somewhere writable, every verification fails
// with "mkdir /.sigstore: permission denied" and the whole feature is
// inert while still looking configured.
//
// Asserted for the PUBLIC path specifically: the private-mirror case is
// the one that obviously needs a cache, and scoping the variable to it
// is exactly the mistake this exists to catch.
func TestSigstoreScanner_AlwaysSetsTUFRoot(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  SigstoreConfig
	}{
		{"public sigstore", baseCfg()},
		{"private trusted root", func() SigstoreConfig { c := baseCfg(); c.TrustedRootPath = "/etc/sigstore/trusted_root.json"; return c }()},
		{"private tuf mirror", func() SigstoreConfig { c := baseCfg(); c.TUFMirror = "https://tuf.internal"; return c }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var found string
			for _, kv := range NewSigstoreScanner(tc.cfg).env() {
				if strings.HasPrefix(kv, "TUF_ROOT=") {
					found = kv
				}
			}
			if found == "" {
				t.Fatal("TUF_ROOT is unset -- cosign will try to create $HOME/.sigstore on a read-only filesystem and every verification will fail")
			}
			if !strings.HasPrefix(found, "TUF_ROOT=/tmp/") {
				t.Errorf("%s points outside the writable scratch volume", found)
			}
		})
	}
}
