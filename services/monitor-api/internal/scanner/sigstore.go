package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// SigstoreConfig configures signature and provenance verification
// (report H2).
//
// PUBLIC SIGSTORE OR YOUR OWN. The zero value verifies against the
// public Sigstore instance -- the default trust root cosign ships. A
// deployment running its own Sigstore (Fulcio/Rekor/TUF) points this at
// that instead, which is the difference between "this image was signed
// by somebody Sigstore trusts" and "this image was signed by us".
type SigstoreConfig struct {
	// CertIdentityRegexp and CertOIDCIssuer are what a keyless
	// signature is checked AGAINST. Without them cosign verifies that a
	// signature exists and chains to the trust root -- which anybody
	// can produce for any image, so it answers almost nothing.
	//
	// Required: NewSigstoreScanner refuses to build without them rather
	// than verifying something meaningless and reporting it as a pass.
	CertIdentityRegexp string
	CertOIDCIssuer     string

	// RequireAttestation additionally demands a SLSA provenance
	// attestation, not just a signature. A signature says "somebody
	// signed this"; provenance says "and here is how it was built".
	RequireAttestation bool

	// AttestationType is the in-toto predicate type the attestation must
	// carry. Empty means DefaultAttestationType.
	//
	// This is a real setting, not a knob for its own sake: cosign's
	// "slsaprovenance" shorthand means SLSA **v0.2**, while
	// actions/attest-build-provenance emits
	// "https://slsa.dev/provenance/v1". Verified against the real
	// binary and a real attested image -- v0.2 fails with "none of the
	// attestations matched the predicate type: slsaprovenance, found:
	// https://slsa.dev/provenance/v1", which this scanner would then
	// report as a MISSING attestation on an image that has a perfectly
	// good one.
	AttestationType string

	// RefPrefixes bounds WHICH artifacts get verified at all: a ref is
	// checked only if it literally starts with one of these. Empty
	// verifies everything, which is the only safe default for a setting
	// whose whole effect is to check less.
	//
	// Why this exists. Unsigned is a high-severity finding (see
	// SigstoreScanner), and that is right for images you build. Most
	// fleets are mostly images somebody ELSE built -- nginx, postgres,
	// the 93 upstream images this project's own deployment tracks, none
	// of which carry a signature from your identity and none of which
	// ever will. Verifying those produces a true, useless, high-severity
	// finding per artifact, which buries the one case the check exists
	// for. So: name your own registry path, and everything else is
	// reported as ProvenanceUnknown -- not checked, rather than accused.
	//
	// A literal prefix, deliberately not a glob or regexp: the failure
	// mode of a too-NARROW pattern is silence, and a pattern language
	// makes that easy to write by accident. Include the trailing "/" --
	// "ghcr.io/acme" also matches "ghcr.io/acmecorp-evil/...".
	RefPrefixes []string

	// TrustedRootPath points cosign at a Sigstore TrustedRoot JSON
	// describing a PRIVATE Sigstore deployment's Fulcio/Rekor/CT keys.
	// Empty uses the public instance.
	//
	// This is cosign v3's mechanism. v2's --fulcio-url/--rekor-url
	// flags are gone from `verify` entirely -- checked against the real
	// v3.1.3 binary, not assumed -- so a config that named those URLs
	// would be silently ignored, which is the worst possible outcome
	// for a trust setting: verification would quietly fall back to the
	// PUBLIC root and still report a pass.
	TrustedRootPath string

	// TUFMirror and TUFRootPath are the other way to reach a private
	// Sigstore: initialise cosign's TUF client against your own mirror
	// once at startup, then verify normally. Kept alongside
	// TrustedRootPath because they suit different deployments -- a TUF
	// mirror is the endpoint-shaped answer for an org already running
	// one, while a TrustedRoot file needs no network and no writable
	// TUF cache, which matters under a read-only root filesystem.
	TUFMirror   string
	TUFRootPath string

	// DockerConfigDir authenticates registry reads, the same mechanism
	// GrypeScanner uses (see main.go's writeDockerConfig).
	DockerConfigDir string
}

// DefaultAttestationType is what actions/attest-build-provenance
// produces, which is what GitHub-built images actually carry. cosign's
// own "slsaprovenance" shorthand is SLSA v0.2 and matches none of them.
const DefaultAttestationType = "slsaprovenance1"

// InScope reports whether ref is one this deployment verifies at all.
// See SigstoreConfig.RefPrefixes.
func (c SigstoreConfig) InScope(ref string) bool {
	if len(c.RefPrefixes) == 0 {
		return true
	}
	for _, p := range c.RefPrefixes {
		if p != "" && strings.HasPrefix(ref, p) {
			return true
		}
	}
	return false
}

// Configured reports whether verification can run at all.
func (c SigstoreConfig) Configured() bool {
	return c.CertIdentityRegexp != "" && c.CertOIDCIssuer != ""
}

// PrivateSigstore reports whether this points at something other than
// the public instance.
func (c SigstoreConfig) PrivateSigstore() bool {
	return c.TrustedRootPath != "" || c.TUFMirror != ""
}

// SigstoreScanner verifies an image's signature and, optionally, its
// SLSA provenance attestation.
//
// UNSIGNED IS A FINDING, NOT A SCAN ERROR. That distinction is the
// whole design. A scan error blocks fix-detection for the bucket (see
// scanArtifact's blockedBuckets) and reads as "the scanner is broken";
// an unsigned image is not a broken scanner, it is the answer. Treating
// it as an error would also mean the first unsigned image in a fleet
// turns provenance checking off for everything.
type SigstoreScanner struct {
	cfg SigstoreConfig
	bin string
}

// NewSigstoreScanner returns nil when the config cannot verify anything
// meaningful, so main.go can register it only when it is real.
func NewSigstoreScanner(cfg SigstoreConfig) *SigstoreScanner {
	if !cfg.Configured() {
		return nil
	}
	return &SigstoreScanner{cfg: cfg, bin: "cosign"}
}

// Bucket implements BucketAffinity.
//
// "other", not a new bucket. Finding.Category today is
// cve/malware/misconfiguration/secret/other, and adding a sixth means
// touching the model, MergeFindings, the API's validFindingsBucket, the
// policy vocabulary, both dashboard copies and every renderer -- a
// bigger and riskier change than the verification itself. Source
// "cosign" is what tells provenance findings apart within the bucket,
// the same way license findings are told apart there today.
func (s *SigstoreScanner) Bucket() string { return "other" }

// Kind implements ScanKind so cosign can be capped independently.
func (s *SigstoreScanner) Kind() string { return "cosign" }

const (
	// ProvenanceFindingSource marks every finding this scanner produces.
	ProvenanceFindingSource = "cosign"
	// findingUnsigned and friends are stable ids -- MergeFindings
	// matches on them, so an image that stays unsigned across scans is
	// ONE finding with a first_seen_at, not a new one every scan.
	findingUnsigned      = "provenance:unsigned"
	findingNoAttestation = "provenance:no-slsa-provenance"
	findingVerifyFailed  = "provenance:verification-error"
)

// Scan implements the base Scanner interface. ScanProvenance is the
// richer form scanArtifact actually uses -- this exists so anything
// that only knows about Scanner still works.
func (s *SigstoreScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	findings, _, _, err := s.ScanProvenance(ctx, ref)
	return findings, err
}

// ScanProvenance verifies ref and reports both the findings and the
// verdict. Implements ProvenanceScanner.
func (s *SigstoreScanner) ScanProvenance(ctx context.Context, ref string) ([]artifact.Finding, string, string, error) {
	// Out of scope: not verified, and deliberately NOT a finding. The
	// verdict stays ProvenanceUnknown -- "nobody checked" -- which is
	// exactly what happened.
	//
	// Logged, because that verdict is otherwise indistinguishable from
	// cosign being switched off entirely, and a mistyped prefix that
	// matches nothing looks identical to success.
	//
	// Ahead of ValidateRef on purpose: a ref this deployment does not
	// verify needs no DNS lookup to reject, and nothing outbound
	// happens on this path at all.
	if !s.cfg.InScope(ref) {
		slog.Info("provenance verification skipped: ref is outside cosign.refPrefixes",
			"ref", ref, "prefixes", strings.Join(s.cfg.RefPrefixes, ","))
		return nil, artifact.ProvenanceUnknown, s.trustDescription(), nil
	}

	// Same guard every other scanner applies before handing a ref to a
	// tool that will make an outbound request from it.
	if err := ValidateRef(ctx, ref); err != nil {
		return nil, artifact.ProvenanceUnknown, s.trustDescription(), err
	}

	findings := []artifact.Finding{}
	status := artifact.ProvenanceUnknown

	sigOut, sigErr := s.run(ctx, s.verifyArgs(ref))
	switch classifyCosignResult(sigErr, sigOut) {
	case cosignOK:
		// Verified. No finding -- a signed image is the expected state,
		// and a finding per signed image would bury the unsigned ones.
		// The VERDICT is recorded instead, so "signed" is still
		// visible; see ProvenanceScanner.
		status = artifact.ProvenanceVerified
	case cosignNotSigned:
		status = artifact.ProvenanceUnsigned
		findings = append(findings, artifact.Finding{
			ID:       findingUnsigned,
			Severity: "high",
			Title:    "no valid signature from " + s.cfg.CertIdentityRegexp + " (" + s.trustDescription() + ")",
			Source:   ProvenanceFindingSource,
		})
	default:
		// Verification could not be COMPLETED -- registry unreachable,
		// trust root unusable, cosign itself failing. Reported as a
		// finding rather than an error for the same reason as above,
		// but at a lower severity and saying plainly that this is "we
		// do not know", not "this is unsigned".
		status = artifact.ProvenanceUnverified
		findings = append(findings, artifact.Finding{
			ID:       findingVerifyFailed,
			Severity: "medium",
			Title:    "signature verification could not be completed: " + firstLine(sigOut, sigErr),
			Source:   ProvenanceFindingSource,
		})
		// A failure to verify the signature makes the attestation check
		// meaningless -- it would fail for the same reason and report
		// the same thing twice.
		return findings, status, s.trustDescription(), nil
	}

	if !s.cfg.RequireAttestation {
		return findings, status, s.trustDescription(), nil
	}

	attOut, attErr := s.run(ctx, s.verifyAttestationArgs(ref))
	switch classifyCosignResult(attErr, attOut) {
	case cosignOK:
	case cosignNotSigned:
		// The signature verified but the required attestation is
		// missing, so this artifact does not meet the bar this
		// deployment set -- reporting it as "verified" would be
		// answering a question nobody asked.
		status = artifact.ProvenanceUnsigned
		findings = append(findings, artifact.Finding{
			ID:       findingNoAttestation,
			Severity: "medium",
			Title:    "no SLSA provenance attestation from " + s.cfg.CertIdentityRegexp + " (" + s.trustDescription() + ")",
			Source:   ProvenanceFindingSource,
		})
	default:
		status = artifact.ProvenanceUnverified
		findings = append(findings, artifact.Finding{
			ID:       findingVerifyFailed,
			Severity: "medium",
			Title:    "attestation verification could not be completed: " + firstLine(attOut, attErr),
			Source:   ProvenanceFindingSource,
		})
	}
	return findings, status, s.trustDescription(), nil
}

// verifyArgs builds `cosign verify`.
func (s *SigstoreScanner) verifyArgs(ref string) []string {
	args := []string{"verify"}
	args = append(args, s.identityArgs()...)
	args = append(args, s.trustArgs()...)
	// "--" ends flag parsing, so a ref that somehow reached here
	// without passing ValidateRef is a positional argument rather than
	// a flag. Same belt-and-braces the other scanners apply.
	return append(args, "--", ref)
}

func (s *SigstoreScanner) verifyAttestationArgs(ref string) []string {
	t := s.cfg.AttestationType
	if t == "" {
		t = DefaultAttestationType
	}
	args := []string{"verify-attestation", "--type", t}
	args = append(args, s.identityArgs()...)
	args = append(args, s.trustArgs()...)
	return append(args, "--", ref)
}

func (s *SigstoreScanner) identityArgs() []string {
	return []string{
		"--certificate-identity-regexp", s.cfg.CertIdentityRegexp,
		"--certificate-oidc-issuer", s.cfg.CertOIDCIssuer,
	}
}

// trustArgs points cosign at a private Sigstore when one is configured.
//
// Only --trusted-root is a verify-time flag; the TUF mirror is applied
// once by Initialize below, because `cosign initialize` populates a
// cache rather than taking effect per invocation.
func (s *SigstoreScanner) trustArgs() []string {
	if s.cfg.TrustedRootPath != "" {
		return []string{"--trusted-root", s.cfg.TrustedRootPath}
	}
	return nil
}

// trustDescription names which Sigstore a finding was judged against,
// so "unsigned" is never ambiguous between "not signed by us" and "not
// signed by anyone the public instance knows".
func (s *SigstoreScanner) trustDescription() string {
	switch {
	case s.cfg.TrustedRootPath != "":
		return "private Sigstore, trusted root " + s.cfg.TrustedRootPath
	case s.cfg.TUFMirror != "":
		return "private Sigstore, TUF mirror " + s.cfg.TUFMirror
	default:
		return "public Sigstore"
	}
}

// Initialize primes cosign's TUF cache against a private mirror. A
// no-op for the public instance and for the TrustedRoot path, both of
// which need no cache.
//
// Called once at startup rather than per scan: it writes to TUF_ROOT
// and hits the mirror over the network, neither of which belongs on a
// scan path.
func (s *SigstoreScanner) Initialize(ctx context.Context) error {
	if s == nil || s.cfg.TUFMirror == "" {
		return nil
	}
	args := []string{"initialize", "--mirror", s.cfg.TUFMirror}
	if s.cfg.TUFRootPath != "" {
		args = append(args, "--root", s.cfg.TUFRootPath)
	}
	out, err := s.run(ctx, args)
	if err != nil {
		return fmt.Errorf("cosign initialize against %s: %w (%s)", s.cfg.TUFMirror, err, firstLine(out, nil))
	}
	return nil
}

func (s *SigstoreScanner) run(ctx context.Context, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, s.bin, args...)
	cmd.Env = append(os.Environ(), s.env()...)

	var buf bytes.Buffer
	if VerboseScanLogs {
		cmd.Stdout = io.MultiWriter(&buf, os.Stderr)
		cmd.Stderr = io.MultiWriter(&buf, os.Stderr)
	} else {
		cmd.Stdout = &buf
		cmd.Stderr = &buf
	}
	err := cmd.Run()
	return buf.String(), err
}

func (s *SigstoreScanner) env() []string {
	var env []string
	if s.cfg.DockerConfigDir != "" {
		env = append(env, "DOCKER_CONFIG="+s.cfg.DockerConfigDir)
	}
	// TUF_ROOT IS SET UNCONDITIONALLY, not just for a private mirror.
	//
	// cosign needs a writable TUF cache for EVERY verification,
	// including against public Sigstore -- it defaults to $HOME/.sigstore
	// and creates it on first use. monitor-api runs with a read-only
	// root filesystem, so without this every single verification fails
	// with "mkdir /.sigstore: permission denied" and the feature is
	// inert.
	//
	// Found by running the real binary in the real image; every stubbed
	// test passed throughout, because a stub cosign never touches a TUF
	// cache.
	env = append(env, "TUF_ROOT="+tufRootDir())
	return env
}

func tufRootDir() string {
	if v := strings.TrimSpace(os.Getenv("COSIGN_TUF_ROOT_DIR")); v != "" {
		return v
	}
	return "/tmp/sigstore-tuf"
}

type cosignResult int

const (
	cosignOK cosignResult = iota
	cosignNotSigned
	cosignError
)

// classifyCosignResult separates "verified", "genuinely not signed" and
// "we could not find out".
//
// The distinction is the entire value of this scanner. cosign exits
// non-zero for both of the last two, so an implementation that only
// looked at the exit code would report a registry outage as an unsigned
// image -- a false accusation that looks exactly like a true one, and
// the direction of that error is somebody chasing a signature that was
// never missing.
//
// Matched on cosign's own wording for "there is nothing here to
// verify". Anything else is treated as an error, which is the safe
// direction: an unrecognised failure becomes "could not verify" rather
// than "unsigned".
func classifyCosignResult(err error, output string) cosignResult {
	if err == nil {
		return cosignOK
	}
	lower := strings.ToLower(output)
	for _, marker := range []string{
		"no signatures found",
		"no matching signatures",
		"no matching attestations",
		"no attestations found",
		"manifest unknown",
	} {
		if strings.Contains(lower, marker) {
			return cosignNotSigned
		}
	}
	return cosignError
}

// firstLine keeps a finding title to something readable -- cosign's
// failure output runs to many lines.
func firstLine(output string, err error) string {
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "Error:") {
			return truncate(line, 200)
		}
	}
	if err != nil {
		return truncate(err.Error(), 200)
	}
	return "no output"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
