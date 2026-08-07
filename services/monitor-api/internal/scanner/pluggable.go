package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// refPlaceholder is substituted for the artifact ref in every configured
// Args entry that contains it -- e.g. an Args of ["{{ref}}", "-o",
// "json"] scans the artifact by running `<command> <ref> -o json`.
// Every arg is checked (not just a single designated one) so a real
// invocation like ["--input", "{{ref}}"] or "image:{{ref}}" also works,
// not just a bare positional ref.
const refPlaceholder = "{{ref}}"

// PluggableScannerConfig describes one operator-configured pluggable
// scanner: an arbitrary command monitor-api shells out to instead of
// (or alongside) its own built-in scanners (trivy, ClamAV, ...). This
// is how a different CVE scanner (Grype, OSV-Scanner, ...) or a
// different SBOM tool gets plugged in without a Go code change here --
// see docs/architecture.md ("Pluggable scanners") for the full design
// and a PLUGGABLE_SCANNERS example. Not to be confused with
// `POST /api/v1/artifacts/{id}/findings` (see internal/api/findings.go),
// which is for a scanner that already ran somewhere entirely outside
// this cluster (a CI pipeline, a different system) and just reports
// its result in -- this type is for a scanner monitor-api itself runs.
//
// Tagged for JSON since this is parsed straight out of the
// PLUGGABLE_SCANNERS env var (a JSON array), which main.go renders from
// charts/supply-chain-monitor/values.yaml's monitorApi.pluggableScanners.
type PluggableScannerConfig struct {
	// Name identifies this scanner in logs/errors and is the fallback
	// Finding.Source for any result that doesn't set its own "source"
	// (see pluggableFinding below) -- e.g. "grype", "osv-scanner".
	Name string `json:"name"`
	// ArtifactTypes lists which artifact.Type values (image/file/sbom/
	// sarif) this scanner registers against. Registration is additive:
	// this scanner runs alongside whatever built-in scanners already
	// exist for that type (e.g. adding Grype to "image" doesn't remove
	// trivy), the same way Registry already supports more than one
	// scanner per type.
	ArtifactTypes []string `json:"artifactTypes"`
	// Command is the binary to exec -- must already exist in the
	// monitor-api image (or a derived image built FROM it; see
	// docs/architecture.md and README for why this project's own
	// Dockerfile can't bake in every possible third-party scanner) or
	// on the $PATH monitor-api's process sees.
	Command string `json:"command"`
	// Args are passed to Command as-is, except any arg containing the
	// literal substring "{{ref}}" has that replaced with the actual
	// artifact ref/local path being scanned (see refPlaceholder).
	Args []string `json:"args"`
	// Category is the default Finding bucket ("cve", "misconfiguration",
	// "secret", "other" -- never "malware", the same restriction
	// classifySarifCategory documents, since this isn't a signature
	// scanner) applied to any result whose own JSON doesn't set one.
	// Almost always set to "cve" for a CVE scanner or left as "other"/
	// unset for a more general SBOM/SAST tool that classifies its own
	// results per-finding instead.
	Category string `json:"category,omitempty"`
	// TimeoutSeconds bounds how long a single Scan call may run before
	// being killed. Defaults to 5 minutes (defaultPluggableScannerTimeout)
	// if zero or negative -- the same ceiling scanArtifact's own context
	// already applies to the whole multi-scanner scan, so this mostly
	// matters for keeping one slow/hung command from being the one that
	// eats that entire budget by itself.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
}

const defaultPluggableScannerTimeout = 5 * time.Minute

// maxPluggableScannerOutputBytes caps how much stdout/stderr a single
// Scan call will accumulate from the configured command, so a
// misbehaving or compromised command flooding either stream can't grow
// this process's memory without bound. 10MiB is generous headroom even
// for a large findings list (a JSON finding record is on the order of
// a couple hundred bytes, so this comfortably covers tens of thousands
// of findings) while still being a hard, enforced ceiling -- a
// well-behaved pluggable scanner emitting the documented
// JSON-array-of-findings contract has no legitimate reason to get
// anywhere close to it.
const maxPluggableScannerOutputBytes = 10 * 1024 * 1024 // 10MiB

// limitedBuffer is a bytes.Buffer that refuses writes once it's
// accumulated more than limit bytes, returning an error instead of
// growing further. Used as cmd.Stdout/cmd.Stderr below so os/exec's
// own internal copy from the child process's pipes treats exceeding
// the cap as a normal copy error (surfaced back through cmd.Run()),
// rather than this process silently growing its own memory to match
// however much the command decides to write.
type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.limit {
		return 0, fmt.Errorf("output exceeded the %d byte limit", b.limit)
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *limitedBuffer) String() string { return b.buf.String() }

// pluggableFinding is the wire format a pluggable scanner's command is
// expected to print as a single JSON array on stdout. It deliberately
// mirrors artifact.Finding's exported fields, plus "category" --
// unlike artifact.Finding.Category (tagged json:"-" everywhere else in
// this app, since a persisted finding's bucket already records its
// category and a second copy would just be a stale duplicate),
// PluggableScanner is the one place a category has to arrive *from*
// JSON rather than only ever be set in-process, since the whole point
// here is letting the configured command decide it.
type pluggableFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Source   string `json:"source"`
	Category string `json:"category"`
}

// PluggableScanner shells out to an arbitrary operator-configured
// command and interprets its stdout as a JSON array of findings. It
// doesn't know or care whether that command is a real third-party
// scanner (Grype, OSV-Scanner, Syft) or a thin shell/Python wrapper
// script that reshapes that tool's own native output into this
// contract -- from monitor-api's side, "a pluggable scanner" is just
// "a command that, given a ref, prints findings as JSON."
type PluggableScanner struct {
	cfg PluggableScannerConfig
}

func NewPluggableScanner(cfg PluggableScannerConfig) *PluggableScanner {
	return &PluggableScanner{cfg: cfg}
}

// buildArgs substitutes refPlaceholder into every configured Args
// entry that contains it. Split out from Scan so the substitution
// logic is unit-testable (pluggable_test.go) without actually running
// any command -- the same reasoning TrivyScanner.args is its own
// method.
func (e *PluggableScanner) buildArgs(ref string) []string {
	args := make([]string, len(e.cfg.Args))
	for i, a := range e.cfg.Args {
		args[i] = strings.ReplaceAll(a, refPlaceholder, ref)
	}
	return args
}

func (e *PluggableScanner) timeout() time.Duration {
	if e.cfg.TimeoutSeconds <= 0 {
		return defaultPluggableScannerTimeout
	}
	return time.Duration(e.cfg.TimeoutSeconds) * time.Second
}

func (e *PluggableScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout())
	defer cancel()

	cmd := exec.CommandContext(ctx, e.cfg.Command, e.buildArgs(ref)...)

	stdout := &limitedBuffer{limit: maxPluggableScannerOutputBytes}
	stderr := &limitedBuffer{limit: maxPluggableScannerOutputBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("pluggable scanner %q (%s) failed for %q: %w (%s)", e.cfg.Name, e.cfg.Command, ref, err, stderr.String())
	}

	var wire []pluggableFinding
	if err := json.Unmarshal(stdout.Bytes(), &wire); err != nil {
		return nil, fmt.Errorf("pluggable scanner %q (%s) produced output that isn't a JSON array of findings (expected [{\"id\":...,\"severity\":...,\"title\":...,\"source\":...,\"category\":...}, ...]): %w", e.cfg.Name, e.cfg.Command, err)
	}

	findings := make([]artifact.Finding, 0, len(wire))
	for _, w := range wire {
		f := artifact.Finding{
			ID:       w.ID,
			Severity: w.Severity,
			Title:    w.Title,
			Source:   w.Source,
			Category: w.Category,
		}
		if f.Source == "" {
			f.Source = e.cfg.Name
		}
		if f.Category == "" {
			f.Category = e.cfg.Category
		}
		findings = append(findings, f)
	}
	return findings, nil
}
