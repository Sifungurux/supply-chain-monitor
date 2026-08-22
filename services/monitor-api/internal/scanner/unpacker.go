package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// UnpackerScanner scans a container image (the `image` artifact type)
// for malware. clamd can only scan real files, not a compressed OCI
// image blob, so this shells out to `unpacker`
// (github.com/Sifungurux/unpacker, built into this image -- see
// Dockerfile) to pull the image and reconstruct its filesystem into a
// plain directory, then streams every regular file under it to clamd
// the same way ClamAVScanner does for standalone file artifacts.
//
// This runs alongside TrivyScanner for `image` artifacts: Trivy covers
// known-CVE package metadata, this covers file-content malware
// signatures. The two sets of findings are told apart downstream by
// Finding.Source ("trivy" vs "clamav"), not by artifact type.
//
// Trust note: this pulls and parses arbitrary, potentially-malicious
// image content (via oras-go / go-containerregistry / umoci). This
// type itself is unchanged from when that ran directly inside the
// long-running API server process -- it's the caller that changed:
// main.go's scanner registry no longer constructs a UnpackerScanner
// directly for the API server to call. Instead, IsolatedUnpackerScanner
// (isolated_unpacker.go) runs this exact code inside a short-lived,
// minimally-privileged Kubernetes Job per scan (via `monitor-api
// scan-worker`, main.go's runScanWorker), so a bug in any of the
// libraries above only ever affects that one disposable pod. See
// docs/architecture.md ("Isolating the unpack+scan step").
type UnpackerScanner struct {
	clamAddr    string
	unpackerBin string
	insecure    bool
	public      bool
	maxFileSize int64
	// dockerConfigPath, when set, points unpacker's own --config flag
	// at a docker CLI config.json (an "auths" map, same shape
	// ~/.docker/config.json uses) authenticating pulls against
	// scm-registry's token-auth (see docs/architecture.md's
	// registry-auth section). Built by main.go's writeDockerConfig,
	// empty in every deployment before registry auth existed.
	dockerConfigPath string
}

func NewUnpackerScanner(clamAddr, unpackerBin string, insecure, public bool, maxFileSize int64, dockerConfigPath string) *UnpackerScanner {
	if unpackerBin == "" {
		unpackerBin = "unpacker"
	}
	if maxFileSize <= 0 {
		maxFileSize = 100 * 1024 * 1024 // 100MB
	}
	return &UnpackerScanner{
		clamAddr:         clamAddr,
		unpackerBin:      unpackerBin,
		insecure:         insecure,
		public:           public,
		maxFileSize:      maxFileSize,
		dockerConfigPath: dockerConfigPath,
	}
}

// Bucket implements BucketAffinity: this scanner's findings always come
// from scanFileWithClamd (same as ClamAVScanner) with Source: "clamav",
// which classifyBucket always maps to "malware".
func (u *UnpackerScanner) Bucket() string { return "malware" }

func (u *UnpackerScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	// unpacker pulls the image itself (oras-go, falling back to crane),
	// so this is an outbound request made from a ref -- checked here for
	// the same reason Fetch and the CVE scanners check their own.
	if err := ValidateRef(ctx, ref); err != nil {
		return nil, err
	}
	tmpDir, err := os.MkdirTemp("", "scm-unpack-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create scratch dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	args := []string{"--output-dir", tmpDir}
	// Scoped to the in-cluster registry rather than applied to every
	// pull: UNPACKER_INSECURE exists for a plain-HTTP scm-registry, and
	// before this it also downgraded transport for docker.io and every
	// other public host in the same process. See
	// InsecureTransportAllowed (report S4, leg 3).
	if u.insecure && InsecureTransportAllowed(ref) {
		args = append(args, "--insecure")
	}
	if u.public {
		args = append(args, "--public")
	}
	if u.dockerConfigPath != "" {
		args = append(args, "--config", u.dockerConfigPath)
	}
	args = append(args, ref)

	cmd := exec.CommandContext(ctx, u.unpackerBin, args...)

	// Equivalent to cmd.CombinedOutput() (both streams captured into one
	// buffer, since unpacker's own log lines -- "pulling ... with oras",
	// the oras-failed-falling-back-to-crane message, etc. -- aren't
	// meaningfully split between stdout/stderr and error messages below
	// want them interleaved in the order they were written) -- written
	// out longhand so VerboseScanLogs can additionally tee the same
	// bytes to this process's real stderr as they're written, instead of
	// only ever surfacing them after the fact if the scan happens to
	// fail. See TrivyScanner.Scan's identical teeing in trivy.go for why
	// os.Stderr specifically (os.Stdout stays reserved for the final
	// ResultMarker line).
	var output bytes.Buffer
	if VerboseScanLogs {
		cmd.Stdout = io.MultiWriter(&output, os.Stderr)
		cmd.Stderr = io.MultiWriter(&output, os.Stderr)
	} else {
		cmd.Stdout = &output
		cmd.Stderr = &output
	}

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("unpacker failed for %q: %w (%s)", ref, err, output.String())
	}

	// Per unpacker's documented output layout: <output-dir>/image holds
	// the unpacked artifact contents.
	imageDir := filepath.Join(tmpDir, "image")
	if _, statErr := os.Stat(imageDir); statErr != nil {
		return nil, fmt.Errorf("unpacker did not produce %q: %w", imageDir, statErr)
	}

	// Always-on, not gated behind VerboseScanLogs -- the point is
	// confirming, from a scan-worker Job's pod logs alone, that clamav
	// itself is the thing running right now, not just unpacker (which
	// already finished by this point). See main.go's runScanWorker for
	// the equivalent start/complete markers around trivy/grype.
	slog.Info("unpacker: image unpacked, scanning files with clamav", "scanner", "clamav", "clam_addr", u.clamAddr)

	var findings []artifact.Finding
	// found counts every regular file in the unpacked image; attempted
	// counts the ones actually sent to clamd. They differ by skipped,
	// and keeping them apart is the whole point: "no findings" is only
	// good news next to a non-zero attempted, and the two ways of
	// reaching zero need different error messages.
	var found, skipped, attempted, failed int
	var lastErr error

	walkErr := filepath.WalkDir(imageDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil // skip files we can't stat rather than aborting the whole walk
		}
		found++
		if info.Size() > u.maxFileSize {
			skipped++
			return nil
		}

		attempted++
		result, scanErr := scanFileWithClamd(ctx, u.clamAddr, path)
		if scanErr != nil {
			failed++
			lastErr = scanErr
			return nil
		}
		if result.Found {
			rel, relErr := filepath.Rel(imageDir, path)
			if relErr != nil {
				rel = path
			}
			findings = append(findings, artifact.Finding{
				ID:       "clamav-signature-match",
				Severity: "critical",
				Title:    fmt.Sprintf("%s: %s", rel, result.Signature),
				Source:   "clamav",
			})
		}
		return nil
	})
	if walkErr != nil {
		return findings, fmt.Errorf("failed walking unpacked image: %w", walkErr)
	}
	slog.Info("unpacker: clamav scan complete",
		"scanner", "clamav", "files_found", found, "files_scanned", attempted,
		"files_skipped", skipped, "files_failed", failed, "count", len(findings))

	// Nothing was opened. Reporting no findings here would record the
	// artifact as malware-clean on the strength of a scan that never
	// looked at a byte -- and an image whose unpack produced nothing is
	// indistinguishable, from this side, from one that is genuinely
	// clean.
	//
	// That is not hypothetical: unpacker exits 0 having downloaded no
	// blobs at all for some references (a multi-arch index, measured),
	// leaving an empty image/ behind. The stat above passes, this walk
	// finds nothing, and the artifact comes back clean.
	//
	// The two ways of reaching zero are reported differently because
	// they need different fixes: an empty directory is an unpack that
	// silently produced nothing, while an all-skipped directory is
	// maxFileSize set below everything in the image.
	if attempted == 0 {
		if found == 0 {
			return findings, fmt.Errorf("clamav scanned nothing: the unpacked image at %q contains no regular files -- "+
				"treating that as clean would record an image nobody opened", imageDir)
		}
		return findings, fmt.Errorf("clamav scanned nothing: all %d files in the unpacked image are larger than the "+
			"%d byte limit (monitorApi.unpacker.maxFileMB) -- treating that as clean would record an image nobody opened",
			skipped, u.maxFileSize)
	}

	// If every file that WAS attempted failed (e.g. clamd was
	// unreachable for the whole run), surface that for the same reason.
	if failed == attempted {
		return findings, fmt.Errorf("clamav scan failed for all %d files in unpacked image (e.g. %w)", attempted, lastErr)
	}

	return findings, nil
}

// Kind implements ScanKind: this scanner is capped independently of
// the global scan cap via SCAN_CONCURRENCY_UNPACKER.
func (s *UnpackerScanner) Kind() string { return "unpacker" }
