package scanner

import (
	"context"
	"fmt"
	"io/fs"
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
}

func NewUnpackerScanner(clamAddr, unpackerBin string, insecure, public bool, maxFileSize int64) *UnpackerScanner {
	if unpackerBin == "" {
		unpackerBin = "unpacker"
	}
	if maxFileSize <= 0 {
		maxFileSize = 100 * 1024 * 1024 // 100MB
	}
	return &UnpackerScanner{
		clamAddr:    clamAddr,
		unpackerBin: unpackerBin,
		insecure:    insecure,
		public:      public,
		maxFileSize: maxFileSize,
	}
}

func (u *UnpackerScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	tmpDir, err := os.MkdirTemp("", "scm-unpack-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create scratch dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	args := []string{"--output-dir", tmpDir}
	if u.insecure {
		args = append(args, "--insecure")
	}
	if u.public {
		args = append(args, "--public")
	}
	args = append(args, ref)

	cmd := exec.CommandContext(ctx, u.unpackerBin, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("unpacker failed for %q: %w (%s)", ref, err, string(output))
	}

	// Per unpacker's documented output layout: <output-dir>/image holds
	// the unpacked artifact contents.
	imageDir := filepath.Join(tmpDir, "image")
	if _, statErr := os.Stat(imageDir); statErr != nil {
		return nil, fmt.Errorf("unpacker did not produce %q: %w", imageDir, statErr)
	}

	var findings []artifact.Finding
	var attempted, failed int
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
		if info.Size() > u.maxFileSize {
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
	// If every single file failed to scan (e.g. clamd was unreachable
	// for the whole run), surface that as an error rather than quietly
	// reporting a "clean" scan that never actually happened.
	if attempted > 0 && failed == attempted {
		return findings, fmt.Errorf("clamav scan failed for all %d files in unpacked image (e.g. %w)", attempted, lastErr)
	}

	return findings, nil
}
