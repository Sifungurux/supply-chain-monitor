package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// GeneratedDocument is one SBOM/SARIF document derived from an image
// scan's raw trivy JSON report -- see GenerateImageDocuments. Kind is a
// plain string (artifact.DocumentKindSBOM/DocumentKindSARIF) rather
// than importing internal/artifact here just for two constants.
type GeneratedDocument struct {
	Kind        string
	ContentType string
	Content     []byte
}

// GenerateImageDocuments derives a CycloneDX SBOM and a SARIF report
// from rawJSON (trivy's own `--format json` output -- see
// TrivyScanner.ScanRaw, already produced for the same scan) via `trivy
// convert`, rather than re-scanning the image a second or third time.
// `--scanners vuln` on the cyclonedx conversion keeps the vulnerability
// data already present in rawJSON in the generated SBOM -- without it,
// trivy convert produces a component inventory only (confirmed via
// trivy's own CLI: "'--format cyclonedx' disables security scanning"
// unless this flag is passed); it does not trigger a re-scan, it only
// controls what the converter includes from the report it's already
// been given.
//
// Best-effort, mirroring Artifact.Digest's convention (see that
// field's comment): returns whatever documents it managed to generate
// plus every error encountered, never a single all-or-nothing failure
// -- a SARIF conversion failing shouldn't also discard a successfully
// generated SBOM, and neither should ever fail the scan that produced
// rawJSON in the first place (see runScanWorker's caller).
//
// trivy convert only accepts a file path argument, not stdin, so
// rawJSON is written to a temp file under dir first and removed
// afterward. dir must be writable -- runScanWorker passes the
// scan-worker Job's /tmp scratch emptyDir (see k8sjob.NewScanJob),
// since the rest of that pod's root filesystem is deliberately
// read-only.
func GenerateImageDocuments(ctx context.Context, rawJSON []byte, dir string) ([]GeneratedDocument, []error) {
	reportFile, err := os.CreateTemp(dir, "trivy-report-*.json")
	if err != nil {
		return nil, []error{fmt.Errorf("write trivy report for conversion: %w", err)}
	}
	reportPath := reportFile.Name()
	defer os.Remove(reportPath)

	if _, err := reportFile.Write(rawJSON); err != nil {
		reportFile.Close()
		return nil, []error{fmt.Errorf("write trivy report for conversion: %w", err)}
	}
	if err := reportFile.Close(); err != nil {
		return nil, []error{fmt.Errorf("write trivy report for conversion: %w", err)}
	}

	var docs []GeneratedDocument
	var errs []error

	if content, err := runTrivyConvert(ctx, reportPath, "cyclonedx", "--scanners", "vuln"); err != nil {
		errs = append(errs, fmt.Errorf("generate sbom: %w", err))
	} else {
		docs = append(docs, GeneratedDocument{Kind: "sbom", ContentType: "application/vnd.cyclonedx+json", Content: content})
	}

	if content, err := runTrivyConvert(ctx, reportPath, "sarif"); err != nil {
		errs = append(errs, fmt.Errorf("generate sarif: %w", err))
	} else {
		docs = append(docs, GeneratedDocument{Kind: "sarif", ContentType: "application/sarif+json", Content: content})
	}

	return docs, errs
}

// runTrivyConvert runs `trivy convert --format <format> [extraArgs...]
// <reportPath>` and returns its stdout -- confirmed directly against
// trivy (v0.72, this project's pinned version, see Dockerfile) that
// omitting -o writes the converted document to stdout as clean JSON,
// with any informational logging going to stderr instead, so no -o/temp
// output file is needed here the way reportPath itself needed one.
//
// Its own short timeout (rather than inheriting whatever's left of the
// caller's overall scan budget) reflects that this is a fast, local
// reformat of data trivy already produced -- not a network operation --
// so a slow conversion is a strong signal something's actually wrong,
// worth failing on its own terms rather than silently eating whatever
// time happens to remain in ctx.
func runTrivyConvert(ctx context.Context, reportPath, format string, extraArgs ...string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	args := append([]string{"convert", "--format", format}, extraArgs...)
	args = append(args, reportPath)

	cmd := exec.CommandContext(cctx, "trivy", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy convert --format %s: %w (%s)", format, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// UploadDocument POSTs a generated document to monitor-api's
// POST /api/v1/artifacts/{id}/documents/{kind} endpoint. This is how a
// scan-worker Job hands a generated SBOM/SARIF document back to
// monitor-api -- see GenerateImageDocuments' own comment for why this
// exists instead of returning the bytes through the existing pod-logs/
// WorkerResult channel used for findings (that channel is a single
// small JSON line; these documents commonly run 10-20MB for a
// real-world image).
//
// Authenticates with the same shared Bearer API key every other
// request in this system already uses (see internal/api/router.go's
// withAuth) -- no separate auth scheme needed for this one caller.
func UploadDocument(ctx context.Context, apiBaseURL, apiKey, artifactID, kind, contentType string, content []byte) error {
	url := strings.TrimRight(apiBaseURL, "/") + "/api/v1/artifacts/" + artifactID + "/documents/" + kind
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("build %s document upload request: %w", kind, err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("upload %s document: %w", kind, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("upload %s document: server returned %d: %s", kind, resp.StatusCode, string(body))
	}
	return nil
}
