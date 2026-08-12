package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AllowLocalArtifactPathsEnv / LocalArtifactRootEnv gate the one
// remaining way a ref can name a file on this pod's own filesystem
// instead of something in a registry.
//
// That convention predates registry fetching (see RegistryFetcher's own
// comment) and, left ungated, it is an arbitrary-file-read primitive
// handed to whoever can call POST /api/v1/artifacts: `file` and `sarif`
// artifacts are the two types that still scan IN-PROCESS -- never in an
// isolated scan-worker Job (see main.go's Registry) -- so
// ClamAVScanner/SARIFScanner open the path inside monitor-api's own
// pod, the process whose environment holds POSTGRES_PASSWORD and
// API_KEY. `ref: "/proc/self/environ"`, `ref:
// "/var/run/secrets/kubernetes.io/serviceaccount/token"`, or
// `ref: "/dev/zero"` (streamed to clamd until something gives out) all
// used to be accepted.
//
// So it is off unless BOTH are set: ALLOW_LOCAL_ARTIFACT_PATHS=true and
// LOCAL_ARTIFACT_ROOT naming the single directory such paths may live
// under. Off is the default, which is to say the default behaviour is
// now "every ref is fetched from a registry" -- the flag exists for the
// documented case of running this binary outside a cluster (see
// README's "Running monitor-api outside a Kubernetes pod"), or a
// deployment that really does mount a volume of artifacts and wants to
// scan them in place.
//
// Deliberately not plumbed through the chart: no chart-managed
// deployment mounts an artifact volume, so a values key would be a knob
// that cannot be turned usefully. Setting these means editing the
// Deployment to mount the volume anyway.
const (
	AllowLocalArtifactPathsEnv = "ALLOW_LOCAL_ARTIFACT_PATHS"
	LocalArtifactRootEnv       = "LOCAL_ARTIFACT_ROOT"
)

// localArtifactRoot returns the configured root, cleaned, or an error
// explaining why local paths aren't accepted right now. Fails closed in
// every ambiguous case: flag off, flag on with no root, or a root that
// isn't an absolute path -- a relative root would be resolved against
// whatever working directory the process happens to have, which is not
// something a security boundary should depend on.
func localArtifactRoot() (string, error) {
	if strings.ToLower(strings.TrimSpace(os.Getenv(AllowLocalArtifactPathsEnv))) != "true" {
		return "", fmt.Errorf("a local filesystem path is not an accepted artifact ref -- push the artifact to a registry, or set %s=true with %s (see README)", AllowLocalArtifactPathsEnv, LocalArtifactRootEnv)
	}
	root := strings.TrimSpace(os.Getenv(LocalArtifactRootEnv))
	if root == "" {
		return "", fmt.Errorf("%s is set but %s is empty -- refusing local paths rather than defaulting to a root", AllowLocalArtifactPathsEnv, LocalArtifactRootEnv)
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("%s must be an absolute path, got %q", LocalArtifactRootEnv, root)
	}
	return filepath.Clean(root), nil
}

// checkLocalArtifactPath applies the policy WITHOUT touching the
// filesystem: local paths must be enabled, and ref must be absolute and
// lexically inside the configured root. Split out from
// resolveLocalArtifactPath so registration (ValidateRef) can refuse an
// obviously out-of-bounds ref up front without requiring the file to
// exist yet -- registering an artifact before the file lands in the
// mounted volume is legitimate, reading one outside the root never is.
//
// Lexical first also makes the answer the same everywhere: "/proc/self/
// environ" is refused for being outside the root on a developer's Mac,
// where /proc doesn't exist at all, exactly as it is in the pod where it
// does.
func checkLocalArtifactPath(ref string) (clean, root string, err error) {
	root, err = localArtifactRoot()
	if err != nil {
		return "", "", err
	}
	if !filepath.IsAbs(ref) {
		return "", "", fmt.Errorf("local artifact path %q must be absolute (relative and ~ paths depend on a working directory this cannot reason about)", ref)
	}
	clean = filepath.Clean(ref)
	if !withinRoot(root, clean) {
		return "", "", fmt.Errorf("local artifact path %q is outside the permitted root -- refused", ref)
	}
	return clean, root, nil
}

// resolveLocalArtifactPath is checkLocalArtifactPath plus the checks
// that need the filesystem, and returns the path the caller should
// actually open -- the symlink-resolved one, not the one it was handed,
// so no caller can end up opening a different file than was validated.
//
// EvalSymlinks is what catches the escape filepath.Clean cannot see: a
// symlink sitting inside the root pointing at /etc/shadow is lexically
// perfect. Both sides are resolved before comparing, since the root
// itself is often a symlink (on macOS /var -> /private/var, and a
// Kubernetes volume mount is symlinked through ../data).
func resolveLocalArtifactPath(ref string) (string, error) {
	clean, root, err := checkLocalArtifactPath(ref)
	if err != nil {
		return "", err
	}
	return realPathWithin(root, clean)
}

// realPathWithin resolves path and root through EvalSymlinks and
// returns the real path if it is inside the real root and is a regular
// file. The regular-file requirement is not pedantry: a FIFO or
// /dev/zero inside the root would otherwise be streamed to clamd until
// something gives out, which is the same "arbitrary path" problem
// wearing a different hat.
func realPathWithin(root, path string) (string, error) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("artifact root %q is not usable: %w", root, err)
	}
	real, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("artifact path %q cannot be read: %w", path, err)
	}
	if !withinRoot(realRoot, real) {
		return "", fmt.Errorf("artifact path %q resolves outside the permitted root -- refused", path)
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", fmt.Errorf("artifact path %q cannot be read: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("artifact path %q is not a regular file -- refused", path)
	}
	return real, nil
}

// withinRoot reports whether path is root itself or sits under it. The
// separator matters: without it "/data-secrets/x" would count as inside
// "/data".
func withinRoot(root, path string) bool {
	return path == root || strings.HasPrefix(path, root+string(os.PathSeparator))
}

// ensureScannablePath is the check a scanner runs on a path it is about
// to open, rather than trusting whoever handed it one. Two directories
// are legitimate sources of such a path, and nothing else is:
//
//   - fetchScratchDir, where RegistryFetcher.Fetch writes what it
//     pulled -- the normal case for every artifact in a real install;
//   - the configured LOCAL_ARTIFACT_ROOT, when local paths are enabled
//     at all.
//
// This is deliberately not "trust anything under TMPDIR": /tmp is
// world-writable in a container and the unpacker writes there too, so
// that version would prove a much weaker property than the one claimed
// here.
func ensureScannablePath(path string) error {
	if _, err := realPathWithin(fetchScratchDir(), path); err == nil {
		return nil
	}
	if root, err := localArtifactRoot(); err == nil {
		if _, err := realPathWithin(root, path); err == nil {
			return nil
		}
	}
	return fmt.Errorf("refusing to open %q: it is neither a fetched artifact nor inside the permitted local artifact root", path)
}
