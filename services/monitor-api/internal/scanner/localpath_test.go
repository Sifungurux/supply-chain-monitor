package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The paths an attacker would actually reach for from inside a
// monitor-api pod. Every one of these was an accepted `file`/`sarif`
// artifact ref before local paths were gated -- both types scan
// in-process, so the read happened in the pod holding POSTGRES_PASSWORD
// and API_KEY.
//
// They are checked lexically against the root before anything touches
// the filesystem, so the answer is the same on a Mac (where /proc and
// the ServiceAccount directory don't exist) as in the pod where they do
// -- otherwise these would pass for the wrong reason.
var inwardPaths = map[string]string{
	"proc environ":         "/proc/self/environ",
	"serviceaccount token": "/var/run/secrets/kubernetes.io/serviceaccount/token",
	"serviceaccount ca":    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
	"shadow file":          "/etc/shadow",
	"device":               "/dev/zero",
}

// Default posture: no flag, no root, no local paths at all. This is the
// behaviour every deployment gets without opting in, and it is the same
// answer as deleting local-path support outright.
func TestLocalPaths_RefusedByDefault(t *testing.T) {
	for name, path := range inwardPaths {
		t.Run(name, func(t *testing.T) {
			if _, err := resolveLocalArtifactPath(path); err == nil {
				t.Fatalf("resolveLocalArtifactPath(%q) = nil, want refused with local paths off", path)
			}
		})
	}
	// Not even a path that would be legal under a configured root --
	// the flag is what makes any of this reachable.
	inside := filepath.Join(t.TempDir(), "report.sarif")
	if err := os.WriteFile(inside, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := resolveLocalArtifactPath(inside); err == nil {
		t.Fatal("a real file is still refused while local paths are off")
	}
}

// Enabled, with a root: the root is the boundary, and everything that
// leaves it is refused however it tries to.
func TestLocalPaths_RootIsTheBoundary(t *testing.T) {
	root := t.TempDir()
	enableLocalPaths(t, root)

	inside := filepath.Join(root, "report.sarif")
	if err := os.WriteFile(inside, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	t.Run("a real file inside the root is accepted", func(t *testing.T) {
		got, err := resolveLocalArtifactPath(inside)
		if err != nil {
			t.Fatalf("resolveLocalArtifactPath(%q) = %v, want accepted", inside, err)
		}
		// The RESOLVED path comes back, so the file that was validated
		// is the file the caller opens.
		want, err := filepath.EvalSymlinks(inside)
		if err != nil {
			t.Fatalf("evalsymlinks: %v", err)
		}
		if got != want {
			t.Fatalf("resolved path = %q, want %q", got, want)
		}
	})

	for name, path := range inwardPaths {
		t.Run(name+" is outside the root", func(t *testing.T) {
			_, err := resolveLocalArtifactPath(path)
			if err == nil {
				t.Fatalf("resolveLocalArtifactPath(%q) = nil, want refused", path)
			}
			if !strings.Contains(err.Error(), "outside the permitted root") {
				t.Fatalf("refused for the wrong reason: %v -- it must fail containment, not existence, or this test proves nothing on a machine where the path doesn't exist", err)
			}
		})
	}

	t.Run("../ escape", func(t *testing.T) {
		for _, path := range []string{
			filepath.Join(root, "..", "etc", "shadow"),
			filepath.Join(root, "sub", "..", "..", "etc", "shadow"),
			root + "/../../../../proc/self/environ",
		} {
			if _, err := resolveLocalArtifactPath(path); err == nil {
				t.Fatalf("resolveLocalArtifactPath(%q) = nil, want refused", path)
			}
		}
	})

	t.Run("sibling directory sharing the root's prefix", func(t *testing.T) {
		// "/data-secrets/x" must not count as inside "/data".
		if _, err := resolveLocalArtifactPath(root + "-secrets/x"); err == nil {
			t.Fatal("a sibling directory sharing the root's name prefix must not be treated as inside it")
		}
	})

	t.Run("symlink out of the root", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(outside, []byte("credentials"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		link := filepath.Join(root, "innocent.sarif")
		if err := os.Symlink(outside, link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		// Lexically perfect, which is exactly why EvalSymlinks has to run.
		if _, err := resolveLocalArtifactPath(link); err == nil {
			t.Fatal("a symlink inside the root pointing outside it must be refused")
		}
	})

	t.Run("not a regular file", func(t *testing.T) {
		dir := filepath.Join(root, "subdir")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if _, err := resolveLocalArtifactPath(dir); err == nil {
			t.Fatal("a directory is not a scannable artifact")
		}
	})

	t.Run("relative and ~ paths", func(t *testing.T) {
		for _, path := range []string{"./report.sarif", "../report.sarif", "~/report.sarif"} {
			if _, err := resolveLocalArtifactPath(path); err == nil {
				t.Fatalf("resolveLocalArtifactPath(%q) = nil, want refused", path)
			}
		}
	})
}

// Half-configured is refused, not guessed at: a flag with no root would
// otherwise have to invent one.
func TestLocalPaths_FlagWithoutRootFailsClosed(t *testing.T) {
	t.Setenv(AllowLocalArtifactPathsEnv, "true")
	t.Setenv(LocalArtifactRootEnv, "")
	if _, err := resolveLocalArtifactPath("/etc/shadow"); err == nil {
		t.Fatal("want refused when the root is unset")
	}
	t.Setenv(LocalArtifactRootEnv, "relative/root")
	if _, err := resolveLocalArtifactPath("relative/root/x"); err == nil {
		t.Fatal("want refused when the root is not absolute")
	}
}

// The gate is at registration too, so an artifact nothing could ever
// legally open is refused up front rather than failing every scan
// forever after.
func TestValidateRef_LocalPathsFollowTheSamePolicy(t *testing.T) {
	if err := ValidateRef(context.Background(), "/proc/self/environ"); err == nil {
		t.Fatal("registration must refuse a local path while local paths are off")
	}

	root := t.TempDir()
	enableLocalPaths(t, root)
	if err := ValidateRef(context.Background(), "/proc/self/environ"); err == nil {
		t.Fatal("registration must refuse a local path outside the root")
	}
	// Lexical only at registration: the file need not exist yet, because
	// registering an artifact before it lands in the volume is fine.
	if err := ValidateRef(context.Background(), filepath.Join(root, "not-written-yet.sarif")); err != nil {
		t.Fatalf("in-root path = %v, want accepted at registration even before the file exists", err)
	}
}

// Fetch is where a ref becomes a path, so it is where the passthrough
// used to live. Both directions asserted: refused when off, resolved
// when on.
func TestRegistryFetcher_Fetch_LocalPath(t *testing.T) {
	f := NewRegistryFetcher(true, "", "")

	_, cleanup, err := f.Fetch(context.Background(), "/proc/self/environ")
	cleanup()
	if err == nil {
		t.Fatal("Fetch must refuse a local path while local paths are off")
	}

	root := t.TempDir()
	enableLocalPaths(t, root)
	inside := filepath.Join(root, "suspicious.bin")
	if err := os.WriteFile(inside, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	path, cleanup, err := f.Fetch(context.Background(), inside)
	defer cleanup() // must be safe even though nothing was downloaded
	if err != nil {
		t.Fatalf("Fetch(%q) = %v, want the in-root path accepted", inside, err)
	}
	want, _ := filepath.EvalSymlinks(inside)
	if path != want {
		t.Fatalf("path = %q, want the resolved in-root path %q", path, want)
	}
}

// Both in-process scanners that open a file by path enforce this
// themselves rather than relying on the FetchingScanner that normally
// wraps them -- and both are asserted here, in one function, so the two
// can't drift into enforcing it differently.
func TestScannersRefuseToOpenPathsOutsideTheRoot(t *testing.T) {
	// A real clamd address is never dialed: the path is refused first,
	// which is the point -- an address that would fail loudly if it were
	// reached makes that observable.
	clam := NewClamAVScanner("127.0.0.1:1")
	sarif := NewSARIFScanner()

	for name, path := range inwardPaths {
		t.Run(name, func(t *testing.T) {
			if _, err := sarif.Scan(context.Background(), path); err == nil {
				t.Fatalf("SARIFScanner.Scan(%q) = nil, want refused", path)
			} else if !strings.Contains(err.Error(), "refusing to open") {
				t.Fatalf("SARIFScanner.Scan(%q) failed for the wrong reason: %v", path, err)
			}
			if _, err := clam.Scan(context.Background(), path); err == nil {
				t.Fatalf("ClamAVScanner.Scan(%q) = nil, want refused", path)
			} else if !strings.Contains(err.Error(), "refusing to open") {
				t.Fatalf("ClamAVScanner.Scan(%q) failed for the wrong reason (did it dial clamd?): %v", path, err)
			}
		})
	}

	// Still refused with local paths enabled, when the path is outside
	// the configured root.
	enableLocalPaths(t, t.TempDir())
	if _, err := sarif.Scan(context.Background(), "/etc/shadow"); err == nil {
		t.Fatal("SARIFScanner.Scan must refuse a path outside the configured root")
	}
}

// enableLocalPaths turns the feature on for one test. Restored
// automatically by t.Setenv, so no test leaks the policy into another.
func enableLocalPaths(t *testing.T, root string) {
	t.Helper()
	t.Setenv(AllowLocalArtifactPathsEnv, "true")
	t.Setenv(LocalArtifactRootEnv, root)
}
