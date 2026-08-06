package scanner

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// writeFakeUnpacker writes a small shell script standing in for the
// real `unpacker` binary (github.com/Sifungurux/unpacker), returning
// its path. UnpackerScanner.Scan always builds argv as
// ["--output-dir", tmpDir, (--insecure), (--public), ref] -- "--output-dir"
// and its value come first, before any flags -- so a fake script can
// rely on $1/$2 positionally without parsing the rest of argv at all.
// script is the shell body that runs with $1="--output-dir", $2=<the
// output dir>; it's responsible for creating whatever
// $2/image/... layout (or not) the test needs, and for its own exit
// code.
func writeFakeUnpacker(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-unpacker.sh")
	content := "#!/bin/sh\n" + script + "\n"
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write fake unpacker script: %v", err)
	}
	return path
}

func newTestUnpackerScanner(t *testing.T, clamAddr, unpackerScript string, maxFileSize int64) *UnpackerScanner {
	t.Helper()
	return NewUnpackerScanner(clamAddr, writeFakeUnpacker(t, unpackerScript), false, false, maxFileSize, "")
}

func TestUnpackerScanner_Bucket(t *testing.T) {
	s := NewUnpackerScanner("127.0.0.1:1", "unpacker", false, false, 0, "")
	if got := s.Bucket(); got != "malware" {
		t.Fatalf("Bucket() = %q, want %q", got, "malware")
	}
}

func TestUnpackerScanner_Scan_HappyPathFindsMalwareAmongCleanFiles(t *testing.T) {
	addr := startFakeClamd(t, func(received []byte) string {
		if string(received) == "malware content" {
			return "stream: Eicar-Test-Signature FOUND"
		}
		return "stream: OK"
	})
	script := `
mkdir -p "$2/image/sub"
printf 'clean content' > "$2/image/clean.txt"
printf 'malware content' > "$2/image/sub/bad.txt"
`
	s := newTestUnpackerScanner(t, addr, script, 0)

	findings, err := s.Scan(context.Background(), "ref-does-not-matter:latest")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", findings)
	}
	f := findings[0]
	if f.Source != "clamav" || f.Severity != "critical" || f.ID != "clamav-signature-match" {
		t.Errorf("finding = %+v, want the standard clamav-signature-match shape", f)
	}
	// Title includes the path relative to the unpacked image root, so
	// the specific infected file (not just "something matched") is
	// visible from the finding alone.
	if !strings.Contains(f.Title, "sub/bad.txt") {
		t.Errorf("Title = %q, want it to include the relative path %q", f.Title, "sub/bad.txt")
	}
}

// TestUnpackerScanner_Scan_DockerConfigPathIsPassedThrough confirms
// dockerConfigPath (set once registry auth is enabled -- see
// main.go's writeDockerConfig) reaches unpacker as --config, the flag
// docs/architecture.md's Roadmap already identified unpacker supports
// for exactly this. The fake script records argv to argvFile, a fixed
// path outside the ephemeral scm-unpack-* dir Scan creates and cleans
// up itself, so it survives long enough for this test to read it back.
func TestUnpackerScanner_Scan_DockerConfigPathIsPassedThrough(t *testing.T) {
	argvFile := filepath.Join(t.TempDir(), "argv.txt")
	script := `mkdir -p "$2/image"
echo "$@" > ` + argvFile
	s := newTestUnpackerScanner(t, "127.0.0.1:1", script, 0)
	s.dockerConfigPath = "/creds/dockerconfig.json"

	if _, err := s.Scan(context.Background(), "ref-does-not-matter:latest"); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	got, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read recorded argv: %v", err)
	}
	if !strings.Contains(string(got), "--config /creds/dockerconfig.json") {
		t.Errorf("argv = %q, want it to include \"--config /creds/dockerconfig.json\"", string(got))
	}
}

func TestUnpackerScanner_Scan_UnpackerFailureIsReturnedWithItsOutput(t *testing.T) {
	script := `
echo "pulling ref with oras" >&2
echo "oras: manifest unknown" >&2
exit 1
`
	s := newTestUnpackerScanner(t, "127.0.0.1:1", script, 0)

	_, err := s.Scan(context.Background(), "missing:tag")
	if err == nil {
		t.Fatal("expected an error when the unpacker binary exits nonzero, got nil")
	}
	if !strings.Contains(err.Error(), "unpacker failed for") || !strings.Contains(err.Error(), "manifest unknown") {
		t.Fatalf("error = %q, want it to include both the failure context and the captured output", err.Error())
	}
}

func TestUnpackerScanner_Scan_MissingImageDirIsAnError(t *testing.T) {
	// Exits 0 (a "successful" run, as far as the process exit code
	// goes) but never creates <output-dir>/image -- e.g. a future
	// unpacker version changing its documented output layout.
	s := newTestUnpackerScanner(t, "127.0.0.1:1", "exit 0", 0)

	_, err := s.Scan(context.Background(), "ref")
	if err == nil {
		t.Fatal("expected an error when unpacker doesn't produce an image/ directory, got nil")
	}
	if !strings.Contains(err.Error(), "did not produce") {
		t.Fatalf("error = %q, want it to mention the missing image directory", err.Error())
	}
}

func TestUnpackerScanner_Scan_FilesOverMaxSizeAreSkipped(t *testing.T) {
	// Every connection would be reported as malware if scanFileWithClamd
	// were ever actually called -- so an empty findings result here can
	// only mean the oversized file was skipped before reaching clamd at
	// all, not that clamd happened to report it clean.
	addr := startFakeClamd(t, func(received []byte) string {
		return "stream: Eicar-Test-Signature FOUND"
	})
	script := `
mkdir -p "$2/image"
printf 'this content is well over the ten byte limit' > "$2/image/big.txt"
`
	s := newTestUnpackerScanner(t, addr, script, 10) // maxFileSize=10 bytes

	findings, err := s.Scan(context.Background(), "ref")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none -- the only file present is over maxFileSize and should have been skipped", findings)
	}
}

func TestUnpackerScanner_Scan_AllFilesFailingToScanIsAnError(t *testing.T) {
	// Bind then close -- guaranteed nothing is listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	unreachable := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	script := `
mkdir -p "$2/image"
printf 'irrelevant' > "$2/image/a.txt"
printf 'irrelevant' > "$2/image/b.txt"
`
	s := newTestUnpackerScanner(t, unreachable, script, 0)

	_, err = s.Scan(context.Background(), "ref")
	if err == nil {
		t.Fatal("expected an error when clamd is unreachable for every file, got nil")
	}
	if !strings.Contains(err.Error(), "clamav scan failed for all") {
		t.Fatalf("error = %q, want it to say every file's scan failed", err.Error())
	}
}

// One file's scan failing (not every file) must not fail the whole
// Scan -- see UnpackerScanner.Scan's own "attempted > 0 && failed ==
// attempted" comment: a single flaky file shouldn't discard findings
// already collected from every other file that scanned successfully.
// The fake clamd server below fails only the very first connection it
// accepts (draining the client's INSTREAM chunks first, so the client's
// writes don't race a connection reset, then closing without a reply --
// a real reply-read failure, not a write-side one) and replies normally
// to every connection after that.
func TestUnpackerScanner_Scan_OneFailingFileDoesNotDiscardOtherFindings(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	connCount := 0
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()

				handshake := make([]byte, len("zINSTREAM\x00"))
				if _, err := io.ReadFull(conn, handshake); err != nil {
					return
				}
				sizeBuf := make([]byte, 4)
				for {
					if _, err := io.ReadFull(conn, sizeBuf); err != nil {
						return
					}
					size := binary.BigEndian.Uint32(sizeBuf)
					if size == 0 {
						break
					}
					chunk := make([]byte, size)
					if _, err := io.ReadFull(conn, chunk); err != nil {
						return
					}
				}

				mu.Lock()
				connCount++
				isFirst := connCount == 1
				mu.Unlock()

				if isFirst {
					// Close without replying -- the client's final
					// ReadString('\x00') fails, a real reply-read error.
					return
				}
				_, _ = conn.Write([]byte("stream: OK\x00"))
			}(conn)
		}
	}()

	script := `
mkdir -p "$2/image"
printf 'a' > "$2/image/a-fails.txt"
printf 'b' > "$2/image/b-succeeds.txt"
`
	s := newTestUnpackerScanner(t, ln.Addr().String(), script, 0)

	findings, err := s.Scan(context.Background(), "ref")
	if err != nil {
		t.Fatalf("Scan: %v (want no error -- only one of two files failed)", err)
	}
	// Neither file matched (the one that "succeeded" reported clean),
	// so no findings either way -- this test is about the error being
	// nil despite one real per-file failure, not about findings content.
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}
