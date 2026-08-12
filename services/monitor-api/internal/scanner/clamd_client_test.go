package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// startFakeClamd starts a local TCP listener speaking just enough of
// clamd's INSTREAM protocol (https://docs.clamav.net/manual/Usage/Scanning.html#instream)
// for scanFileWithClamd's own tests: read the "zINSTREAM\0" handshake,
// then each 4-byte-big-endian-length-prefixed chunk until the
// zero-length terminator, concatenating the bytes received, then reply
// with whatever replyFor(received) returns (its own trailing NUL is
// added here, matching what a real clamd reply looks like). Returns the
// address to dial; the listener and every accepted connection are
// cleaned up via t.Cleanup.
func startFakeClamd(t *testing.T, replyFor func(received []byte) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed -- test is done
			}
			go func(conn net.Conn) {
				defer conn.Close()

				handshake := make([]byte, len("zINSTREAM\x00"))
				if _, err := io.ReadFull(conn, handshake); err != nil {
					return
				}

				var received []byte
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
					received = append(received, chunk...)
				}

				reply := replyFor(received) + "\x00"
				_, _ = conn.Write([]byte(reply))
			}(conn)
		}
	}()

	return ln.Addr().String()
}

// The temp dir doubles as the permitted artifact root for the calling
// test -- ClamAVScanner.Scan refuses paths outside it now (see
// ensureScannablePath). scanFileWithClamd itself is unaffected, since
// UnpackerScanner feeds it paths from its own extraction dir.
func writeTempFile(t *testing.T, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	enableLocalPaths(t, dir)
	path := filepath.Join(dir, "scan-target")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

func TestScanFileWithClamd_CleanFile(t *testing.T) {
	addr := startFakeClamd(t, func(received []byte) string {
		if string(received) != "hello world" {
			return "stream: UNEXPECTED_CONTENT FOUND"
		}
		return "stream: OK"
	})
	path := writeTempFile(t, []byte("hello world"))

	result, err := scanFileWithClamd(context.Background(), addr, path)
	if err != nil {
		t.Fatalf("scanFileWithClamd: %v", err)
	}
	if result.Found {
		t.Fatalf("result = %+v, want a clean (not found) result", result)
	}
}

func TestScanFileWithClamd_MalwareMatch(t *testing.T) {
	addr := startFakeClamd(t, func(received []byte) string {
		return "stream: Eicar-Test-Signature FOUND"
	})
	path := writeTempFile(t, []byte("fake eicar payload"))

	result, err := scanFileWithClamd(context.Background(), addr, path)
	if err != nil {
		t.Fatalf("scanFileWithClamd: %v", err)
	}
	if !result.Found {
		t.Fatalf("result = %+v, want Found=true", result)
	}
	// Matches the current (slightly surprising, but this is what it
	// actually does) behavior: Signature keeps clamd's "stream: " reply
	// prefix -- only the trailing " FOUND" is trimmed.
	if result.Signature != "stream: Eicar-Test-Signature" {
		t.Fatalf("signature = %q, want %q", result.Signature, "stream: Eicar-Test-Signature")
	}
}

// A file bigger than clamdChunkSize (4096 bytes) forces the INSTREAM
// loop to send more than one chunk -- this confirms the chunking itself
// reassembles correctly on the receiving end, not just that a
// single-chunk file round-trips.
func TestScanFileWithClamd_LargeFileSendsMultipleChunks(t *testing.T) {
	want := bytes.Repeat([]byte("A"), clamdChunkSize*3+123)
	var gotLen int
	addr := startFakeClamd(t, func(received []byte) string {
		gotLen = len(received)
		if !bytes.Equal(received, want) {
			return "stream: CONTENT_MISMATCH FOUND"
		}
		return "stream: OK"
	})
	path := writeTempFile(t, want)

	result, err := scanFileWithClamd(context.Background(), addr, path)
	if err != nil {
		t.Fatalf("scanFileWithClamd: %v", err)
	}
	if result.Found {
		t.Fatalf("result = %+v (server received %d of %d bytes) -- chunking did not reassemble correctly", result, gotLen, len(want))
	}
}

func TestScanFileWithClamd_AddrNotConfigured(t *testing.T) {
	path := writeTempFile(t, []byte("x"))
	_, err := scanFileWithClamd(context.Background(), "", path)
	if err == nil {
		t.Fatal("expected an error when addr is empty, got nil")
	}
}

func TestScanFileWithClamd_FileDoesNotExist(t *testing.T) {
	_, err := scanFileWithClamd(context.Background(), "127.0.0.1:1", filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected an error for a nonexistent path, got nil")
	}
}

// Binds a listener, then closes it immediately -- addr is a real,
// syntactically valid address that's guaranteed to have nothing
// listening on it, unlike a hardcoded port that might collide with
// something else running on the test machine.
func TestScanFileWithClamd_ConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	path := writeTempFile(t, []byte("x"))

	_, err = scanFileWithClamd(context.Background(), addr, path)
	if err == nil {
		t.Fatal("expected a connection error, got nil")
	}
}

func TestScanFileWithClamd_ContextAlreadyCanceled(t *testing.T) {
	path := writeTempFile(t, []byte("x"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := scanFileWithClamd(ctx, "127.0.0.1:9", path)
	if err == nil {
		t.Fatal("expected an error from an already-canceled context, got nil")
	}
}

// Regression test for the bug fixed alongside this test: a non-EOF read
// error (reading a directory, here -- Linux's read(2) fails with EISDIR
// rather than returning 0 bytes and EOF) used to be silently treated
// exactly like a normal end-of-file, sending whatever partial content
// had been read so far as if it were the whole file. See
// docs/tech-debt-audit.md, "In-process malware-scan fallback has zero
// unit tests" -- this is the concrete bug that finding's "zero unit
// tests" gap let ship unnoticed.
func TestScanFileWithClamd_NonEOFReadErrorIsNotSwallowed(t *testing.T) {
	addr := startFakeClamd(t, func(received []byte) string {
		return "stream: OK" // would report "clean" if the bug were still present
	})
	dir := t.TempDir()

	_, err := scanFileWithClamd(context.Background(), addr, dir)
	if err == nil {
		t.Fatal("expected an error reading a directory as if it were a file, got nil")
	}
}
