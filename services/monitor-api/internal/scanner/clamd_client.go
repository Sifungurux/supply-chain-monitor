package scanner

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// clamdChunkSize is the per-write chunk size for the INSTREAM protocol.
// Well under clamd's default StreamMaxLength.
const clamdChunkSize = 4096

// clamdResult is the outcome of streaming a single file to clamd.
type clamdResult struct {
	Found     bool
	Signature string
}

// scanFileWithClamd streams a single local file to a clamd instance
// over the INSTREAM protocol and reports whether it matched a
// signature. Shared by ClamAVScanner (standalone `file` artifacts) and
// UnpackerScanner (one call per file inside an unpacked image).
func scanFileWithClamd(ctx context.Context, addr, path string) (clamdResult, error) {
	if addr == "" {
		return clamdResult{}, fmt.Errorf("clamav address not configured")
	}

	f, err := os.Open(path)
	if err != nil {
		return clamdResult{}, fmt.Errorf("failed to open %q: %w", path, err)
	}
	defer f.Close()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return clamdResult{}, fmt.Errorf("failed to connect to clamav at %s: %w", addr, err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return clamdResult{}, fmt.Errorf("failed to start clamav stream: %w", err)
	}

	buf := make([]byte, clamdChunkSize)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			sizeHdr := make([]byte, 4)
			binary.BigEndian.PutUint32(sizeHdr, uint32(n))
			if _, werr := conn.Write(sizeHdr); werr != nil {
				return clamdResult{}, fmt.Errorf("failed writing chunk size: %w", werr)
			}
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return clamdResult{}, fmt.Errorf("failed writing chunk: %w", werr)
			}
		}
		if readErr == io.EOF {
			break
		}
		// A read error that isn't io.EOF (e.g. a real I/O failure
		// partway through, or path pointing at a directory rather than
		// a regular file) used to be treated exactly like a normal,
		// successful end-of-file here -- silently sending the
		// terminating zero-length chunk for whatever partial content
		// had already been streamed and reporting back whatever clamd
		// made of that truncated stream, typically "clean," rather than
		// surfacing that the read itself failed.
		if readErr != nil {
			return clamdResult{}, fmt.Errorf("failed reading %q: %w", path, readErr)
		}
	}
	// zero-length chunk signals end of stream
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return clamdResult{}, fmt.Errorf("failed writing terminating chunk: %w", err)
	}

	reply, err := bufio.NewReader(conn).ReadString('\x00')
	if err != nil {
		return clamdResult{}, fmt.Errorf("failed reading clamav reply: %w", err)
	}
	reply = strings.TrimRight(reply, "\x00\n ")

	if strings.Contains(reply, "FOUND") {
		return clamdResult{Found: true, Signature: strings.TrimSuffix(reply, " FOUND")}, nil
	}
	return clamdResult{}, nil
}
