package scanner

import "github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"

// WorkerResult is the JSON shape printed to stdout by `monitor-api
// scan-worker` (see main.go's runScanWorker) and read back by
// IsolatedUnpackerScanner (isolated_unpacker.go) from the completed
// Kubernetes Job's pod logs. Defined here, not in package main, since
// both main.go and isolated_unpacker.go need it and main isn't
// importable.
//
// Error is a string, not the error interface, so it survives a JSON
// round-trip -- the worker process and the process reading its output
// are never the same Go process, so there's no way to hand back a real
// error value.
type WorkerResult struct {
	Findings []artifact.Finding `json:"findings"`
	Error    string             `json:"error,omitempty"`
}
