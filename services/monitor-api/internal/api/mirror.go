package api

import (
	"context"
	"log/slog"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// mirrorTimeout bounds one `oras copy`. Generous because it is a full
// pull-and-push of every layer and single images in this project's own
// test corpus run past 1.5GB, and because the alternative to finishing
// is a partial push that the destination-digest check then rejects,
// leaving the artifact unmirrored anyway.
//
// Nothing waits on it: registration answers only after the copy, but
// runScan mirrors after the scan and outside the scan slot, so a copy
// that runs the full fifteen minutes blocks no scanning capacity.
const mirrorTimeout = 15 * time.Minute

// mirrorArtifact copies a into the in-cluster registry and rewrites its
// ref to the copy, keeping the original in SourceRef.
//
// Best-effort, exactly like resolveDigest: every failure path returns
// the artifact unchanged and still pointing at its original ref, so a
// registry that is unreachable, out of disk, or refusing the push
// degrades to "scans still pull from upstream" rather than to a
// registration or scan that fails. A failure here is logged and nowhere
// else.
//
// THE ONE CALLER THAT MATTERS IS THE SECOND ONE. Registration mirrors
// inline (see createArtifact), but bulk registration deliberately does
// not -- 500 refs in one HTTP request cannot each wait for a full image
// copy. runScan calls this too, which makes the existing
// sweep-registered CronJob the backfill for everything registration
// skipped: artifacts registered in bulk, artifacts that predate this
// feature entirely, and artifacts whose registration-time copy failed.
// One function, both callers, so there is no second definition of
// "mirrored" to drift.
func (h *handler) mirrorArtifact(ctx context.Context, a *artifact.Artifact) *artifact.Artifact {
	if h.mirror == nil || a == nil || a.SourceRef != "" {
		return a
	}
	// WithoutCancel, not the caller's context: a copy that is already
	// half-pushed should finish and be recorded even if the HTTP client
	// that triggered the registration has given up waiting, or the scan
	// that triggered the backfill is on a tighter budget than the copy
	// needs. mirrorTimeout is the only bound, the same reasoning runScan
	// applies to its own context.
	mctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mirrorTimeout)
	defer cancel()

	// The ref this copy is OF, captured before the copy runs -- the
	// Update below refuses to rewrite anything else. See there.
	from := a.Ref
	local, err := h.mirror.Mirror(mctx, from, a.Digest)
	if err != nil {
		slog.Warn("could not mirror artifact into the local registry (continuing with the original ref)",
			"artifact_id", a.ID, "ref", from, "err", err)
		return a
	}
	if local == "" {
		// Nothing to mirror: a local filesystem path, or a ref already
		// pointing at this registry. Not a failure -- see scanner.Mirror.
		return a
	}

	// One Update, both fields. A rewrite that persisted the new ref
	// without the old one would lose where the artifact came from with
	// no way back -- see Artifact.SourceRef and PostgresStore.Update.
	//
	// The guard is re-checked INSIDE the mutate func, against the row as
	// it is right now, because the check at the top of this function read
	// a snapshot taken before a copy that may have run for minutes.
	// Nothing serializes scans of one artifact (slots are per kind), so
	// two of them racing here would have the second overwrite SourceRef
	// with the FIRST one's mirrored ref -- destroying the public ref
	// permanently, which is the one thing this feature must never do.
	// Re-reading a.Ref in a local and comparing beats re-deriving it:
	// see the resolved-values-live-in-locals trap in PostgresStore.Update.
	mirrored := false
	updated, err := h.store.Update(a.ID, func(art *artifact.Artifact) {
		if art.SourceRef != "" || art.Ref != from {
			return
		}
		art.SourceRef = art.Ref
		art.Ref = local
		mirrored = true
	})
	if err != nil {
		slog.Error("mirrored the artifact but could not persist the rewritten ref",
			"artifact_id", a.ID, "ref", from, "mirror_ref", local, "err", err)
		return a
	}
	if !mirrored {
		slog.Info("another scan mirrored this artifact first -- keeping its rewrite",
			"artifact_id", updated.ID, "ref", updated.Ref, "source_ref", updated.SourceRef)
		return updated
	}
	slog.Info("mirrored artifact into the local registry",
		"artifact_id", updated.ID, "source_ref", updated.SourceRef, "ref", updated.Ref)
	return updated
}

// provenanceRef is the ref signature verification runs against: the
// ORIGINAL one when this artifact has been mirrored.
//
// cosign's classic signatures live at a sibling `sha256-<digest>.sig`
// TAG in the same repository, which is not an OCI referrer and so is not
// something `oras copy --recursive` brings along. Verifying the mirrored
// copy would therefore find no signature and conclude "unsigned" for
// every signed image in the fleet -- and per Artifact.Provenance's own
// comment, a badge flipping to unsigned is an alarm nobody can act on.
//
// Verifying the source is also the more correct answer independently of
// that: the signer signed THAT identity, and an attestation about
// `scm-registry/mirror/...` is not one anybody ever made.
//
// ponytail: the alternative is copying the .sig tag too and verifying
// locally. Worth doing only if scanning has to work with no egress at
// all -- until then this is three lines instead of a second copy path
// whose silent failure mode is a fleet-wide false alarm.
func provenanceRef(a *artifact.Artifact) string {
	if a.SourceRef != "" {
		return a.SourceRef
	}
	return a.Ref
}
