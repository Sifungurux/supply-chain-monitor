package api

import (
	"context"
	"log/slog"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
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
		// pointing at this registry. Not a failure -- see scanner.Mirror
		// -- but it does have to be RECORDED, by setting SourceRef to the
		// ref itself.
		//
		// Otherwise "source_ref is empty" would mean two different things
		// -- "not mirrored yet" and "never mirrorable" -- and the sweep's
		// backfill (main.go's SWEEP_MIRROR_BACKFILL) would re-scan every
		// local-path and already-local artifact on every run, forever,
		// looking for a copy that is never going to happen. With this,
		// an empty SourceRef means exactly "mirroring has not been
		// settled for this artifact yet" and the backfill converges.
		local = from
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
	switch {
	case !mirrored:
		slog.Info("another scan mirrored this artifact first -- keeping its rewrite",
			"artifact_id", updated.ID, "ref", updated.Ref, "source_ref", updated.SourceRef)
	case updated.Ref == updated.SourceRef:
		slog.Info("artifact needs no mirror (already local, or not a registry ref) -- recorded so the backfill stops revisiting it",
			"artifact_id", updated.ID, "ref", updated.Ref)
	default:
		slog.Info("mirrored artifact into the local registry",
			"artifact_id", updated.ID, "source_ref", updated.SourceRef, "ref", updated.Ref)
	}
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

// provenanceRefs is provenanceRef plus the mirrored copy, in the order
// to try them.
//
// The comment above is right about cosign's CLASSIC signatures: a
// sibling `sha256-<digest>.sig` TAG is not a referrer and `oras copy
// --recursive` leaves it behind. It is NOT right about every signature.
// A modern Sigstore bundle -- what actions/attest-build-provenance
// pushes, media type
// application/vnd.dev.sigstore.bundle.v0.3+json -- is attached as an OCI
// REFERRER, and --recursive carries referrers; mirror.go's own copyArgs
// comment says so.
//
// Measured rather than assumed (CI run 37614709186): this project's own
// image was copied with copyArgs' exact flags into a local registry:2,
// the referrer arrived, and `cosign verify-attestation` against the COPY
// exited 0 -- "claims validated", "transparency log verified offline".
// It works because an attestation is bound to the DIGEST, not to a
// repository path: the decoded subject still named the ghcr repository
// while verification ran against localhost:5000.
//
// So for a mirrored artifact whose signature travelled, the upstream
// round-trip every scan makes is unnecessary -- and upstream is the
// least reliable participant in a scan (anonymous pull limits are the
// single most common cause of a scan failing here).
//
// THE ORDER IS THE SAFETY PROPERTY. The mirror is tried first and the
// source is tried LAST, so the final attempt is always exactly what this
// code did before. A caller that keeps the first VERIFIED result and
// otherwise the last one cannot turn a signed artifact into an unsigned
// one, whatever the local registry does -- which is the failure mode
// provenanceRef's comment calls a fleet-wide false alarm nobody can act
// on.
//
// Cost: an artifact that is genuinely unsigned is verified twice. Those
// are overwhelmingly third-party images, which cosign.refPrefixes
// already excludes from being checked at all.
func provenanceRefs(a *artifact.Artifact) []string {
	source := provenanceRef(a)
	// Not mirrored, or mirrored to itself (a local path, or a ref
	// already in this registry -- see the backfill's second case).
	if a.Ref == "" || a.Ref == source {
		return []string{source}
	}
	return []string{a.Ref, source}
}

// scanProvenanceRefs verifies against each ref in turn and keeps the
// first VERIFIED answer, falling back to the LAST attempt's result.
//
// Those two rules together are what make trying the mirror free of
// risk. provenanceRefs always puts the original ref last, so the
// fallback is byte-for-byte the verdict this code produced before the
// mirror was ever consulted -- an unreachable local registry, a copy
// whose referrer did not travel, a cosign error, all land on exactly
// the old answer rather than on "unsigned".
//
// It cannot UPGRADE a verdict either: a VERIFIED from the mirror is a
// real verification of the same digest against the same identity and
// trust root, not a shortcut around one.
func scanProvenanceRefs(ctx context.Context, s scanner.ProvenanceScanner, refs []string) ([]artifact.Finding, string, string, error) {
	var findings []artifact.Finding
	var provenance, trustRoot string
	var err error

	for i, ref := range refs {
		findings, provenance, trustRoot, err = s.ScanProvenance(ctx, ref)
		if provenance == artifact.ProvenanceVerified {
			if i > 0 {
				// Only interesting when the mirror did NOT answer: it
				// means the copy is missing something the original has,
				// and the upstream round-trip is still being paid.
				slog.Info("provenance verified against the original ref after the mirrored copy did not",
					"ref", ref, "tried_first", refs[0])
			}
			return findings, provenance, trustRoot, err
		}
		if i < len(refs)-1 {
			slog.Debug("provenance not verified against this ref, trying the next",
				"ref", ref, "provenance", provenance, "err", err)
		}
	}
	return findings, provenance, trustRoot, err
}
