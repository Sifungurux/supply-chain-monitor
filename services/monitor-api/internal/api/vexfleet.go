package api

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

// maxFleetVEXArtifactIDs bounds how many artifact ids the response
// lists. Same reasoning and same shape as maxListLimit: the count is
// always exact, the enumeration is capped.
const maxFleetVEXArtifactIDs = 200

// uploadFleetVEX ingests an OpenVEX document that applies FLEET-WIDE
// rather than to one artifact: "CVE-2024-1234 does not apply to
// log4j-core 2.14.1 the way we build it, wherever it appears."
//
// The per-artifact endpoint (POST /artifacts/{id}/vex) has already been
// told which artifact it is about, so it ignores the document's
// `products` array entirely. This one has no such context, so products
// ARE the addressing: a statement that names no product matches
// nothing, deliberately -- the alternative reading, "applies to
// everything", would let one malformed document suppress the estate.
//
// Applied immediately to every matching artifact rather than waiting
// for their next scans, for the same reason uploadVEX applies its
// document immediately: the whole point of uploading one is to stop
// looking at findings you have already triaged.
//
// Parsed BEFORE it is stored, so an unparseable upload is a 400 that
// leaves previously-applied documents alone.
func (h *handler) uploadFleetVEX(w http.ResponseWriter, r *http.Request) {
	limitBody(w, r, maxVEXBytes)
	content, err := io.ReadAll(r.Body)
	if err != nil {
		writeBodyError(w, err, "failed to read request body (connection dropped): "+err.Error())
		return
	}
	if len(content) == 0 {
		writeError(w, http.StatusBadRequest, "VEX document body is empty")
		return
	}

	statements, err := scanner.ParseVEXProducts(content)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(statements) == 0 {
		writeError(w, http.StatusBadRequest, "no usable statements: every statement lacked a vulnerability id")
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}
	sum := sha256.Sum256(content)
	doc := artifact.FleetVEXDocument{
		ID:          hex.EncodeToString(sum[:]),
		ContentType: contentType,
		Content:     content,
		UploadedAt:  time.Now().UTC(),
	}
	if err := h.store.SaveFleetVEX(doc); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	applied, matched := h.applyFleetVEX(statements)

	// unmatched is the number an operator actually needs. A document
	// that stored fine and suppressed nothing is the common failure
	// here -- a purl that does not match how this fleet spells its
	// components -- and without this it looks identical to success.
	unmatched := 0
	for _, st := range statements {
		if len(st.Products) == 0 {
			unmatched++
		}
	}
	slog.Info("fleet VEX document applied",
		"document_id", doc.ID, "statements", len(statements),
		"artifacts_updated", applied, "statements_naming_no_product", unmatched)

	// The id list is CAPPED and the true total is reported separately,
	// the same contract SearchComponents uses. A component-purl match
	// legitimately spans the whole estate, and an unbounded array of
	// ids would make the response size a function of how many artifacts
	// exist -- which is exactly the shape maxListLimit exists to stop.
	// artifacts_updated is the number that matters; the ids are a
	// convenience for the common small case.
	truncated := false
	if len(matched) > maxFleetVEXArtifactIDs {
		matched = matched[:maxFleetVEXArtifactIDs]
		truncated = true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":                       "applied",
		"document_id":                  doc.ID,
		"statements":                   len(statements),
		"artifacts_updated":            applied,
		"statements_naming_no_product": unmatched,
		"artifacts":                    matched,
		// Stated rather than left to be inferred from a short array:
		// silent truncation reads as "these are all of them".
		"artifacts_truncated": truncated,
	})
}

// applyFleetVEX applies statements to every artifact any of them
// matches, and returns how many artifacts changed plus their ids.
//
// Fans out per artifact rather than per statement so each artifact is
// updated ONCE, with every statement that applies to it: two statements
// matching the same artifact through different products would otherwise
// be two Update calls, and the second would re-run MergeFindings over
// the result of the first for no reason.
func (h *handler) applyFleetVEX(statements []artifact.ProductVEXStatement) (int, []string) {
	byArtifact := map[string]map[string]artifact.VEXStatement{}
	for _, st := range statements {
		for _, id := range h.artifactsMatching(st.Products) {
			if byArtifact[id] == nil {
				byArtifact[id] = map[string]artifact.VEXStatement{}
			}
			// Last statement wins for a given vulnerability within one
			// document, matching VEXByID's own rule for the
			// per-artifact path.
			byArtifact[id][st.VulnID] = st.VEXStatement
		}
	}

	now := time.Now().UTC()
	updated := make([]string, 0, len(byArtifact))
	for id, vex := range byArtifact {
		// The per-artifact document still wins: it is the more specific
		// claim about this artifact, and an operator who assessed THIS
		// image must not be overridden by a fleet-wide statement about
		// a package it happens to contain.
		for vulnID, st := range h.vexFor(id) {
			vex[vulnID] = st
		}
		if _, err := h.store.Update(id, func(art *artifact.Artifact) {
			applyVEXToEveryBucket(art, vex, now)
		}); err != nil {
			// One artifact failing must not abandon the rest: a fleet
			// document legitimately spans hundreds, and stopping at the
			// first deleted-mid-request artifact would apply the
			// document to an arbitrary prefix of them.
			slog.Warn("could not apply fleet VEX to artifact (continuing)", "artifact_id", id, "err", err)
			continue
		}
		updated = append(updated, id)
	}
	sort.Strings(updated)
	return len(updated), updated
}

// artifactsMatching resolves product identifiers to artifact ids,
// through the two arms that mean genuinely different things:
//
//   - BY DIGEST, e.g. "sha256:abc..." or "pkg:oci/app@sha256:abc...".
//     The product IS the artifact. Narrow by construction.
//   - BY COMPONENT PURL, e.g. "pkg:maven/.../log4j-core@2.14.1".
//     The product is something the artifact CONTAINS, so this matches
//     every artifact shipping it -- potentially the whole estate from
//     one line of one document. That breadth is the point of a fleet
//     document, but it is also why the handler logs and returns the
//     artifact count rather than reporting a bare "applied".
func (h *handler) artifactsMatching(products []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}

	for _, product := range products {
		if digest := digestFromProduct(product); digest != "" {
			if a, err := h.store.FindByDigest(digest); err != nil {
				slog.Warn("fleet VEX: digest lookup failed (skipping this product)", "product", product, "err", err)
			} else if a != nil {
				add(a.ID)
			}
		}
		// Not an else: "pkg:oci/app@sha256:..." can legitimately be both
		// an artifact's digest AND a purl some other artifact lists as a
		// base image in its SBOM, and both readings are correct.
		if strings.HasPrefix(product, "pkg:") {
			arts, err := h.store.FindByComponentPURL(product)
			if err != nil {
				slog.Warn("fleet VEX: component lookup failed (skipping this product)", "product", product, "err", err)
				continue
			}
			for _, a := range arts {
				add(a.ID)
			}
		}
	}
	return out
}

// digestFromProduct pulls an OCI content digest out of a product
// identifier, or returns "" if it holds none.
//
// Accepts the bare form ("sha256:abc...") and the purl-qualified one
// ("pkg:oci/app@sha256:abc..."), because both turn up: `vexctl` writes
// the purl, while documents written by hand and the `hashes` map both
// tend to carry the bare digest (see vexProduct.identifiers, which
// normalizes hashes into this same shape).
func digestFromProduct(product string) string {
	product = strings.TrimSpace(product)
	if i := strings.LastIndex(product, "@sha256:"); i >= 0 {
		product = product[i+1:]
	}
	if !strings.HasPrefix(product, "sha256:") {
		return ""
	}
	// Anything after a "?" is a purl qualifier
	// ("...@sha256:abc?arch=amd64"), never part of the digest.
	if i := strings.IndexAny(product, "?#"); i >= 0 {
		product = product[:i]
	}
	return strings.ToLower(product)
}

// applyVEXToEveryBucket is uploadVEX's five-bucket merge, shared so the
// fleet path cannot drift from the per-artifact one. detectFixed is
// false on all five for the same reason it is there: nothing was
// reported this round, and this must never read as "a scan found
// nothing, so everything is fixed."
func applyVEXToEveryBucket(art *artifact.Artifact, vex map[string]artifact.VEXStatement, now time.Time) {
	art.CVEFindings = artifact.MergeFindings(art.CVEFindings, nil, now, false, vex)
	art.MalwareFindings = artifact.MergeFindings(art.MalwareFindings, nil, now, false, vex)
	art.MisconfigFindings = artifact.MergeFindings(art.MisconfigFindings, nil, now, false, vex)
	art.SecretFindings = artifact.MergeFindings(art.SecretFindings, nil, now, false, vex)
	art.OtherFindings = artifact.MergeFindings(art.OtherFindings, nil, now, false, vex)
}

// fleetVEXFor returns the fleet statements that apply to ONE artifact,
// keyed by vulnerability id and ready to hand to MergeFindings.
//
// Called on every scan (see runScan), which is why it takes the
// artifact's component purls in ONE query rather than asking the store
// per product identifier.
//
// digest is passed in rather than read off a.Digest, and that is not
// defensive: runScan resolves the digest into a LOCAL variable and only
// writes it onto the artifact inside the store.Update that comes
// afterwards, so on the first scan of a freshly registered artifact
// a.Digest is still empty. Reading it here would mean a fleet document
// naming that artifact by digest silently did nothing until the NEXT
// scan -- see TestFleetVEX_MatchesTheDigestResolvedByThisVeryScan,
// which fails on exactly that.
//
// ponytail: every fleet document is read and parsed per scan, with no
// cache. Deliberate at this scale, and the ceiling is BYTES rather than
// document count -- ListFleetVEX selects the full content column, so
// the cost is (total stored bytes x scans in flight), and at
// maxVEXBytes each a handful of documents is already tens of MB per
// scan. Against a scan that spends seconds to minutes in trivy/grype
// that is still noise, which is why it stays uncached; a process-local
// cache would also go stale on the OTHER replica the moment somebody
// uploaded a document (this runs two).
//
// Measure total bytes in vex_documents, not the row count, before
// deciding this needs fixing. The upgrade is a short-TTL cache keyed on
// row count plus newest uploaded_at, NOT a lifetime one.
//
// Best-effort in the same spirit as vexFor: a document that cannot be
// read or parsed drops out with a log line rather than failing the
// scan. Suppression already stamped onto findings persists regardless
// (see MergeFindings), so this can only fail to apply a statement to a
// finding seen for the first time this round.
func (h *handler) fleetVEXFor(a *artifact.Artifact, digest string) map[string]artifact.VEXStatement {
	docs, err := h.store.ListFleetVEX()
	if err != nil {
		slog.Warn("could not list fleet VEX documents (continuing without them)", "artifact_id", a.ID, "err", err)
		return nil
	}
	if len(docs) == 0 {
		return nil
	}

	purls, err := h.store.ComponentPURLs(a.ID)
	if err != nil {
		// Not fatal: the digest arm below still works, so a fleet
		// document naming this artifact directly still applies.
		slog.Warn("could not read component purls for fleet VEX matching", "artifact_id", a.ID, "err", err)
	}
	has := make(map[string]bool, len(purls))
	for _, p := range purls {
		has[p] = true
	}

	out := map[string]artifact.VEXStatement{}
	// Oldest first, so that within the fleet set a NEWER document wins
	// for the same vulnerability. ListFleetVEX returns newest first, so
	// this walks it backwards.
	for i := len(docs) - 1; i >= 0; i-- {
		statements, err := scanner.ParseVEXProducts(docs[i].Content)
		if err != nil {
			slog.Warn("a stored fleet VEX document no longer parses (continuing without it)", "document_id", docs[i].ID, "err", err)
			continue
		}
		for _, st := range statements {
			if statementMatches(st.Products, digest, has) {
				out[st.VulnID] = st.VEXStatement
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// statementMatches is artifactsMatching in the other direction: given
// one artifact already in hand, does this statement name it? Same two
// arms -- the artifact's digest, or a purl in its inventory -- answered
// locally against data the caller already loaded, with no query per
// product.
func statementMatches(products []string, digest string, hasPURL map[string]bool) bool {
	digest = strings.ToLower(strings.TrimSpace(digest))
	for _, product := range products {
		if digest != "" && digestFromProduct(product) == digest {
			return true
		}
		if hasPURL[product] {
			return true
		}
	}
	return false
}
