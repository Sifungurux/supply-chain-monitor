package artifact

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Store is the artifact persistence interface. MemStore (below) is a
// zero-dependency in-memory implementation used by this package's own
// unit tests and internal/api's handler tests, so those stay fast and
// hermetic. PostgresStore (postgres_store.go) is the backend main.go
// actually wires up in production -- see docs/architecture.md for why
// the in-memory store was replaced.
type Store interface {
	Create(ref string, t Type) (*Artifact, error)
	Get(id string) (*Artifact, error)
	List() ([]*Artifact, error)
	// ListPage returns one page of artifacts (newest first) plus the
	// total number matching the filters -- the total, not the page
	// length, so a caller can render "showing 50 of 812" and build
	// next/prev links (see internal/api's listArtifacts). An empty
	// statusFilter/typeFilter means "don't filter on that column".
	//
	// List() is kept alongside this deliberately: it's what the
	// package's own tests and the paging-agnostic callers still use.
	// Callers must pass limit >= 1 and offset >= 0 -- validating and
	// bounding those is the HTTP layer's job (see maxListLimit), not
	// something each Store re-implements.
	// ListPage is List plus filtering, paging and a total count.
	// searchFilter is a case-insensitive SUBSTRING match across ref,
	// source_ref, digest, maintainer team/email and current stage -- the
	// fields somebody actually remembers an artifact by. Empty means no
	// search, not "match nothing".
	ListPage(limit, offset int, statusFilter, typeFilter, searchFilter string) ([]*Artifact, int, error)
	Update(id string, mutate func(*Artifact)) (*Artifact, error)
	// FindByFindingID returns every artifact where findingID (e.g.
	// "CVE-2024-1234") is ACTIVE, in any of the five buckets -- the
	// concrete payoff of normalizing findings into their own table (see
	// docs/architecture.md, "Normalizing findings and stage history into
	// their own tables"). MemStore answers this with a linear scan;
	// PostgresStore uses the findings.finding_id index.
	//
	// "Active" means neither fixed nor VEX-suppressed (Finding.IsActive)
	// -- this endpoint has always described itself as "every artifact
	// still affected", and an artifact that patched the CVE last month,
	// or formally assessed it as not applying, is not still affected.
	// It's also the population SearchFindings counts, so the number a
	// search shows and the list a caller gets are the same set rather
	// than differing by however many were suppressed.
	FindByFindingID(findingID string) ([]*Artifact, error)
	// SearchFindings finds DISTINCT finding ids whose id or title
	// contains query (case-insensitive substring), each with the number
	// of artifacts where it's active -- the discovery step that makes
	// FindByFindingID usable by someone who knows "log4j" but not
	// "CVE-2021-44228". Same contract as SearchComponents: at most limit
	// matches plus the true total, ordered by artifact count descending
	// then id ascending.
	SearchFindings(query string, limit int) ([]FindingMatch, int, error)
	// FindByDigest returns the first-registered artifact matching
	// digest, or (nil, nil) if none exists yet -- "not found" is the
	// expected, common case (most registrations are the first time
	// their content has been seen), not an error condition. Never
	// matches an empty digest: callers should only ever call this with
	// a digest they've actually resolved (see internal/api/artifacts.go's
	// duplicate-registration check), not as a way to enumerate
	// not-yet-resolved artifacts.
	FindByDigest(digest string) (*Artifact, error)
	// FindByRef returns the first-registered artifact with this exact
	// ref, or (nil, nil) if none exists -- the same "not found is the
	// expected case" convention FindByDigest uses.
	//
	// This exists as the fallback for registrations whose digest could
	// not be resolved. Dedup normally keys on digest, which is the
	// right key: a mutable tag can legitimately point at different
	// content over time, and only the digest can tell those apart. But
	// resolution fails routinely -- a dead or moved ref, a rate-limited
	// registry, or a ref that is a local filesystem path and never had
	// a digest to resolve -- and with no digest the dedup check was
	// skipped entirely, so every re-registration created a brand new
	// artifact. Measured on a live deployment: 5 unresolvable refs
	// registered across ~9 runs left 43 duplicate rows, every one with
	// digest = ''.
	//
	// Callers must only consult this when their own resolution came
	// back empty -- see internal/api/artifacts.go. When a digest DOES
	// resolve it is strictly better evidence and wins outright.
	FindByRef(ref string) (*Artifact, error)
	// Count returns how many artifacts exist. Deliberately not
	// List()/ListPage(): the one caller is a quota check on the
	// registration path (see internal/api's MaxArtifacts), which runs
	// on every registration and needs a number, not rows -- ListPage
	// would fetch an artifact and batch-load its findings and stage
	// history to answer it.
	Count() (int, error)
	// Delete permanently removes an artifact and everything recorded
	// against it (stage history, findings, scan errors) -- there is no
	// undo and no soft-delete/archive semantics (see
	// docs/architecture.md, "Deleting an artifact"). Returns an error
	// if id doesn't exist, the same "not found" convention Get/Update
	// already use.
	Delete(id string) error
	// SaveDocument stores (overwriting any existing document of the
	// same kind) a generated SBOM/SARIF document against an artifact --
	// see Document's own comment for why this is a separate call rather
	// than a field Update's mutate callback can set. Returns an error
	// if artifactID doesn't exist.
	SaveDocument(artifactID, kind, contentType string, content []byte) error
	// GetDocument returns (nil, nil) if no document of that kind has
	// been captured yet -- e.g. before the first scan runs, or generation
	// failed (best-effort, see Document's comment) -- the same "not
	// found is the expected, common case" convention FindByDigest above
	// already uses.
	GetDocument(artifactID, kind string) (*Document, error)
	// SaveComponents REPLACES this artifact's component inventory with
	// the one parsed from its most recently uploaded SBOM (see
	// scanner.ParseSBOMComponents). Replace, not append, deliberately:
	// SaveDocument already overwrites the previous SBOM rather than
	// keeping history, so appending here would leave the components of
	// every SBOM this artifact ever had on record, and
	// FindByComponentPURL would keep returning it for a package a
	// rebuild removed months ago. An empty slice therefore means "this
	// artifact now contains nothing we could identify", which is a
	// meaningful statement, not a no-op.
	SaveComponents(artifactID string, components []Component) error
	// FindByComponentPURL returns every artifact whose inventory
	// contains this exact purl -- "which of our images ship
	// log4j-core 2.14.1", the component-level counterpart to
	// FindByFindingID's "which are affected by CVE-X". Exact match, not
	// a prefix: that's what the indexed column supports, and "any
	// version of this package" is a different question than this one
	// answers. Returns an empty slice (not an error) when nothing
	// matches, exactly like FindByFindingID.
	FindByComponentPURL(purl string) ([]*Artifact, error)
	// ComponentPURLs returns just the purls in one artifact's
	// inventory. The inverse direction of FindByComponentPURL, and it
	// exists for the scan path specifically: matching fleet VEX
	// products against an artifact needs "what does THIS artifact
	// contain", and answering that with one FindByComponentPURL call
	// per product identifier would be a query per product on every
	// scan. This is one query, and the matching is then a set lookup.
	//
	// Empty slice, not an error, for an artifact with no indexed SBOM
	// -- much the most common case before the first scan.
	ComponentPURLs(artifactID string) ([]string, error)
	// SaveFleetVEX stores an OpenVEX document that applies fleet-wide
	// rather than to one artifact. Keyed by content hash, so
	// re-uploading the same document replaces the row rather than
	// adding a second one saying the same thing.
	//
	// Named SaveFleetVEX, not SaveVEXDocument, because SaveDocument
	// above already stores per-artifact VEX under kind "vex" and the
	// two are genuinely different things -- see FleetVEXDocument.
	SaveFleetVEX(doc FleetVEXDocument) error
	// ListFleetVEX returns every stored fleet document, newest first.
	// The whole set: callers parse them and narrow by product, which
	// cannot be pushed into the query because the match is against
	// digests and component purls the document names, not against
	// anything indexed on this table.
	ListFleetVEX() ([]FleetVEXDocument, error)
	// SearchComponents finds DISTINCT packages whose name or purl
	// contains query (case-insensitive substring), each with the number
	// of artifacts containing it -- the discovery step that makes
	// FindByComponentPURL's exact matching usable by a human, who knows
	// "openssl" and not
	// "pkg:apk/alpine/openssl@3.1.4-r6?arch=x86_64&distro=3.19.1".
	//
	// Returns at most limit matches plus the TOTAL number that matched,
	// so a caller can say "showing 200 of 4,312" rather than silently
	// truncating. Ordered by artifact count descending then purl
	// ascending: the package in the most artifacts is the one most
	// likely meant, and the tie-break keeps the order stable between
	// backends and between calls.
	SearchComponents(query string, limit int) ([]ComponentMatch, int, error)
	// FindByLicense returns every artifact containing a component
	// licensed under this exact identifier -- the ?license= half of GET
	// /api/v1/components. EXACT and case-insensitive against one entry
	// of a component's comma-joined list, never a substring of the
	// whole: "GPL-3.0-only" must not match "LGPL-3.0-only", and must
	// not match inside "MIT OR AGPL-3.0-only" where the OR is the
	// permissive escape. Empty slice when nothing matches, like
	// FindByComponentPURL.
	FindByLicense(license string) ([]*Artifact, error)
	// Stats returns fleet-wide counts in one call -- see Stats itself
	// for what each map means. The point is that it aggregates in the
	// backend: the dashboard holds one page of artifacts and its summary
	// cards are about all of them, so every one of these numbers was
	// either wrong or unavailable before this existed.
	//
	// This is the only method here that takes a context, which is a wart
	// -- every other one calls context.Background() internally (see
	// PostgresStore). It takes one anyway because it's the only method
	// that scans two whole tables to answer, and its only caller is a
	// handler the dashboard polls every 10 seconds: a client that hung
	// up should cancel the query rather than have Postgres finish
	// counting for nobody. The rest of this interface should grow a
	// context the same way eventually; that's a mechanical change worth
	// doing on its own rather than smuggling in here.
	Stats(ctx context.Context) (Stats, error)
	// CountOlderThan and DeleteOlderThan implement age-based retention
	// (`monitor-api prune`, see main.go): "older" means UpdatedAt is
	// before cutoff, i.e. nothing has touched this artifact since --
	// not CreatedAt, because a long-lived artifact that is still being
	// re-scanned and re-staged is in active use however old it is.
	//
	// Both take a limit, and DeleteOlderThan deletes the OLDEST first,
	// so a first run against a large backlog does bounded work and the
	// next run continues rather than one statement locking the table
	// for a very long time. Same batching instinct as SWEEP_BATCH_SIZE.
	//
	// Counting is separate from deleting so a dry run costs nothing and
	// risks nothing -- this deletes an artifact's findings, stage
	// history, documents and components with it (Delete's cascade, see
	// above) and there is no undo, so "show me what this would remove"
	// has to be answerable without removing it.
	//
	// Deliberately no context parameter, matching the other seventeen
	// methods here -- see Stats' own comment. Two of nineteen taking a
	// context is a worse state than one, and the fix is the mechanical
	// pass that converts all of them.
	// ComponentSnapshots returns the scan timestamps this artifact has a
	// component snapshot for, NEWEST FIRST, at most limit of them. Empty
	// for an artifact whose SBOM has never been indexed, which is the
	// common case rather than an error.
	//
	// Timestamps rather than the snapshots themselves: the diff endpoint
	// needs to pick two (the latest pair, or the ones ?from=/?to= name)
	// before it wants any component rows, and a real image's inventory
	// runs to thousands of them per snapshot.
	ComponentSnapshots(artifactID string, limit int) ([]time.Time, error)
	// ComponentsAt returns the inventory recorded at exactly this scan
	// timestamp -- one of the values ComponentSnapshots handed back.
	// An unknown timestamp is an empty slice, not an error: the caller
	// asking for a snapshot that has since aged out of the retained
	// window (MaxComponentSnapshots) is a normal race, not a fault.
	ComponentsAt(artifactID string, scanAt time.Time) ([]Component, error)
	// AcquireScanSlots takes one slot per requested kind, all or
	// nothing, and reaps abandoned slots while it is in there. This is
	// what bounds concurrent scanning ACROSS REPLICAS -- the cap used to
	// be a buffered channel in one process, so two monitor-api pods each
	// allowed a full SCAN_CONCURRENCY and the real limit was silently
	// double what was configured.
	//
	// Reaping is part of acquisition rather than a separate sweep: a pod
	// killed between acquiring and releasing leaves its rows behind, and
	// the only moment anyone cares is when somebody else wants a slot.
	// A background reaper would be a second moving part to schedule and
	// monitor for a job that has a natural trigger.
	AcquireScanSlots(req ScanSlotRequest) (ScanSlotResult, error)
	// ReleaseScanSlots frees everything AcquireScanSlots took under this
	// holder. Safe to call for a holder that has nothing (a scan
	// rejected before it started, or slots already reaped), which is
	// what lets callers release unconditionally on every path.
	ReleaseScanSlots(holderID string) error

	// CreateScanToken/ConsumeScanToken/DeleteScanTokens back the
	// per-Job upload credential that replaced handing scan workers the
	// master API key (report S3). Only the SHA-256 of a token is ever
	// stored.
	//
	// ConsumeScanToken is scoped to one artifact and one document kind,
	// and each kind is usable once -- so a compromised worker can
	// upload one SBOM and one SARIF for the artifact it was already
	// scanning, and nothing else.
	CreateScanToken(artifactID, tokenHash string, expiresAt time.Time) error
	ConsumeScanToken(tokenHash, artifactID, kind string) (bool, error)
	DeleteScanTokens(artifactID string) error
	// CountStaleScans returns how many artifacts were last scanned
	// BEFORE cutoff -- the "not scanned recently" number behind the
	// dashboard's staleness warning.
	//
	// Artifacts that have NEVER been scanned are deliberately excluded.
	// A null LastScanAt is not infinitely old, it is a different state
	// with its own handling: those sit at status "registered" and the
	// sweep CronJob already picks them up. Counting them here would
	// double-report them and, worse, the dashboard computes its
	// per-artifact badge from the same field in JavaScript -- where a
	// null date compares as older than any cutoff, so the count and the
	// visible badges would disagree and one of them would look broken.
	//
	// Keys on LastScanAt, which is set when a scan COMPLETES, including
	// one that failed. So an artifact failing every scan stays "fresh"
	// here forever; LastScanFailureReason is the signal for that case,
	// not this one.
	// KEV/EPSS enrichment (internal/scanner's Enricher). Kept on the
	// Store because the feeds are shared state every replica and the
	// refresh CronJob read and write -- see PostgresStore's own comment
	// on why they live in the database rather than on a shared volume.
	ReplaceEnrichment(kev []string, epss map[string]float64, at time.Time) error
	LookupEnrichment(cveIDs []string) (map[string]Enrichment, error)
	EnrichmentStatus() (EnrichmentStatus, error)

	CountStaleScans(cutoff time.Time) (int, error)
	CountOlderThan(cutoff time.Time) (int, error)
	DeleteOlderThan(cutoff time.Time, limit int) (int, error)
}

// MemStore is a thread-safe, in-memory Store implementation.
//
// This used to be the only Store this service had ("v1 stub, no
// external dependencies"). It's kept around now purely as a fast,
// hermetic backend for tests -- production always uses PostgresStore.
// MaxComponentSnapshots bounds how many per-scan component snapshots
// each artifact keeps (see SaveComponents). Every scan of a real image
// writes another few thousand rows, so this is unbounded growth without
// a cap -- and the question the history answers ("what changed?") is
// asked about recent scans, not about the hundredth one back.
const MaxComponentSnapshots = 10

type MemStore struct {
	scanTokens map[string]*scanToken
	mu         sync.RWMutex
	data       map[string]*Artifact
	// documents is keyed by artifact ID then kind (DocumentKindSBOM/
	// DocumentKindSARIF) -- a plain nested map is enough here since
	// MemStore only ever backs tests, never production (see the type's
	// own comment).
	documents map[string]map[string]*Document
	// components is keyed by artifact ID. Same reasoning as documents:
	// a map is enough for a test backend, where PostgresStore has a real
	// table with an index on purl.
	components map[string][]Component
	// enrichment mirrors PostgresStore's cve_enrichment/enrichment_feeds
	// tables, keyed by upper-cased CVE id.
	enrichment       map[string]Enrichment
	enrichmentStatus EnrichmentStatus
	// componentHistory is the per-scan snapshot log behind the diff
	// endpoint, oldest first, capped at MaxComponentSnapshots. Mirrors
	// PostgresStore's components_history table.
	componentHistory map[string][]componentSnapshot
	// fleetVEX mirrors PostgresStore's vex_documents table, keyed by
	// the document's content hash so a re-upload replaces rather than
	// accumulates -- the same idempotence the real table gets from its
	// primary key.
	fleetVEX map[string]FleetVEXDocument
	// scanSlots is the process-local equivalent of PostgresStore's
	// scan_slots table, keyed by holder id. Process-local is the honest
	// implementation for a store that is itself process-local: it gives
	// every handler test exactly the cap semantics it had when this was
	// a buffered channel, while leaving internal/api with a single code
	// path instead of one per backend.
	scanSlots map[string][]scanSlot
}

type scanSlot struct {
	kind       string
	acquiredAt time.Time
}

// componentSnapshot is one artifact's inventory as of one scan.
// Unexported: the Store interface hands out timestamps and components
// separately, so nothing outside this file needs the pairing.
type componentSnapshot struct {
	scanAt     time.Time
	components []Component
}

func NewMemStore() *MemStore {
	return &MemStore{
		data:             make(map[string]*Artifact),
		documents:        make(map[string]map[string]*Document),
		components:       make(map[string][]Component),
		componentHistory: make(map[string][]componentSnapshot),
		scanSlots:        make(map[string][]scanSlot),
		fleetVEX:         make(map[string]FleetVEXDocument),
	}
}

func (s *MemStore) ComponentPURLs(artifactID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.components[artifactID]))
	for _, c := range s.components[artifactID] {
		if c.PURL != "" {
			out = append(out, c.PURL)
		}
	}
	return out, nil
}

func (s *MemStore) SaveFleetVEX(doc FleetVEXDocument) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fleetVEX == nil {
		s.fleetVEX = make(map[string]FleetVEXDocument)
	}
	s.fleetVEX[doc.ID] = doc
	return nil
}

func (s *MemStore) ListFleetVEX() ([]FleetVEXDocument, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]FleetVEXDocument, 0, len(s.fleetVEX))
	for _, doc := range s.fleetVEX {
		out = append(out, doc)
	}
	// Newest first, with the content hash as the tie-break: two
	// documents uploaded in the same instant is routine in tests (see
	// the clock-granularity note in store_test.go's mustCreateStore),
	// and an unstable order here would make any assertion over the list
	// flaky for reasons that have nothing to do with VEX.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].UploadedAt.Equal(out[j].UploadedAt) {
			return out[i].UploadedAt.After(out[j].UploadedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// newID generates the random hex artifact ID used by every Store
// implementation, so IDs look the same regardless of backend.
func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// copyArtifact returns a snapshot callers can read without holding
// MemStore's lock. Get/List/Create/Update all hand out one of these
// rather than the pointer they store, so a caller reading an artifact
// can never observe a concurrent Update tearing its fields -- which is
// exactly what happens now that scans run in a background goroutine
// while the API keeps serving reads of the same artifact.
//
// PostgresStore has always had these semantics for free (every read
// scans a fresh struct), so this makes the two implementations agree
// rather than leaving MemStore subtly racier than the backend it
// stands in for.
//
// The slices are copied too, not just the struct: Update's mutate
// callbacks append to StageHistory, and an append that fits in spare
// capacity would otherwise write into an array a previous caller is
// still reading.
func copyArtifact(a *Artifact) *Artifact {
	if a == nil {
		return nil
	}
	out := *a
	out.StageHistory = append([]StageEvent(nil), a.StageHistory...)
	out.CVEFindings = append([]Finding(nil), a.CVEFindings...)
	out.MalwareFindings = append([]Finding(nil), a.MalwareFindings...)
	out.MisconfigFindings = append([]Finding(nil), a.MisconfigFindings...)
	out.SecretFindings = append([]Finding(nil), a.SecretFindings...)
	out.OtherFindings = append([]Finding(nil), a.OtherFindings...)
	out.LastScanErrors = append([]string(nil), a.LastScanErrors...)
	return &out
}

func (s *MemStore) Create(ref string, t Type) (*Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	a := &Artifact{
		ID:        newID(),
		Ref:       ref,
		Type:      t,
		Status:    StatusRegistered,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.data[a.ID] = a
	return copyArtifact(a), nil
}

func (s *MemStore) Get(id string) (*Artifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	a, ok := s.data[id]
	if !ok {
		return nil, fmt.Errorf("artifact %q not found", id)
	}
	return copyArtifact(a), nil
}

func (s *MemStore) List() ([]*Artifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Artifact, 0, len(s.data))
	for _, a := range s.data {
		out = append(out, copyArtifact(a))
	}
	return out, nil
}

// ListPage filters, sorts and slices the in-memory map. The sort is
// (CreatedAt DESC, ID DESC), not CreatedAt alone: MemStore ranges over
// a map, so artifacts created in the same nanosecond -- routine in a
// test that registers a handful in a tight loop -- would otherwise come
// back in a different order on every call, and offset paging over an
// unstable order silently skips and repeats rows. PostgresStore's
// ListPage orders by the same two columns for the same reason.
func (s *MemStore) ListPage(limit, offset int, statusFilter, typeFilter, searchFilter string) ([]*Artifact, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Lower-cased once rather than per artifact per field.
	needle := strings.ToLower(strings.TrimSpace(searchFilter))

	filtered := make([]*Artifact, 0, len(s.data))
	for _, a := range s.data {
		if statusFilter != "" && string(a.Status) != statusFilter {
			continue
		}
		if typeFilter != "" && string(a.Type) != typeFilter {
			continue
		}
		if needle != "" && !matchesArtifactSearch(a, needle) {
			continue
		}
		filtered = append(filtered, copyArtifact(a))
	}
	sort.Slice(filtered, func(i, j int) bool {
		if !filtered[i].CreatedAt.Equal(filtered[j].CreatedAt) {
			return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
		}
		return filtered[i].ID > filtered[j].ID
	})

	total := len(filtered)
	if offset >= total {
		return []*Artifact{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return filtered[offset:end], total, nil
}

func (s *MemStore) Update(id string, mutate func(*Artifact)) (*Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.data[id]
	if !ok {
		return nil, fmt.Errorf("artifact %q not found", id)
	}
	mutate(a)
	a.UpdatedAt = time.Now().UTC()
	return copyArtifact(a), nil
}

func (s *MemStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data[id]; !ok {
		return fmt.Errorf("artifact %q not found", id)
	}
	delete(s.data, id)
	delete(s.documents, id)
	// Mirrors PostgresStore's ON DELETE CASCADE -- without this a
	// deleted artifact's components would still answer
	// FindByComponentPURL, from a map nothing else can reach.
	delete(s.components, id)
	delete(s.componentHistory, id)
	return nil
}

func (s *MemStore) SaveComponents(artifactID string, components []Component) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data[artifactID]; !ok {
		return fmt.Errorf("artifact %q not found", artifactID)
	}
	// Replaces, never appends -- see the Store interface's comment.
	s.components[artifactID] = append([]Component(nil), components...)
	s.appendSnapshotLocked(artifactID, components)
	return nil
}

// appendSnapshotLocked records this inventory as a new snapshot and
// evicts anything past MaxComponentSnapshots. Caller holds the lock.
//
// The timestamp is forced strictly newer than the previous snapshot's.
// That is not paranoia about clocks: two SaveComponents calls in the
// same test (or two scans of a small SBOM back to back) can land on the
// same time.Now() on a coarse monotonic clock, and two snapshots
// sharing a timestamp silently become ONE -- so the diff endpoint,
// which is defined as "compare the two most recent snapshots", would
// compare a merged set against an older one, or against itself, and
// report no changes. A wrong answer that looks exactly like a right
// one. PostgresStore gets this for free (separate transactions, distinct
// now()), so the guard lives here where the risk is.
func (s *MemStore) appendSnapshotLocked(artifactID string, components []Component) {
	now := time.Now().UTC()
	history := s.componentHistory[artifactID]
	if n := len(history); n > 0 && !now.After(history[n-1].scanAt) {
		now = history[n-1].scanAt.Add(time.Nanosecond)
	}
	history = append(history, componentSnapshot{
		scanAt:     now,
		components: append([]Component(nil), components...),
	})
	if len(history) > MaxComponentSnapshots {
		history = history[len(history)-MaxComponentSnapshots:]
	}
	s.componentHistory[artifactID] = history
}

// ComponentSnapshots returns retained snapshot timestamps, newest
// first. See the Store interface.
func (s *MemStore) ComponentSnapshots(artifactID string, limit int) ([]time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	history := s.componentHistory[artifactID]
	out := make([]time.Time, 0, len(history))
	for i := len(history) - 1; i >= 0; i-- {
		if limit > 0 && len(out) >= limit {
			break
		}
		out = append(out, history[i].scanAt)
	}
	return out, nil
}

func (s *MemStore) ComponentsAt(artifactID string, scanAt time.Time) ([]Component, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, snap := range s.componentHistory[artifactID] {
		if snap.scanAt.Equal(scanAt) {
			return append([]Component(nil), snap.components...), nil
		}
	}
	// Unknown timestamp is an empty inventory, not an error -- see the
	// Store interface.
	return []Component{}, nil
}

// SearchComponents scans and groups in Go, matching PostgresStore's
// GROUP BY. Same ordering (artifacts DESC, purl ASC) so the two
// backends can't disagree on what the picker shows.
func (s *MemStore) SearchComponents(query string, limit int) ([]ComponentMatch, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return []ComponentMatch{}, 0, nil
	}

	// Same two passes as SearchFindings, for the same reason: match
	// purls first, then count every artifact carrying them, so a
	// name-substring query can't undercount an artifact whose SBOM
	// spells the package differently for the same purl.
	matchedPURLs := make(map[string]bool)
	for id, components := range s.components {
		if _, ok := s.data[id]; !ok {
			continue
		}
		for _, c := range components {
			if strings.Contains(strings.ToLower(c.Name), q) || strings.Contains(strings.ToLower(c.PURL), q) {
				matchedPURLs[c.PURL] = true
			}
		}
	}

	byPURL := make(map[string]*ComponentMatch)
	for id, components := range s.components {
		if _, ok := s.data[id]; !ok {
			continue
		}
		for _, c := range components {
			if !matchedPURLs[c.PURL] {
				continue
			}
			m, ok := byPURL[c.PURL]
			if !ok {
				m = &ComponentMatch{PURL: c.PURL, Name: c.Name, Version: c.Version, Licenses: c.Licenses}
				byPURL[c.PURL] = m
			}
			// Alphabetically first name/version wins, matching the
			// DISTINCT ON in PostgresStore: the same purl can carry
			// different names across artifacts, and "whichever the map
			// happened to reach first" would differ between two calls on
			// the same data.
			if c.Name < m.Name {
				m.Name, m.Version, m.Licenses = c.Name, c.Version, c.Licenses
			}
			m.Artifacts++
		}
	}

	out := make([]ComponentMatch, 0, len(byPURL))
	for _, m := range byPURL {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Artifacts != out[j].Artifacts {
			return out[i].Artifacts > out[j].Artifacts
		}
		return out[i].PURL < out[j].PURL
	})

	total := len(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, total, nil
}

// FindByComponentPURL answers with a linear scan, the same way
// FindByFindingID does here -- PostgresStore uses the components.purl
// index for the same query.
// FindByLicense scans and compares per-identifier, matching
// PostgresStore's unnest-based query rather than a substring test on
// the joined string -- see the Store interface for why that difference
// matters.
func (s *MemStore) FindByLicense(license string) ([]*Artifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Artifact, 0)
	want := strings.ToLower(strings.TrimSpace(license))
	if want == "" {
		return out, nil
	}
	for id, components := range s.components {
		a, ok := s.data[id]
		if !ok {
			continue
		}
		if anyComponentLicensed(components, want) {
			out = append(out, copyArtifact(a))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// anyComponentLicensed reports whether any component carries want as one
// of its comma-separated identifiers (already lowercased and trimmed).
func anyComponentLicensed(components []Component, want string) bool {
	for _, c := range components {
		for _, one := range strings.Split(c.Licenses, ",") {
			if strings.ToLower(strings.TrimSpace(one)) == want {
				return true
			}
		}
	}
	return false
}

func (s *MemStore) FindByComponentPURL(purl string) ([]*Artifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Artifact, 0)
	if purl == "" {
		return out, nil
	}
	for id, components := range s.components {
		a, ok := s.data[id]
		if !ok {
			continue
		}
		for _, c := range components {
			if c.PURL == purl {
				out = append(out, copyArtifact(a))
				break
			}
		}
	}
	// Newest first, matching PostgresStore's ORDER BY created_at DESC --
	// MemStore ranges over a map, so without this the order would differ
	// between two calls with the same data.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

func (s *MemStore) SaveDocument(artifactID, kind, contentType string, content []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.data[artifactID]
	if !ok {
		return fmt.Errorf("artifact %q not found", artifactID)
	}
	if s.documents[artifactID] == nil {
		s.documents[artifactID] = make(map[string]*Document)
	}
	s.documents[artifactID][kind] = &Document{
		ArtifactID:  artifactID,
		Kind:        kind,
		ContentType: contentType,
		Content:     content,
		CreatedAt:   time.Now().UTC(),
	}
	switch kind {
	case DocumentKindSBOM:
		a.HasSBOM = true
	case DocumentKindSARIF:
		a.HasSARIF = true
	}
	return nil
}

func (s *MemStore) GetDocument(artifactID, kind string) (*Document, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.documents[artifactID][kind], nil
}

func (s *MemStore) FindByFindingID(findingID string) ([]*Artifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Artifact, 0)
	for _, a := range s.data {
		for _, bucket := range allBuckets(a) {
			if findingIDMatches(bucket, findingID) {
				out = append(out, copyArtifact(a))
				break
			}
		}
	}
	return out, nil
}

// namedBuckets is every finding slice on an artifact, keyed by the
// bucket name PostgresStore stores in findings.bucket. THE list of
// buckets, written once so a whole-artifact scan can't miss one: the
// old hand-written list checked CVE, malware and other only, so a
// misconfiguration or secret finding -- both real buckets since SARIF
// classification landed -- was invisible to FindByFindingID here while
// PostgresStore (which queries one table with a bucket column) found
// it. Two backends disagreeing about whether an artifact is affected is
// the kind of difference that only shows up in production.
//
// Keyed rather than a bare slice because Stats reports per-bucket
// counts and so needs to know which slice is which; allBuckets below
// drops the keys for the callers that only need "all of them".
func namedBuckets(a *Artifact) map[string][]Finding {
	return map[string][]Finding{
		bucketCVE:              a.CVEFindings,
		bucketMalware:          a.MalwareFindings,
		bucketMisconfiguration: a.MisconfigFindings,
		bucketSecret:           a.SecretFindings,
		bucketOther:            a.OtherFindings,
	}
}

// bucketNames is the five buckets in a fixed order. Ranging a map
// directly would hand allBuckets' callers a different order on every
// call; none of them looks like it would care (each scans every bucket
// and either breaks on the first match or aggregates all of them), but
// "looks like it wouldn't care" is a claim about three call sites that
// has to be re-checked every time a fourth appears, and a stable order
// costs one slice.
var bucketNames = []string{bucketCVE, bucketMalware, bucketMisconfiguration, bucketSecret, bucketOther}

// allBuckets is namedBuckets without the names, in bucketNames order.
func allBuckets(a *Artifact) [][]Finding {
	byName := namedBuckets(a)
	out := make([][]Finding, 0, len(bucketNames))
	for _, name := range bucketNames {
		out = append(out, byName[name])
	}
	return out
}

// findingIDMatches reports whether this bucket has findingID ACTIVE --
// a fixed or VEX-suppressed finding is on record but is not something
// the artifact is still affected by. See the Store interface.
func findingIDMatches(findings []Finding, findingID string) bool {
	for _, f := range findings {
		if f.ID == findingID && f.IsActive() {
			return true
		}
	}
	return false
}

// SearchFindings scans and groups in Go, matching PostgresStore's GROUP
// BY, with the same ordering so the two backends can't show a picker in
// different orders.
func (s *MemStore) SearchFindings(query string, limit int) ([]FindingMatch, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return []FindingMatch{}, 0, nil
	}

	// Two passes: find which ids match, then aggregate over EVERY active
	// row of those ids. Aggregating the matched rows instead undercounts
	// -- one CVE is recorded with whichever package title each scanner
	// reported ("openssl: ...", "libcrypto3 3.1.4-r5"), so a q=openssl
	// search would count only the artifacts whose title happened to say
	// openssl, while the click-through returns all of them. Mirrors the
	// matched_ids CTE in PostgresStore.SearchFindings.
	matchedIDs := make(map[string]bool)
	for _, a := range s.data {
		for _, bucket := range allBuckets(a) {
			for _, f := range bucket {
				if !f.IsActive() {
					continue
				}
				if strings.Contains(strings.ToLower(f.ID), q) || strings.Contains(strings.ToLower(f.Title), q) {
					matchedIDs[f.ID] = true
				}
			}
		}
	}

	type agg struct {
		match     FindingMatch
		artifacts map[string]bool
	}
	byID := make(map[string]*agg)
	for _, a := range s.data {
		for _, bucket := range allBuckets(a) {
			for _, f := range bucket {
				if !f.IsActive() || !matchedIDs[f.ID] {
					continue
				}
				g, ok := byID[f.ID]
				if !ok {
					g = &agg{match: FindingMatch{ID: f.ID}, artifacts: map[string]bool{}}
					byID[f.ID] = g
				}
				g.artifacts[a.ID] = true
				// Worst severity seen across every artifact carrying this
				// id, with the title from that same worst row -- see
				// FindingMatch.Severity.
				if g.match.Title == "" || (f.Severity != "" && SeverityRank(f.Severity) > SeverityRank(g.match.Severity)) {
					g.match.Title = f.Title
				}
				if f.Severity != "" && SeverityRank(f.Severity) >= SeverityRank(g.match.Severity) {
					g.match.Severity = f.Severity
				}
			}
		}
	}

	out := make([]FindingMatch, 0, len(byID))
	for _, g := range byID {
		g.match.Artifacts = len(g.artifacts)
		out = append(out, g.match)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Artifacts != out[j].Artifacts {
			return out[i].Artifacts > out[j].Artifacts
		}
		return out[i].ID < out[j].ID
	})

	total := len(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, total, nil
}

// FindByRef scans for the earliest artifact with this exact ref. Same
// oldest-wins tie-break as FindByDigest, so repeated registrations
// converge on the original rather than the most recent.
func (s *MemStore) Count() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data), nil
}

// Stats counts the whole map in one pass. ctx is accepted to satisfy
// the interface and ignored: there is nothing to cancel: this never
// blocks on anything, and returning ctx.Err() from a pure in-memory
// walk would make a test with an already-cancelled context fail in a
// way PostgresStore's timing wouldn't reproduce.
func (s *MemStore) Stats(_ context.Context) (Stats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := Stats{
		Total:        len(s.data),
		ByStatus:     map[string]int{},
		ByType:       map[string]int{},
		WithFindings: map[string]int{},
		ByStage:      map[string]int{},
	}
	// The five buckets are pre-seeded to zero, unlike the other three
	// maps -- see Stats' own comment for why this one reports its whole
	// closed set rather than only what it saw.
	for _, name := range bucketNames {
		stats.WithFindings[name] = 0
	}

	for _, a := range s.data {
		stats.ByStatus[string(a.Status)]++
		stats.ByType[string(a.Type)]++
		// Unstaged artifacts land under "" rather than a placeholder --
		// see Stats.ByStage.
		stats.ByStage[a.CurrentStage]++
		for name, findings := range namedBuckets(a) {
			// At most one per bucket per artifact: these count AFFECTED
			// ARTIFACTS, so an artifact with nine active CVEs is still one.
			// Mirrors PostgresStore's count(DISTINCT artifact_id).
			for _, f := range findings {
				if f.IsActive() {
					stats.WithFindings[name]++
					break
				}
			}
		}
	}
	return stats, nil
}

// AcquireScanSlots is the in-process equivalent of the SQL one -- same
// semantics, same all-or-nothing, same reaping, no database. See the
// Store interface.
func (s *MemStore) AcquireScanSlots(req ScanSlotRequest) (ScanSlotResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reap first, so an abandoned holder cannot keep a cap saturated
	// forever -- exactly what the SQL version does inside its
	// transaction.
	if req.StaleAfter > 0 {
		cutoff := time.Now().UTC().Add(-req.StaleAfter)
		for holder, slots := range s.scanSlots {
			kept := slots[:0]
			for _, sl := range slots {
				if sl.acquiredAt.After(cutoff) {
					kept = append(kept, sl)
				}
			}
			if len(kept) == 0 {
				delete(s.scanSlots, holder)
				continue
			}
			s.scanSlots[holder] = kept
		}
	}

	held := make(map[string]int)
	for _, slots := range s.scanSlots {
		for _, sl := range slots {
			held[sl.kind]++
		}
	}

	// Check every kind BEFORE taking any, so a partial acquisition is
	// never left behind on rejection.
	wanted := dedupeKinds(req.Kinds)
	for _, kind := range wanted {
		capacity, limited := req.Caps[kind]
		if !limited || capacity <= 0 {
			continue
		}
		if held[kind] >= capacity {
			return ScanSlotResult{BlockedKind: kind, BlockedCap: capacity}, nil
		}
	}

	now := time.Now().UTC()
	for _, kind := range wanted {
		s.scanSlots[req.HolderID] = append(s.scanSlots[req.HolderID], scanSlot{kind: kind, acquiredAt: now})
	}
	return ScanSlotResult{Acquired: true}, nil
}

func (s *MemStore) ReleaseScanSlots(holderID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.scanSlots, holderID)
	return nil
}

// dedupeKinds keeps the first occurrence of each kind, in order. Two
// scanners of the same kind in one scan take ONE slot -- the cap counts
// concurrent scans of a kind, not scanner instances.
func dedupeKinds(kinds []string) []string {
	seen := make(map[string]bool, len(kinds))
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out
}

func (s *MemStore) CountStaleScans(cutoff time.Time) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n := 0
	for _, a := range s.data {
		// Never scanned is excluded, not treated as infinitely old --
		// see the Store interface.
		if a.LastScanAt != nil && a.LastScanAt.Before(cutoff) {
			n++
		}
	}
	return n, nil
}

func (s *MemStore) CountOlderThan(cutoff time.Time) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n := 0
	for _, a := range s.data {
		if a.UpdatedAt.Before(cutoff) {
			n++
		}
	}
	return n, nil
}

// DeleteOlderThan removes the oldest-first, up to limit. Sorting before
// deleting matters even here: MemStore ranges over a map, so without it
// a limited run would delete an arbitrary subset rather than the oldest
// ones, and two backends would disagree about which artifacts survive a
// capped prune.
func (s *MemStore) DeleteOlderThan(cutoff time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	stale := make([]*Artifact, 0)
	for _, a := range s.data {
		if a.UpdatedAt.Before(cutoff) {
			stale = append(stale, a)
		}
	}
	sort.Slice(stale, func(i, j int) bool {
		if !stale[i].UpdatedAt.Equal(stale[j].UpdatedAt) {
			return stale[i].UpdatedAt.Before(stale[j].UpdatedAt)
		}
		return stale[i].ID < stale[j].ID
	})
	if len(stale) > limit {
		stale = stale[:limit]
	}
	for _, a := range stale {
		// Mirrors PostgresStore's ON DELETE CASCADE, the same way
		// Delete above has to.
		delete(s.data, a.ID)
		delete(s.documents, a.ID)
		delete(s.components, a.ID)
		delete(s.componentHistory, a.ID)
	}
	return len(stale), nil
}

func (s *MemStore) FindByRef(ref string) (*Artifact, error) {
	if ref == "" {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var match *Artifact
	for _, a := range s.data {
		// SourceRef too -- see PostgresStore.FindByRef for why a
		// mirrored artifact must still be found by the ref it was
		// originally registered under.
		if a.Ref != ref && a.SourceRef != ref {
			continue
		}
		if match == nil || a.CreatedAt.Before(match.CreatedAt) {
			match = a
		}
	}
	return copyArtifact(match), nil
}

func (s *MemStore) FindByDigest(digest string) (*Artifact, error) {
	if digest == "" {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var match *Artifact
	for _, a := range s.data {
		if a.Digest == "" || a.Digest != digest {
			continue
		}
		if match == nil || a.CreatedAt.Before(match.CreatedAt) {
			match = a
		}
	}
	return copyArtifact(match), nil
}

// scanToken is MemStore's in-memory equivalent of a scan_tokens row.
type scanToken struct {
	artifactID string
	expiresAt  time.Time
	usedKinds  map[string]bool
}

func (s *MemStore) CreateScanToken(artifactID, tokenHash string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scanTokens == nil {
		s.scanTokens = make(map[string]*scanToken)
	}
	s.scanTokens[tokenHash] = &scanToken{artifactID: artifactID, expiresAt: expiresAt, usedKinds: map[string]bool{}}
	return nil
}

func (s *MemStore) ConsumeScanToken(tokenHash, artifactID, kind string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.scanTokens[tokenHash]
	// Every rejection returns the same (false, nil): unknown token,
	// wrong artifact, expired, or this kind already used. The caller
	// answers 401 either way, so distinguishing them here would only
	// create something to leak.
	if !ok || t.artifactID != artifactID || !time.Now().Before(t.expiresAt) || t.usedKinds[kind] {
		return false, nil
	}
	t.usedKinds[kind] = true
	return true, nil
}

func (s *MemStore) DeleteScanTokens(artifactID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, t := range s.scanTokens {
		if t.artifactID == artifactID || !time.Now().Before(t.expiresAt) {
			delete(s.scanTokens, hash)
		}
	}
	return nil
}

// ReplaceEnrichment mirrors PostgresStore's: wholesale per feed, and a
// nil feed is left alone so a partial refresh keeps the good half.
func (s *MemStore) ReplaceEnrichment(kev []string, epss map[string]float64, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enrichment == nil {
		s.enrichment = make(map[string]Enrichment)
	}
	when := at

	if epss != nil {
		for id, e := range s.enrichment {
			e.EPSSScore = 0
			s.enrichment[id] = e
		}
		for cve, score := range epss {
			id := strings.ToUpper(cve)
			e := s.enrichment[id]
			e.EPSSScore = score
			s.enrichment[id] = e
		}
		s.enrichmentStatus.EPSSUpdatedAt, s.enrichmentStatus.EPSSEntries = &when, len(epss)
	}

	if kev != nil {
		for id, e := range s.enrichment {
			e.KnownExploited = false
			s.enrichment[id] = e
		}
		for _, cve := range kev {
			id := strings.ToUpper(cve)
			e := s.enrichment[id]
			e.KnownExploited = true
			s.enrichment[id] = e
		}
		s.enrichmentStatus.KEVUpdatedAt, s.enrichmentStatus.KEVEntries = &when, len(kev)
	}
	return nil
}

func (s *MemStore) LookupEnrichment(cveIDs []string) (map[string]Enrichment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Enrichment, len(cveIDs))
	for _, id := range cveIDs {
		up := strings.ToUpper(id)
		if e, ok := s.enrichment[up]; ok {
			out[up] = e
		}
	}
	return out, nil
}

func (s *MemStore) EnrichmentStatus() (EnrichmentStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enrichmentStatus, nil
}

// matchesArtifactSearch is MemStore's half of ?q=, and must agree with
// the ILIKE clause listFilterClause builds for Postgres -- same six
// fields, same case-insensitive substring semantics. needle is already
// lower-cased and trimmed.
//
// The two are separate implementations of one rule, which is only safe
// because a test runs the same cases against both (see
// TestListPageSearchAgreesAcrossStores). A search box that behaves
// differently in tests than in production would be worse than not
// having one.
func matchesArtifactSearch(a *Artifact, needle string) bool {
	for _, field := range []string{a.Ref, a.SourceRef, a.Digest, a.MaintainerTeam, a.MaintainerEmail, a.CurrentStage} {
		if strings.Contains(strings.ToLower(field), needle) {
			return true
		}
	}
	return false
}
