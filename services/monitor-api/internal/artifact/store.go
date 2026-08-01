package artifact

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
	Update(id string, mutate func(*Artifact)) (*Artifact, error)
	// FindByFindingID returns every artifact with a CVE/malware/other
	// finding matching findingID (e.g. "CVE-2024-1234") in any bucket --
	// the concrete payoff of normalizing findings into their own table
	// (see docs/architecture.md, "Normalizing findings and stage
	// history into their own tables"). MemStore answers this with a
	// linear scan; PostgresStore uses the findings.finding_id index.
	FindByFindingID(findingID string) ([]*Artifact, error)
	// FindByDigest returns the first-registered artifact matching
	// digest, or (nil, nil) if none exists yet -- "not found" is the
	// expected, common case (most registrations are the first time
	// their content has been seen), not an error condition. Never
	// matches an empty digest: callers should only ever call this with
	// a digest they've actually resolved (see internal/api/handlers.go's
	// duplicate-registration check), not as a way to enumerate
	// not-yet-resolved artifacts.
	FindByDigest(digest string) (*Artifact, error)
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
}

// MemStore is a thread-safe, in-memory Store implementation.
//
// This used to be the only Store this service had ("v1 stub, no
// external dependencies"). It's kept around now purely as a fast,
// hermetic backend for tests -- production always uses PostgresStore.
type MemStore struct {
	mu   sync.RWMutex
	data map[string]*Artifact
	// documents is keyed by artifact ID then kind (DocumentKindSBOM/
	// DocumentKindSARIF) -- a plain nested map is enough here since
	// MemStore only ever backs tests, never production (see the type's
	// own comment).
	documents map[string]map[string]*Document
}

func NewMemStore() *MemStore {
	return &MemStore{data: make(map[string]*Artifact), documents: make(map[string]map[string]*Document)}
}

// newID generates the random hex artifact ID used by every Store
// implementation, so IDs look the same regardless of backend.
func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
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
	return a, nil
}

func (s *MemStore) Get(id string) (*Artifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	a, ok := s.data[id]
	if !ok {
		return nil, fmt.Errorf("artifact %q not found", id)
	}
	return a, nil
}

func (s *MemStore) List() ([]*Artifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Artifact, 0, len(s.data))
	for _, a := range s.data {
		out = append(out, a)
	}
	return out, nil
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
	return a, nil
}

func (s *MemStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data[id]; !ok {
		return fmt.Errorf("artifact %q not found", id)
	}
	delete(s.data, id)
	delete(s.documents, id)
	return nil
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
		if findingIDMatches(a.CVEFindings, findingID) ||
			findingIDMatches(a.MalwareFindings, findingID) ||
			findingIDMatches(a.OtherFindings, findingID) {
			out = append(out, a)
		}
	}
	return out, nil
}

func findingIDMatches(findings []Finding, findingID string) bool {
	for _, f := range findings {
		if f.ID == findingID {
			return true
		}
	}
	return false
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
	return match, nil
}
