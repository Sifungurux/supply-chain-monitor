package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/api"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/scanner"
)

const mirrorRegistry = "scm-registry.supply-chain-monitor.svc.cluster.local:5000"

// fakeMirror stands in for `oras copy` against two real registries.
// refs it was asked to copy are recorded, so a test can prove the copy
// did NOT happen as easily as that it did.
type fakeMirror struct {
	err    error
	copied []string
}

func (f *fakeMirror) Mirror(_ context.Context, ref, _ string) (string, error) {
	f.copied = append(f.copied, ref)
	if f.err != nil {
		return "", f.err
	}
	return mirrorRegistry + "/mirror/docker.io/library/" + ref, nil
}

func newTestRouterWithMirror(m scanner.Mirror) (http.Handler, *artifact.MemStore) {
	store := artifact.NewMemStore()
	tracker := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})
	return api.NewRouter(api.Config{Store: store, Tracker: tracker, APIKey: testAPIKey, Mirror: m}), store
}

// The feature itself: registering an artifact copies it into the local
// registry and leaves the artifact pointing at the copy, with the public
// ref kept as a note. Every later scan reads Ref, so this rewrite IS
// what stops scans pulling from Docker Hub.
func TestCreateArtifact_MirrorsAndRewritesRef(t *testing.T) {
	m := &fakeMirror{}
	h, store := newTestRouterWithMirror(m)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": "nginx:alpine", "type": "image"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	a := decodeArtifact(t, rec)
	if a.SourceRef != "nginx:alpine" {
		t.Errorf("source_ref = %q, want the original public ref", a.SourceRef)
	}
	if a.Ref != mirrorRegistry+"/mirror/docker.io/library/nginx:alpine" {
		t.Errorf("ref = %q, want the local mirror", a.Ref)
	}
	// And it is on disk, not just in the response -- a rewrite that only
	// existed in the reply would leave every later scan pulling from
	// Docker Hub while the API claimed otherwise.
	stored, err := store.Get(a.ID)
	if err != nil {
		t.Fatalf("get artifact: %v", err)
	}
	if stored.Ref != a.Ref || stored.SourceRef != a.SourceRef {
		t.Errorf("stored ref/source_ref = %q/%q, want %q/%q", stored.Ref, stored.SourceRef, a.Ref, a.SourceRef)
	}
}

// A registry that is unreachable, out of disk, or refusing the push must
// not take registration down with it: the artifact registers with its
// original ref and the next scan tries again.
func TestCreateArtifact_MirrorFailureKeepsTheOriginalRef(t *testing.T) {
	h, _ := newTestRouterWithMirror(&fakeMirror{err: errors.New("no space left on device")})

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts", map[string]string{"ref": "nginx:alpine", "type": "image"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("a failed mirror broke registration: status = %d: %s", rec.Code, rec.Body.String())
	}
	a := decodeArtifact(t, rec)
	if a.Ref != "nginx:alpine" || a.SourceRef != "" {
		t.Errorf("ref/source_ref = %q/%q, want the original ref and no source_ref", a.Ref, a.SourceRef)
	}
}

// Bulk registration deliberately does NOT copy inline -- 500 refs in one
// request cannot each wait for a full image copy. This is the test that
// keeps that deferral from being quietly undone.
func TestBulkCreateArtifacts_DefersMirroring(t *testing.T) {
	m := &fakeMirror{}
	h, _ := newTestRouterWithMirror(m)

	rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", map[string]any{
		"artifacts": []map[string]string{
			{"ref": "nginx:alpine", "type": "image"},
			{"ref": "redis:7", "type": "image"},
		},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	if len(m.copied) != 0 {
		t.Errorf("bulk registration copied %v inline -- it must leave that to the first scan", m.copied)
	}
}

// Once an artifact is mirrored its ref names the local copy, so
// re-registering the ORIGINAL public ref has to still be recognised as
// the duplicate it is. Both entry points, because the single and bulk
// paths enforce dedup with their own code and have drifted apart before.
func TestMirroredArtifactIsStillFoundByItsOriginalRef(t *testing.T) {
	for _, path := range []string{"single", "bulk"} {
		t.Run(path, func(t *testing.T) {
			h, _ := newTestRouterWithMirror(&fakeMirror{})
			if rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts",
				map[string]string{"ref": "nginx:alpine", "type": "image"}); rec.Code != http.StatusCreated {
				t.Fatalf("first registration: status = %d: %s", rec.Code, rec.Body.String())
			}

			if path == "single" {
				rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts",
					map[string]string{"ref": "nginx:alpine", "type": "image"})
				if rec.Code != http.StatusConflict {
					t.Fatalf("re-registering the original ref: status = %d, want 409 -- it was mirrored, not forgotten: %s",
						rec.Code, rec.Body.String())
				}
				return
			}

			rec := doJSON(t, h, http.MethodPost, "/api/v1/artifacts/bulk", map[string]any{
				"artifacts": []map[string]string{{"ref": "nginx:alpine", "type": "image"}},
			})
			var resp struct {
				Created    int `json:"created"`
				Duplicates int `json:"duplicates"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
			}
			if resp.Duplicates != 1 || resp.Created != 0 {
				t.Fatalf("created=%d duplicates=%d, want 0/1 -- the mirrored artifact was registered a second time",
					resp.Created, resp.Duplicates)
			}
		})
	}
}
