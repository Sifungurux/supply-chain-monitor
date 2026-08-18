package artifact_test

import (
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// searchCases is the shared contract for ?q=. Both stores implement it
// independently -- MemStore with strings.Contains, PostgresStore with
// ILIKE -- and the point of keeping the cases in one place is that
// TestPostgresStore_ListPageSearch (postgres_store_integration_test.go)
// runs this exact table too. A search box that behaved differently in
// tests than in production would be worse than not having one.
type searchCase struct {
	Name  string
	Query string
	Want  []string // refs, in any order
}

func SearchCases() []searchCase {
	return []searchCase{
		{"ref substring", "nginx", []string{"docker.io/library/nginx:1.27"}},
		{"case-insensitive", "NGINX", []string{"docker.io/library/nginx:1.27"}},
		{"matches a digest", "sha256:beef", []string{"alpine:3.19"}},
		{"matches a maintainer team", "platform", []string{"alpine:3.19"}},
		{"matches a maintainer email", "sec@example", []string{"docker.io/library/nginx:1.27"}},
		{"matches the current stage", "deploy", []string{"busybox:1.36"}},
		{"matches nothing", "no-such-thing", nil},
		// A user typing a LIKE metacharacter must match it literally.
		// Unescaped, "%" matches every artifact -- a search box that
		// returns everything for one keystroke feels broken in a way
		// nobody can explain.
		{"percent is literal, not a wildcard", "%", nil},
		{"underscore is literal, not any-character", "_", nil},
		// Empty means "no search", never "match nothing".
		{"empty returns everything", "", []string{"alpine:3.19", "docker.io/library/nginx:1.27", "busybox:1.36"}},
		{"whitespace only is also no search", "   ", []string{"alpine:3.19", "docker.io/library/nginx:1.27", "busybox:1.36"}},
	}
}

// SeedSearchFixtures creates the three artifacts SearchCases expects.
func SeedSearchFixtures(t *testing.T, s artifact.Store) {
	t.Helper()

	mk := func(ref string, typ artifact.Type, mutate func(*artifact.Artifact)) {
		t.Helper()
		a, err := s.Create(ref, typ)
		if err != nil {
			t.Fatalf("Create(%q): %v", ref, err)
		}
		if mutate != nil {
			if _, err := s.Update(a.ID, mutate); err != nil {
				t.Fatalf("Update(%q): %v", ref, err)
			}
		}
	}

	mk("alpine:3.19", artifact.TypeImage, func(a *artifact.Artifact) {
		a.Digest = "sha256:beefcafe"
		a.MaintainerTeam = "Platform"
	})
	mk("docker.io/library/nginx:1.27", artifact.TypeImage, func(a *artifact.Artifact) {
		a.MaintainerEmail = "sec@example.com"
	})
	mk("busybox:1.36", artifact.TypeImage, func(a *artifact.Artifact) {
		a.CurrentStage = "deploy"
	})
}

// AssertSearch runs the shared table against any Store.
func AssertSearch(t *testing.T, s artifact.Store) {
	t.Helper()
	for _, tc := range SearchCases() {
		t.Run(tc.Name, func(t *testing.T) {
			page, total, err := s.ListPage(50, 0, "", "", tc.Query)
			if err != nil {
				t.Fatalf("ListPage(q=%q): %v", tc.Query, err)
			}
			got := map[string]bool{}
			for _, a := range page {
				got[a.Ref] = true
			}
			if total != len(page) {
				t.Errorf("total = %d but page has %d -- the count must describe the SEARCH result", total, len(page))
			}
			if len(got) != len(tc.Want) {
				t.Fatalf("q=%q matched %d artifact(s) %v, want %d %v", tc.Query, len(got), keys(got), len(tc.Want), tc.Want)
			}
			for _, ref := range tc.Want {
				if !got[ref] {
					t.Errorf("q=%q did not match %q (got %v)", tc.Query, ref, keys(got))
				}
			}
		})
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestMemStore_ListPageSearch(t *testing.T) {
	s := artifact.NewMemStore()
	SeedSearchFixtures(t, s)
	AssertSearch(t, s)
}

// Search combines with the other filters rather than replacing them.
func TestMemStore_ListPageSearchCombinesWithFilters(t *testing.T) {
	s := artifact.NewMemStore()
	SeedSearchFixtures(t, s)

	page, total, err := s.ListPage(50, 0, string(artifact.StatusRegistered), string(artifact.TypeImage), "nginx")
	if err != nil {
		t.Fatalf("ListPage: %v", err)
	}
	if total != 1 || len(page) != 1 || page[0].Ref != "docker.io/library/nginx:1.27" {
		t.Fatalf("filters+search = %d artifacts, want just nginx", total)
	}

	// A filter that excludes the searched artifact wins -- they are
	// ANDed, not ORed.
	_, total, err = s.ListPage(50, 0, string(artifact.StatusScanned), "", "nginx")
	if err != nil {
		t.Fatalf("ListPage: %v", err)
	}
	if total != 0 {
		t.Fatalf("total = %d, want 0 -- status and q must combine, not alternate", total)
	}
}
