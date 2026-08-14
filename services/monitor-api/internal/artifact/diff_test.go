package artifact_test

import (
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

func comp(purl, name, version string) artifact.Component {
	return artifact.Component{PURL: purl, Name: name, Version: version}
}

func purls(cs []artifact.Component) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.PURL)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDiffComponents(t *testing.T) {
	openssl5 := comp("pkg:apk/alpine/openssl@3.1.4-r5", "openssl", "3.1.4-r5")
	openssl6 := comp("pkg:apk/alpine/openssl@3.1.4-r6", "openssl", "3.1.4-r6")
	busybox := comp("pkg:apk/alpine/busybox@1.36.1-r15", "busybox", "1.36.1-r15")
	zlib := comp("pkg:apk/alpine/zlib@1.3-r0", "zlib", "1.3-r0")

	cases := []struct {
		name           string
		from, to       []artifact.Component
		added, removed []string
		changed        []artifact.ComponentVersionChange
	}{
		{
			name: "no change",
			from: []artifact.Component{openssl5, busybox},
			to:   []artifact.Component{openssl5, busybox},
		},
		{
			// The case a purl-keyed diff gets wrong: an upgrade changes
			// the purl, so a naive diff calls it one removal plus one
			// unrelated addition and version_changed is always empty.
			name:    "version bump is one change, not an add plus a remove",
			from:    []artifact.Component{openssl5, busybox},
			to:      []artifact.Component{openssl6, busybox},
			changed: []artifact.ComponentVersionChange{{PURL: openssl6.PURL, From: "3.1.4-r5", To: "3.1.4-r6"}},
		},
		{
			name:  "addition",
			from:  []artifact.Component{busybox},
			to:    []artifact.Component{busybox, zlib},
			added: []string{zlib.PURL},
		},
		{
			name:    "removal",
			from:    []artifact.Component{busybox, zlib},
			to:      []artifact.Component{busybox},
			removed: []string{zlib.PURL},
		},
		{
			name:    "all three at once",
			from:    []artifact.Component{openssl5, busybox},
			to:      []artifact.Component{openssl6, zlib},
			added:   []string{zlib.PURL},
			removed: []string{busybox.PURL},
			changed: []artifact.ComponentVersionChange{{PURL: openssl6.PURL, From: "3.1.4-r5", To: "3.1.4-r6"}},
		},
		{
			// Two versions of one package coexisting, one dropped. That
			// is a removal -- pairing the survivors into a "version
			// change" would invent an upgrade that never happened.
			name:    "one of two concurrent versions removed",
			from:    []artifact.Component{openssl5, openssl6},
			to:      []artifact.Component{openssl6},
			removed: []string{openssl5.PURL},
		},
		{
			name:  "first ever snapshot -- everything is new",
			from:  nil,
			to:    []artifact.Component{busybox, zlib},
			added: []string{busybox.PURL, zlib.PURL},
		},
		{
			name:    "everything dropped",
			from:    []artifact.Component{busybox},
			to:      nil,
			removed: []string{busybox.PURL},
		},
		{
			// Qualifiers carry an "@" of their own in the wild, and the
			// version separator is the last one before them.
			name: "qualifiers don't confuse the version split",
			from: []artifact.Component{comp("pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64", "openssl", "3.1.4-r5")},
			to:   []artifact.Component{comp("pkg:apk/alpine/openssl@3.1.4-r6?arch=x86_64", "openssl", "3.1.4-r6")},
			changed: []artifact.ComponentVersionChange{
				{PURL: "pkg:apk/alpine/openssl@3.1.4-r6?arch=x86_64", From: "3.1.4-r5", To: "3.1.4-r6"},
			},
		},
		{
			// Version field empty (some SBOM formats), so the version has
			// to come out of the purl or the change reads "" -> "".
			name: "version falls back to the purl when the field is empty",
			from: []artifact.Component{comp("pkg:npm/left-pad@1.0.0", "left-pad", "")},
			to:   []artifact.Component{comp("pkg:npm/left-pad@1.1.0", "left-pad", "")},
			changed: []artifact.ComponentVersionChange{
				{PURL: "pkg:npm/left-pad@1.1.0", From: "1.0.0", To: "1.1.0"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := artifact.DiffComponents(tc.from, tc.to)

			// Never nil: "nothing changed" must serialize as [] not null.
			if got.Added == nil || got.Removed == nil || got.VersionChanged == nil {
				t.Fatalf("a diff list is nil; all three must be empty slices: %+v", got)
			}
			want := func(s []string) []string {
				if s == nil {
					return []string{}
				}
				return s
			}
			if !equalStrings(purls(got.Added), want(tc.added)) {
				t.Errorf("added = %v, want %v", purls(got.Added), want(tc.added))
			}
			if !equalStrings(purls(got.Removed), want(tc.removed)) {
				t.Errorf("removed = %v, want %v", purls(got.Removed), want(tc.removed))
			}
			if len(got.VersionChanged) != len(tc.changed) {
				t.Fatalf("version_changed = %+v, want %+v", got.VersionChanged, tc.changed)
			}
			for i, c := range tc.changed {
				if got.VersionChanged[i] != c {
					t.Errorf("version_changed[%d] = %+v, want %+v", i, got.VersionChanged[i], c)
				}
			}
		})
	}
}

// The output feeds an API response and a dashboard list, so two calls on
// the same data must not produce differently-ordered JSON -- the maps
// this walks internally have no order of their own.
func TestDiffComponents_OrderIsStable(t *testing.T) {
	from := []artifact.Component{
		comp("pkg:apk/alpine/zlib@1.3-r0", "zlib", "1.3-r0"),
		comp("pkg:apk/alpine/openssl@3.1.4-r5", "openssl", "3.1.4-r5"),
	}
	to := []artifact.Component{
		comp("pkg:apk/alpine/openssl@3.1.4-r6", "openssl", "3.1.4-r6"),
		comp("pkg:apk/alpine/curl@8.5.0-r0", "curl", "8.5.0-r0"),
		comp("pkg:apk/alpine/bash@5.2-r0", "bash", "5.2-r0"),
	}

	first := artifact.DiffComponents(from, to)
	for i := 0; i < 20; i++ {
		got := artifact.DiffComponents(from, to)
		if !equalStrings(purls(got.Added), purls(first.Added)) {
			t.Fatalf("added order changed between calls: %v vs %v", purls(got.Added), purls(first.Added))
		}
		if !equalStrings(purls(got.Removed), purls(first.Removed)) {
			t.Fatalf("removed order changed between calls: %v vs %v", purls(got.Removed), purls(first.Removed))
		}
	}
	// Sorted by purl, so bash before curl.
	if want := []string{"pkg:apk/alpine/bash@5.2-r0", "pkg:apk/alpine/curl@8.5.0-r0"}; !equalStrings(purls(first.Added), want) {
		t.Errorf("added = %v, want %v (sorted by purl)", purls(first.Added), want)
	}
}
