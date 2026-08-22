package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hostsIn is the assertion these tests actually care about: which
// registries the merged config can authenticate to.
func hostsIn(t *testing.T, auths map[string]any) map[string]bool {
	t.Helper()
	got := map[string]bool{}
	for host := range auths {
		got[host] = true
	}
	return got
}

func writeAuthFile(t *testing.T, dir, name, body string) {
	t.Helper()
	sub := filepath.Join(dir, name)
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// ".dockerconfigjson" is the file name a mounted
	// kubernetes.io/dockerconfigjson Secret produces, since a volume
	// mount names each file after its key.
	if err := os.WriteFile(filepath.Join(sub, ".dockerconfigjson"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestMergeRegistryAuths_MergesLegacyPairAndMountedConfigs is the whole
// point of the multi-registry work: the in-cluster account and every
// externally-managed pull secret end up in ONE auths map, so a scan of
// a ghcr.io image offers ghcr.io's credentials rather than
// scm-registry's.
func TestMergeRegistryAuths_MergesLegacyPairAndMountedConfigs(t *testing.T) {
	dir := t.TempDir()
	writeAuthFile(t, dir, "ghcr-pull-secret", `{"auths":{"ghcr.io":{"auth":"Ym90OnQ="}}}`)
	writeAuthFile(t, dir, "inline", `{"auths":{"registry.internal:5000":{"auth":"c3ZjOnA="}}}`)

	auths := mergeRegistryAuths("scm-registry:5000", "scm-reader", "hunter2", dir)

	got := hostsIn(t, auths)
	for _, want := range []string{"scm-registry:5000", "ghcr.io", "registry.internal:5000"} {
		if !got[want] {
			t.Errorf("host %q missing from merged auths: %v", want, got)
		}
	}
}

// TestMergeRegistryAuths_MountedEntryWinsForTheSameHost pins the
// precedence rather than leaving it to directory iteration order. An
// operator who lists a host explicitly means to override whatever the
// chart derived for it.
func TestMergeRegistryAuths_MountedEntryWinsForTheSameHost(t *testing.T) {
	dir := t.TempDir()
	writeAuthFile(t, dir, "override", `{"auths":{"scm-registry:5000":{"auth":"bmV3OmNyZWRz"}}}`)

	auths := mergeRegistryAuths("scm-registry:5000", "scm-reader", "hunter2", dir)

	body, err := json.Marshal(auths["scm-registry:5000"])
	if err != nil {
		t.Fatal(err)
	}
	if want := base64.StdEncoding.EncodeToString([]byte("new:creds")); !strings.Contains(string(body), want) {
		t.Errorf("mounted entry did not win for scm-registry:5000: %s", body)
	}
}

// TestMergeRegistryAuths_NoCredentialsStaysEmpty preserves the
// pre-feature default: with nothing configured, writeDockerConfig
// returns "" and UnpackerScanner omits --config entirely. A config file
// containing an empty auths map is NOT the same thing -- it would make
// every caller pass a flag pointing at credentials that do not exist.
func TestMergeRegistryAuths_NoCredentialsStaysEmpty(t *testing.T) {
	if auths := mergeRegistryAuths("scm-registry:5000", "", "", t.TempDir()); len(auths) != 0 {
		t.Errorf("no credentials configured, but auths = %v", auths)
	}
	if path := writeDockerConfig("scm-registry:5000", "", "", t.TempDir()); path != "" {
		t.Errorf("writeDockerConfig returned %q with nothing configured, want \"\"", path)
	}
}

// TestMergeRegistryAuths_SkipsUnreadableAndMalformed keeps one broken
// mount from taking every other registry down with it. The failure is
// logged, not fatal: a pod that refuses to start because one optional
// pull secret holds bad JSON is a worse outcome than one that scans
// everything else.
func TestMergeRegistryAuths_SkipsUnreadableAndMalformed(t *testing.T) {
	dir := t.TempDir()
	writeAuthFile(t, dir, "broken", `{"auths":`)
	writeAuthFile(t, dir, "good", `{"auths":{"ghcr.io":{"auth":"Ym90OnQ="}}}`)

	auths := mergeRegistryAuths("", "", "", dir)

	if got := hostsIn(t, auths); !got["ghcr.io"] {
		t.Errorf("a malformed config suppressed a valid one: %v", got)
	}
}

// TestMergeRegistryAuths_MissingDirIsNotAnError covers the default
// deployment, where the chart mounts nothing because no extra
// registries are configured.
func TestMergeRegistryAuths_MissingDirIsNotAnError(t *testing.T) {
	auths := mergeRegistryAuths("scm-registry:5000", "scm-reader", "hunter2", filepath.Join(t.TempDir(), "does-not-exist"))
	if got := hostsIn(t, auths); !got["scm-registry:5000"] {
		t.Errorf("legacy pair lost when the mount directory is absent: %v", got)
	}
}

// writeUserPair lays out a username/password pair the way a mounted
// Secret actually arrives: the real files in a timestamped "..2026_..."
// directory, a "..data" symlink pointing at it, and the two visible
// names symlinked through that. Reproduced faithfully rather than
// simplified to two plain files, because the timestamped directory is
// the entire reason mergeRegistryAuths skips dot-directories -- a test
// against plain files would pass with that skip removed.
func writeUserPair(t *testing.T, dir, host, user, pass string) {
	t.Helper()
	base := filepath.Join(dir, host)
	data := filepath.Join(base, "..2026_08_22_15_44_23.3812500056")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"username": user, "password": pass} {
		if err := os.WriteFile(filepath.Join(data, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(base, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(data, filepath.Join(base, "..data")); err != nil {
		t.Fatal(err)
	}
}

// TestMergeRegistryAuths_ReadsUsernameSecretRefPairs covers the
// usernameSecretRef shape: a Secret holding a bare username and
// password, whose host is carried by the mount path rather than by any
// file content.
func TestMergeRegistryAuths_ReadsUsernameSecretRefPairs(t *testing.T) {
	dir := t.TempDir()
	writeUserPair(t, dir, "registry.internal:5000", "svc", "hunter2")

	auths := mergeRegistryAuths("", "", "", dir)

	if got := hostsIn(t, auths); !got["registry.internal:5000"] {
		t.Fatalf("usernameSecretRef host missing from merged auths: %v", got)
	}
	// The timestamped directory must NOT have become a host of its own
	// -- that is the bug the dot-directory skip exists to prevent, and
	// it is invisible unless asserted, since the real host is present
	// either way.
	if len(auths) != 1 {
		t.Errorf("want exactly one host, got %d: %v", len(auths), hostsIn(t, auths))
	}

	entry, ok := auths["registry.internal:5000"].(map[string]string)
	if !ok {
		t.Fatalf("entry has unexpected type %T", auths["registry.internal:5000"])
	}
	if want := base64.StdEncoding.EncodeToString([]byte("svc:hunter2")); entry["auth"] != want {
		t.Errorf("auth = %q, want %q", entry["auth"], want)
	}
}

// TestMergeRegistryAuths_UserPairTrailingNewlineStripped is the failure
// this project would otherwise debug as "the password is wrong":
// `kubectl create secret generic --from-file` keeps the newline at the
// end of the file, and a credential with a stray "\n" 401s exactly the
// way a wrong password does.
func TestMergeRegistryAuths_UserPairTrailingNewlineStripped(t *testing.T) {
	dir := t.TempDir()
	writeUserPair(t, dir, "ghcr.io", "bot\n", "token\r\n")

	auths := mergeRegistryAuths("", "", "", dir)

	entry, ok := auths["ghcr.io"].(map[string]string)
	if !ok {
		t.Fatalf("entry has unexpected type %T", auths["ghcr.io"])
	}
	if entry["username"] != "bot" || entry["password"] != "token" {
		t.Errorf("username/password not trimmed: %q / %q", entry["username"], entry["password"])
	}
	if want := base64.StdEncoding.EncodeToString([]byte("bot:token")); entry["auth"] != want {
		t.Errorf("auth = %q, want %q", entry["auth"], want)
	}
}

// TestMergeRegistryAuths_HalfPopulatedUserPairIsSkipped: a Secret whose
// password key is missing (or misnamed in usernameSecretRef) must not
// register half a credential. Anonymous is the correct outcome; a
// username with an empty password would authenticate as something.
func TestMergeRegistryAuths_HalfPopulatedUserPairIsSkipped(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "ghcr.io")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "username"), []byte("bot"), 0o600); err != nil {
		t.Fatal(err)
	}

	if auths := mergeRegistryAuths("", "", "", dir); len(auths) != 0 {
		t.Errorf("half-populated pair produced auths: %v", hostsIn(t, auths))
	}
}

// TestMergeRegistryAuths_UserPairAndDockerConfigOrderByPath pins the
// precedence rule ACROSS the two kinds. Both are sorted by path
// together, so "z-config" beats the pair mounted at "ghcr.io" -- the
// point being that the winner does not depend on which KIND of source
// it is, which is not something values.yaml could otherwise predict.
func TestMergeRegistryAuths_UserPairAndDockerConfigOrderByPath(t *testing.T) {
	dir := t.TempDir()
	writeUserPair(t, dir, "ghcr.io", "pair", "wins-if-later")
	writeAuthFile(t, dir, "z-config", `{"auths":{"ghcr.io":{"auth":"Y29uZmlnOndpbnM="}}}`)

	auths := mergeRegistryAuths("", "", "", dir)

	body, err := json.Marshal(auths["ghcr.io"])
	if err != nil {
		t.Fatal(err)
	}
	// "z-config" sorts after "ghcr.io", so the docker config is applied
	// last and wins.
	if want := base64.StdEncoding.EncodeToString([]byte("config:wins")); !strings.Contains(string(body), want) {
		t.Errorf("later path did not win across source kinds: %s", body)
	}
}
