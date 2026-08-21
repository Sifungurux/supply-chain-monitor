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
