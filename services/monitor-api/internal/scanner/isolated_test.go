package scanner

import "testing"

// The 256Mi flat limit these replaced evicted every "image"-mode
// trivy/grype Job that scanned a non-trivial image ("Pod ephemeral local
// storage usage exceeds the total limit of containers 256Mi"), because
// both tools extract the image to /tmp. See isolated.go.
func TestEphemeralStorageDefaultsBySubCommand(t *testing.T) {
	for _, tc := range []struct {
		subCommand    string
		request, want string
	}{
		{"image", "512Mi", "2Gi"},
		{"sbom", "128Mi", "256Mi"},
		{"", "512Mi", "2Gi"}, // unset means image -- see each withDefaults
	} {
		if got := ephemeralStorageRequestFor(tc.subCommand); got != tc.request {
			t.Errorf("request for %q = %q, want %q", tc.subCommand, got, tc.request)
		}
		if got := ephemeralStorageLimitFor(tc.subCommand); got != tc.want {
			t.Errorf("limit for %q = %q, want %q", tc.subCommand, got, tc.want)
		}
	}

	// The defaults have to actually reach the Job spec, not just exist.
	trivy := IsolatedTrivyConfig{SubCommand: "image"}.withDefaults()
	if trivy.EphemeralStorageLimit != "2Gi" {
		t.Errorf("trivy image EphemeralStorageLimit = %q, want 2Gi", trivy.EphemeralStorageLimit)
	}
	if sbom := (IsolatedTrivyConfig{SubCommand: "sbom"}).withDefaults(); sbom.EphemeralStorageLimit != "256Mi" {
		t.Errorf("trivy sbom EphemeralStorageLimit = %q, want 256Mi", sbom.EphemeralStorageLimit)
	}
	grype := IsolatedGrypeConfig{SubCommand: "image"}.withDefaults()
	if grype.EphemeralStorageLimit != "2Gi" {
		t.Errorf("grype image EphemeralStorageLimit = %q, want 2Gi", grype.EphemeralStorageLimit)
	}
	if sbom := (IsolatedGrypeConfig{SubCommand: "sbom"}).withDefaults(); sbom.EphemeralStorageLimit != "256Mi" {
		t.Errorf("grype sbom EphemeralStorageLimit = %q, want 256Mi", sbom.EphemeralStorageLimit)
	}
	unpacker := IsolatedUnpackerConfig{}.withDefaults()
	if unpacker.EphemeralStorageLimit != "2Gi" || unpacker.EphemeralStorageRequest != "512Mi" {
		t.Errorf("unpacker eph = %q/%q, want 512Mi/2Gi",
			unpacker.EphemeralStorageRequest, unpacker.EphemeralStorageLimit)
	}
}
