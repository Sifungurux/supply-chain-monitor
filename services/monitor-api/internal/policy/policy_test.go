package policy_test

import (
	"strings"
	"testing"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/policy"
)

var now = time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

func mustLoad(t *testing.T, raw string) policy.Policy {
	t.Helper()
	p, err := policy.Load(raw)
	if err != nil {
		t.Fatalf("Load(%q): %v", raw, err)
	}
	return p
}

func rules(t *testing.T, r policy.Result) []string {
	t.Helper()
	out := make([]string, 0, len(r.Violations))
	for _, v := range r.Violations {
		out = append(out, v.Rule)
	}
	return out
}

func TestLoad(t *testing.T) {
	t.Run("empty is a valid unconfigured policy, not an error", func(t *testing.T) {
		p, err := policy.Load("")
		if err != nil {
			t.Fatalf("Load(\"\"): %v", err)
		}
		if p.Configured() {
			t.Error("an empty policy reports itself configured")
		}
	})

	t.Run("whitespace only is also unconfigured", func(t *testing.T) {
		if p := mustLoad(t, "   \n "); p.Configured() {
			t.Error("whitespace parsed as a configured policy")
		}
	})

	t.Run("a full policy round-trips", func(t *testing.T) {
		p := mustLoad(t, `{
			"maxSeverity": {"cve": "high", "malware": "none"},
			"disallowUnsafe": true,
			"requireSBOM": true,
			"requireScanWithinDays": 7,
			"licenseDenylist": true
		}`)
		if !p.Configured() {
			t.Fatal("a policy with five rules reports itself unconfigured")
		}
		if p.MaxSeverity["cve"] != "high" || p.MaxSeverity["malware"] != "none" {
			t.Fatalf("maxSeverity = %+v", p.MaxSeverity)
		}
		if !p.DisallowUnsafe || !p.RequireSBOM || !p.LicenseDenylist || p.RequireScanWithinDays != 7 {
			t.Fatalf("policy = %+v", p)
		}
	})

	// Every case below is a policy that would otherwise gate NOTHING
	// while looking configured -- the exact failure this feature exists
	// to prevent, and only catchable at load.
	for _, tc := range []struct {
		name, raw, wantIn string
	}{
		{"unparseable json", `{"maxSeverity":`, "policy:"},
		{"typo'd bucket", `{"maxSeverity": {"cves": "high"}}`, "unknown bucket"},
		{"typo'd rule name", `{"maxSevrity": {"cve": "high"}}`, "unknown field"},
		{"severity that is not one", `{"maxSeverity": {"cve": "severe"}}`, "not a severity"},
		{"negative freshness", `{"requireScanWithinDays": -1}`, "cannot be negative"},
	} {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			_, err := policy.Load(tc.raw)
			if err == nil {
				t.Fatalf("Load(%s) accepted a policy that would enforce nothing", tc.raw)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantIn)
			}
		})
	}
}

func TestEvaluate_MaxSeverity(t *testing.T) {
	p := mustLoad(t, `{"maxSeverity": {"cve": "high"}}`)

	t.Run("the named severity passes", func(t *testing.T) {
		a := artifact.Artifact{CVEFindings: []artifact.Finding{
			{ID: "CVE-1", Severity: "high"},
			{ID: "CVE-2", Severity: "medium"},
			{ID: "CVE-3", Severity: "LOW"}, // case is not a severity
		}}
		if got := policy.Evaluate(p, a, now); !got.Pass {
			t.Fatalf("pass = false, want true: %+v", got.Violations)
		}
	})

	t.Run("worse than the named severity fails, and names the finding", func(t *testing.T) {
		a := artifact.Artifact{CVEFindings: []artifact.Finding{
			{ID: "CVE-1", Severity: "high"},
			{ID: "CVE-BAD", Severity: "critical", Title: "very bad"},
		}}
		got := policy.Evaluate(p, a, now)
		if got.Pass {
			t.Fatal("a critical finding passed a high threshold")
		}
		if len(got.Violations) != 1 || got.Violations[0].FindingID != "CVE-BAD" {
			t.Fatalf("violations = %+v, want exactly the critical one", got.Violations)
		}
	})

	t.Run("a bucket the policy does not name is not gated", func(t *testing.T) {
		a := artifact.Artifact{MalwareFindings: []artifact.Finding{{ID: "M1", Severity: "critical"}}}
		if got := policy.Evaluate(p, a, now); !got.Pass {
			t.Fatalf("an ungated bucket failed the policy: %+v", got.Violations)
		}
	})

	t.Run("none rejects any active finding at all", func(t *testing.T) {
		none := mustLoad(t, `{"maxSeverity": {"malware": "none"}}`)
		a := artifact.Artifact{MalwareFindings: []artifact.Finding{{ID: "M1", Severity: "negligible", Title: "eicar"}}}
		got := policy.Evaluate(none, a, now)
		if got.Pass {
			t.Fatal(`"none" admitted a negligible finding`)
		}
		// "none" is also the only way to catch a finding graded
		// "unknown", which legitimately ranks below every threshold.
		unknown := artifact.Artifact{MalwareFindings: []artifact.Finding{{ID: "M2", Severity: "unknown"}}}
		if policy.Evaluate(none, unknown, now).Pass {
			t.Fatal(`"none" admitted an unknown-severity finding`)
		}
	})

	// The bug this guards: artifact.SeverityRank returns 0 for an
	// unrecognized string exactly as it does for the legitimate
	// "unknown", so comparing ranks alone lets a scanner that spells
	// severities differently walk straight through every threshold
	// while the gate reports green.
	t.Run("an unrecognized severity fails rather than ranking as harmless", func(t *testing.T) {
		a := artifact.Artifact{CVEFindings: []artifact.Finding{{ID: "CVE-X", Severity: "moderate", Title: "odd grading"}}}
		got := policy.Evaluate(p, a, now)
		if got.Pass {
			t.Fatal(`a "moderate" finding passed a "high" threshold -- an unrecognized severity must not rank as the lowest one`)
		}
		if !strings.Contains(got.Violations[0].Detail, "not a severity this system recognizes") {
			t.Errorf("detail = %q, want it to explain why it could not be compared", got.Violations[0].Detail)
		}
	})

	// The reason IsActive exists. A human assessed this and said it
	// does not apply; if the gate keeps failing on it, the VEX document
	// does nothing and people route around the gate.
	t.Run("fixed and VEX-suppressed findings do not fail policy", func(t *testing.T) {
		a := artifact.Artifact{CVEFindings: []artifact.Finding{
			{ID: "CVE-FIXED", Severity: "critical", Status: artifact.FindingStatusFixed},
			{ID: "CVE-VEX", Severity: "critical", Status: artifact.FindingStatusNotAffected},
		}}
		if got := policy.Evaluate(p, a, now); !got.Pass {
			t.Fatalf("pass = false, want true -- neither finding is active: %+v", got.Violations)
		}
	})

	t.Run("a finding with no status counts as active", func(t *testing.T) {
		// Persisted before the lifecycle columns existed; IsActive
		// treats these as open and so must the gate.
		a := artifact.Artifact{CVEFindings: []artifact.Finding{{ID: "CVE-OLD", Severity: "critical"}}}
		if policy.Evaluate(p, a, now).Pass {
			t.Fatal("a status-less critical finding passed")
		}
	})
}

func TestEvaluate_Flags(t *testing.T) {
	t.Run("disallowUnsafe", func(t *testing.T) {
		p := mustLoad(t, `{"disallowUnsafe": true}`)
		if policy.Evaluate(p, artifact.Artifact{Unsafe: true}, now).Pass {
			t.Fatal("an unsafe artifact passed")
		}
		if !policy.Evaluate(p, artifact.Artifact{}, now).Pass {
			t.Fatal("a safe artifact failed")
		}
	})

	t.Run("requireSBOM", func(t *testing.T) {
		p := mustLoad(t, `{"requireSBOM": true}`)
		if policy.Evaluate(p, artifact.Artifact{}, now).Pass {
			t.Fatal("an artifact with no SBOM passed")
		}
		if !policy.Evaluate(p, artifact.Artifact{HasSBOM: true}, now).Pass {
			t.Fatal("an artifact with an SBOM failed")
		}
	})

	t.Run("requireScanWithinDays", func(t *testing.T) {
		p := mustLoad(t, `{"requireScanWithinDays": 7}`)

		fresh := now.Add(-2 * 24 * time.Hour)
		if !policy.Evaluate(p, artifact.Artifact{LastScanAt: &fresh}, now).Pass {
			t.Error("a 2-day-old scan failed a 7-day policy")
		}
		stale := now.Add(-8 * 24 * time.Hour)
		if policy.Evaluate(p, artifact.Artifact{LastScanAt: &stale}, now).Pass {
			t.Error("an 8-day-old scan passed a 7-day policy")
		}
		// Never scanned must FAIL, not pass on a nil check: "I have no
		// idea what is in this" is not freshness.
		got := policy.Evaluate(p, artifact.Artifact{}, now)
		if got.Pass {
			t.Fatal("a never-scanned artifact passed a freshness policy")
		}
		if !strings.Contains(got.Violations[0].Detail, "never been scanned") {
			t.Errorf("detail = %q, want it to say the artifact was never scanned", got.Violations[0].Detail)
		}
	})
}

func TestEvaluate_LicenseDenylist(t *testing.T) {
	denied := artifact.Finding{
		ID:       artifact.LicenseFindingID("pkg:npm/left-pad@1.0.0"),
		Severity: "medium",
		Title:    "left-pad is licensed GPL-3.0-only, which this deployment denies",
		Source:   artifact.LicenseFindingSource,
	}

	t.Run("an active denylisted license fails", func(t *testing.T) {
		p := mustLoad(t, `{"licenseDenylist": true}`)
		got := policy.Evaluate(p, artifact.Artifact{OtherFindings: []artifact.Finding{denied}}, now)
		if got.Pass {
			t.Fatal("a denylisted license passed")
		}
		if got.Violations[0].Rule != "licenseDenylist" || got.Violations[0].FindingID != denied.ID {
			t.Fatalf("violation = %+v", got.Violations[0])
		}
	})

	t.Run("a suppressed license finding does not fail", func(t *testing.T) {
		p := mustLoad(t, `{"licenseDenylist": true}`)
		suppressed := denied
		suppressed.Status = artifact.FindingStatusNotAffected
		if !policy.Evaluate(p, artifact.Artifact{OtherFindings: []artifact.Finding{suppressed}}, now).Pass {
			t.Fatal("a VEX-suppressed license finding failed the gate")
		}
	})

	t.Run("a non-license other finding is untouched by the rule", func(t *testing.T) {
		p := mustLoad(t, `{"licenseDenylist": true}`)
		other := artifact.Finding{ID: "SAST-1", Severity: "critical", Source: "sarif"}
		if !policy.Evaluate(p, artifact.Artifact{OtherFindings: []artifact.Finding{other}}, now).Pass {
			t.Fatal("licenseDenylist failed a finding that is not a license finding")
		}
	})

	// The partition. With both rules in force, one denylisted
	// dependency is one fact and must produce one violation -- not a
	// licenseDenylist violation AND a maxSeverity[other] violation.
	t.Run("does not double-report with maxSeverity on the other bucket", func(t *testing.T) {
		p := mustLoad(t, `{"licenseDenylist": true, "maxSeverity": {"other": "low"}}`)
		got := policy.Evaluate(p, artifact.Artifact{OtherFindings: []artifact.Finding{denied}}, now)
		if len(got.Violations) != 1 {
			t.Fatalf("violations = %+v, want exactly 1 for one denylisted dependency", got.Violations)
		}
		if got.Violations[0].Rule != "licenseDenylist" {
			t.Errorf("rule = %q, want licenseDenylist to own license findings", got.Violations[0].Rule)
		}
	})

	// ...but with the license rule OFF, license findings are ordinary
	// members of "other" and the severity threshold must still see them.
	t.Run("with the license rule off the severity threshold still sees them", func(t *testing.T) {
		p := mustLoad(t, `{"maxSeverity": {"other": "low"}}`)
		got := policy.Evaluate(p, artifact.Artifact{OtherFindings: []artifact.Finding{denied}}, now)
		if got.Pass {
			t.Fatal("a medium license finding passed a low threshold while licenseDenylist was off")
		}
		if got.Violations[0].Rule != "maxSeverity" {
			t.Errorf("rule = %q, want maxSeverity", got.Violations[0].Rule)
		}
	})
}

func TestEvaluate_Unconfigured(t *testing.T) {
	// A policy with no rules passes everything -- and Configured is how
	// a caller tells that apart from actually clearing a gate.
	p := mustLoad(t, "")
	a := artifact.Artifact{
		Unsafe:          true,
		CVEFindings:     []artifact.Finding{{ID: "CVE-1", Severity: "critical"}},
		MalwareFindings: []artifact.Finding{{ID: "M1", Severity: "critical"}},
	}
	got := policy.Evaluate(p, a, now)
	if !got.Pass || len(got.Violations) != 0 {
		t.Fatalf("an unconfigured policy found violations: %+v", got.Violations)
	}
	if p.Configured() {
		t.Error("Configured() = true for a policy with no rules -- the dashboard needs this to avoid showing an unearned green badge")
	}
	if got.Configured {
		t.Error("Result.Configured = true with no policy -- a caller cannot then tell 'cleared the gate' from 'there is no gate'")
	}
	// ...and it must be true when there IS a policy, or the flag is
	// just a constant.
	configured := mustLoad(t, `{"disallowUnsafe": true}`)
	if !policy.Evaluate(configured, artifact.Artifact{}, now).Configured {
		t.Error("Result.Configured = false for a policy with a rule in force")
	}
}

func TestEvaluate_ViolationOrderIsStable(t *testing.T) {
	// A CI job diffing this response between runs should see a change
	// only when something actually changed; Go map iteration order
	// would otherwise reshuffle bucket violations every call.
	p := mustLoad(t, `{"maxSeverity": {"cve": "low", "malware": "low", "secret": "low", "other": "low", "misconfiguration": "low"}}`)
	a := artifact.Artifact{
		CVEFindings:       []artifact.Finding{{ID: "c", Severity: "critical"}},
		MalwareFindings:   []artifact.Finding{{ID: "m", Severity: "critical"}},
		SecretFindings:    []artifact.Finding{{ID: "s", Severity: "critical"}},
		OtherFindings:     []artifact.Finding{{ID: "o", Severity: "critical"}},
		MisconfigFindings: []artifact.Finding{{ID: "i", Severity: "critical"}},
	}
	first := rules(t, policy.Evaluate(p, a, now))
	for i := 0; i < 20; i++ {
		got := rules(t, policy.Evaluate(p, a, now))
		if len(got) != len(first) {
			t.Fatalf("violation count changed between runs: %d then %d", len(first), len(got))
		}
	}
	ids := []string{}
	for _, v := range policy.Evaluate(p, a, now).Violations {
		ids = append(ids, v.FindingID)
	}
	// Sorted bucket order: cve, malware, misconfiguration, other, secret
	// ("mal" sorts before "mis").
	want := "c m i o s"
	if got := strings.Join(ids, " "); got != want {
		t.Fatalf("violation order = %q, want %q (buckets in sorted order)", got, want)
	}
}
