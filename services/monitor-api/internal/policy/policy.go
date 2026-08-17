// Package policy turns an artifact's scan results into a pass/fail
// gate a pipeline can act on.
//
// Everything this package needs is already on the artifact: findings
// with severities and lifecycle status, whether a digest was pinned,
// whether an SBOM was generated, when it was last scanned. The gap it
// fills is that "is this artifact acceptable" was previously a
// judgement each caller made for itself out of raw findings, so two
// pipelines reading the same artifact could reasonably disagree.
//
// Deliberately a separate package from internal/api: the rules are
// worth unit-testing without an HTTP server in the way, and nothing
// here needs a store, a request, or a context.
package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// Buckets is the finding-bucket vocabulary a policy may name, and it
// must stay identical to internal/api's validFindingsBucket.
//
// Duplicated rather than imported for the same reason
// internal/artifact duplicates internal/notify's severity table: api
// imports this package, so importing it back would be a cycle.
// TestPolicyBucketsMatchAPI (internal/api/policy_test.go) asserts the
// two agree, which is the part that actually matters -- a policy
// naming a bucket the API does not recognize would gate nothing.
var Buckets = []string{"cve", "malware", "misconfiguration", "secret", "other"}

// SeverityNone is the maxSeverity value meaning "no active finding at
// all is acceptable in this bucket".
//
// It exists because there is no severity below "unknown" to express
// that with. `{"malware": "none"}` is the common case -- any malware
// match is a failure regardless of what a scanner graded it -- and
// `"none"` is also the only way to catch findings graded "unknown",
// which legitimately rank below every real threshold.
const SeverityNone = "none"

// Policy is the rule set, as loaded from POLICY_JSON /
// monitorApi.policy.
//
// Every field's zero value means "this rule is not in force", so a
// policy naming one rule enforces exactly that rule and nothing else.
// A policy with no rules at all is a valid, meaningful thing -- see
// Configured.
type Policy struct {
	// MaxSeverity is the worst ACTIVE finding severity each bucket may
	// contain, e.g. {"cve": "high", "malware": "none"}. A bucket not
	// named here is not gated on severity at all.
	//
	// The named severity PASSES; anything worse fails. "high" admits
	// high, medium, low; it rejects critical. See SeverityNone for the
	// stricter end.
	MaxSeverity map[string]string `json:"maxSeverity,omitempty"`

	// DisallowUnsafe fails an artifact flagged Unsafe -- registered
	// while REQUIRE_DIGEST was on, with a ref whose digest could not be
	// confirmed to match. See artifact.Artifact.Unsafe.
	DisallowUnsafe bool `json:"disallowUnsafe,omitempty"`

	// RequireSBOM fails an artifact with no generated SBOM document.
	RequireSBOM bool `json:"requireSBOM,omitempty"`

	// RequireScanWithinDays fails an artifact whose last scan is older
	// than this many days -- and one that has never been scanned at
	// all, which is the stricter reading and the correct one: "I have
	// no idea what is in this" must not pass a freshness gate.
	RequireScanWithinDays int `json:"requireScanWithinDays,omitempty"`

	// LicenseDenylist fails an artifact carrying any active
	// denylisted-license finding, reusing the findings
	// scanner.LicenseDenylist already produced during a scan rather
	// than re-evaluating licenses here. This package never sees the
	// component inventory, and re-deriving would let the gate and the
	// findings disagree.
	LicenseDenylist bool `json:"licenseDenylist,omitempty"`
}

// Violation is one failed rule. FindingID is set only when a specific
// finding caused it, so a caller can link straight to the offender.
type Violation struct {
	Rule      string `json:"rule"`
	Detail    string `json:"detail"`
	FindingID string `json:"finding_id,omitempty"`
}

// Result is the evaluation outcome. Violations is never nil once
// encoded -- an empty JSON array reads better to a CI script than
// null, and "no violations" is the normal answer.
type Result struct {
	Pass       bool        `json:"pass"`
	Violations []Violation `json:"violations"`
	// Configured reports whether any rule was actually in force.
	//
	// Without it a caller cannot tell "cleared the gate" from "there is
	// no gate": both are pass=true with no violations. That matters
	// most where it is displayed -- the chart ships policy: {} by
	// default, so every default deployment would otherwise show a green
	// "policy passed" badge having checked nothing. See the dashboard's
	// policyBadge, and Policy.Configured.
	Configured bool `json:"configured"`
}

// Configured reports whether any rule is actually in force.
//
// The distinction matters to anything displaying the result: an
// artifact that passes a policy and an artifact with no policy to
// fail both have zero violations, and showing them identically is a
// green light nobody earned. See the dashboard's policyBadge.
func (p Policy) Configured() bool {
	return len(p.MaxSeverity) > 0 || p.DisallowUnsafe || p.RequireSBOM ||
		p.RequireScanWithinDays > 0 || p.LicenseDenylist
}

// Load parses POLICY_JSON. An empty string is the legitimate "no
// policy configured" case and is not an error; anything non-empty must
// parse and validate, because the failure mode of a broken policy is a
// gate that reports green while enforcing nothing.
//
// Unknown bucket names and unknown severities are rejected here rather
// than ignored at evaluation time, for that same reason: a typo'd
// {"cves": "high"} that gates nothing is exactly what this feature
// exists to prevent, and it is only ever catchable at load.
func Load(raw string) (Policy, error) {
	var p Policy
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return p, nil
	}

	dec := json.NewDecoder(strings.NewReader(raw))
	// An unknown top-level key is a typo'd RULE -- same class of
	// silent no-op as a typo'd bucket, and worth the same refusal.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("policy: %w", err)
	}

	for bucket, sev := range p.MaxSeverity {
		if !validBucket(bucket) {
			return Policy{}, fmt.Errorf("policy: maxSeverity names unknown bucket %q (valid: %s)",
				bucket, strings.Join(Buckets, ", "))
		}
		if !validMaxSeverity(sev) {
			return Policy{}, fmt.Errorf("policy: maxSeverity[%q] is %q, which is not a severity (valid: none, negligible, low, medium, high, critical)",
				bucket, sev)
		}
	}
	if p.RequireScanWithinDays < 0 {
		return Policy{}, fmt.Errorf("policy: requireScanWithinDays is %d, which cannot be negative", p.RequireScanWithinDays)
	}
	return p, nil
}

func validBucket(b string) bool {
	for _, known := range Buckets {
		if b == known {
			return true
		}
	}
	return false
}

func validMaxSeverity(s string) bool {
	if strings.EqualFold(strings.TrimSpace(s), SeverityNone) {
		return true
	}
	_, ok := artifact.SeverityRankOK(s)
	return ok
}

// Evaluate runs the policy against one artifact.
//
// now is a parameter rather than time.Now() so freshness is testable
// without sleeping.
//
// Only ACTIVE findings count -- artifact.Finding.IsActive excludes
// fixed ones and VEX-suppressed ones. That is the whole point of
// having assessed a finding: a critical CVE a human has already
// justified as not_affected must not keep failing a build, or the VEX
// document does nothing and people route around the gate.
func Evaluate(p Policy, a artifact.Artifact, now time.Time) Result {
	violations := []Violation{}

	if p.DisallowUnsafe && a.Unsafe {
		violations = append(violations, Violation{
			Rule:   "disallowUnsafe",
			Detail: "artifact was registered without a confirmed digest while REQUIRE_DIGEST was in force, so what this ref points at can change under it",
		})
	}

	if p.RequireSBOM && !a.HasSBOM {
		violations = append(violations, Violation{
			Rule:   "requireSBOM",
			Detail: "no SBOM document has been generated for this artifact",
		})
	}

	if p.RequireScanWithinDays > 0 {
		switch {
		case a.LastScanAt == nil:
			violations = append(violations, Violation{
				Rule:   "requireScanWithinDays",
				Detail: "artifact has never been scanned",
			})
		default:
			age := now.Sub(*a.LastScanAt)
			maxAge := time.Duration(p.RequireScanWithinDays) * 24 * time.Hour
			if age > maxAge {
				violations = append(violations, Violation{
					Rule: "requireScanWithinDays",
					Detail: fmt.Sprintf("last scanned %s, which is older than the %d day(s) this policy allows",
						a.LastScanAt.UTC().Format(time.RFC3339), p.RequireScanWithinDays),
				})
			}
		}
	}

	if p.LicenseDenylist {
		for _, f := range a.OtherFindings {
			if !f.IsActive() || !isLicenseFinding(f) {
				continue
			}
			violations = append(violations, Violation{
				Rule:      "licenseDenylist",
				Detail:    f.Title,
				FindingID: f.ID,
			})
		}
	}

	// Sorted bucket order so two evaluations of the same artifact
	// produce byte-identical output -- a CI job diffing this response
	// between runs should see a change only when something changed.
	buckets := make([]string, 0, len(p.MaxSeverity))
	for b := range p.MaxSeverity {
		buckets = append(buckets, b)
	}
	sort.Strings(buckets)

	for _, bucket := range buckets {
		violations = append(violations, evaluateBucket(bucket, p.MaxSeverity[bucket], findingsFor(a, bucket), p.LicenseDenylist)...)
	}

	return Result{Pass: len(violations) == 0, Violations: violations, Configured: p.Configured()}
}

// evaluateBucket applies one maxSeverity threshold.
//
// licenseRuleActive partitions the "other" bucket the same way
// internal/api's scanArtifact already partitions it for merging:
// when the licenseDenylist rule is in force it owns license findings,
// and reporting them a second time here would turn one denylisted
// dependency into two violations for the same fact. With that rule
// off, license findings are ordinary members of "other" and the
// severity threshold sees them.
func evaluateBucket(bucket, maxSeverity string, findings []artifact.Finding, licenseRuleActive bool) []Violation {
	var out []Violation
	none := strings.EqualFold(strings.TrimSpace(maxSeverity), SeverityNone)
	allowed, allowedOK := artifact.SeverityRankOK(maxSeverity)

	for _, f := range findings {
		if !f.IsActive() {
			continue
		}
		if licenseRuleActive && bucket == "other" && isLicenseFinding(f) {
			continue
		}

		if none {
			out = append(out, Violation{
				Rule:      "maxSeverity",
				Detail:    fmt.Sprintf("%s: %s finding %q is present, and this policy allows none", bucket, strings.ToLower(f.Severity), f.Title),
				FindingID: f.ID,
			})
			continue
		}

		rank, ok := artifact.SeverityRankOK(f.Severity)
		if !ok {
			// An unrecognized severity cannot be compared, and
			// treating it as the lowest possible one is how a policy
			// gate silently stops enforcing anything: SeverityRank
			// returns 0 for "moderate" exactly as it does for
			// "unknown". Failing here is the same direction IsActive
			// already fails in -- toward "still a problem".
			out = append(out, Violation{
				Rule:      "maxSeverity",
				Detail:    fmt.Sprintf("%s: finding %q has severity %q, which is not a severity this system recognizes, so it cannot be compared against the %q threshold", bucket, f.Title, f.Severity, maxSeverity),
				FindingID: f.ID,
			})
			continue
		}
		if allowedOK && rank > allowed {
			out = append(out, Violation{
				Rule:      "maxSeverity",
				Detail:    fmt.Sprintf("%s: %s finding %q exceeds the %q this policy allows", bucket, strings.ToLower(f.Severity), f.Title, strings.ToLower(maxSeverity)),
				FindingID: f.ID,
			})
		}
	}
	return out
}

// isLicenseFinding recognizes a denylisted-license finding by the
// Source scanner.LicenseDenylist stamps on every one it produces.
// Matched on Source rather than the "license:" id prefix because the
// id format is a display detail and the source is the contract.
func isLicenseFinding(f artifact.Finding) bool {
	return f.Source == artifact.LicenseFindingSource
}

// findingsFor maps a bucket name to the artifact list holding it.
// Every name in Buckets is handled; an unrecognized one returns
// nothing, which cannot happen after Load's validation.
func findingsFor(a artifact.Artifact, bucket string) []artifact.Finding {
	switch bucket {
	case "cve":
		return a.CVEFindings
	case "malware":
		return a.MalwareFindings
	case "misconfiguration":
		return a.MisconfigFindings
	case "secret":
		return a.SecretFindings
	case "other":
		return a.OtherFindings
	default:
		return nil
	}
}
