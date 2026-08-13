package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/artifact"
)

// MalcontentScanner shells out to Chainguard's malcontent (`mal`) to
// scan an image for malicious *behaviours* -- a second malware scanner
// alongside ClamAV, answering a question ClamAV cannot.
//
// The two are complementary, not redundant, and it's worth being precise
// about how: ClamAV matches signatures of known-bad files, so a hit is
// "this IS a known threat" and a miss says nothing about novel malware.
// malcontent matches YARA rules describing capabilities -- "this binary
// reads /proc/net/route", "this hides files like a userspace rootkit" --
// so a hit is "this CAN do something a compromised package would do",
// which is exactly the signal a supply-chain attack leaves and exactly
// the signal a legitimate system utility also leaves.
//
// That cuts both ways and the default reflects it: measured against a
// stock alpine:3.19 at --min-risk medium, malcontent reports four HIGH
// behaviours (busybox exec patterns, /dev/shm references, route
// lookups) on an image nobody would call compromised. The chart
// therefore defaults minRisk to "critical" -- see
// values.yaml's monitorApi.malcontent.minRisk. Lower it deliberately,
// with the understanding that "high" will put findings on most images
// in a normal fleet.
//
// Nothing is downloaded at scan time: malcontent embeds its rules (it
// advertises air-gapped support), so unlike trivy/grype there is no
// vulnerability DB to mirror, no refresh CronJob, and no cache PVC.
type MalcontentScanner struct {
	// bin is the malcontent binary. The upstream container's entrypoint
	// is /usr/bin/mal, and that is the name the Dockerfile copies in.
	bin string
	// minRisk is passed through as --min-risk (any, low, medium, high,
	// critical). Empty means the binary's own default, which is "low" --
	// far too noisy for this to be worth reading, hence the chart's
	// "critical".
	minRisk string
	// dockerConfigDir, when set, is exported as DOCKER_CONFIG so
	// malcontent's own image pull authenticates against a private
	// registry -- the same mechanism GrypeScanner uses (see grype.go),
	// since both pull the image themselves rather than being handed a
	// local path.
	dockerConfigDir string
}

func NewMalcontentScanner(bin, minRisk, dockerConfigDir string) *MalcontentScanner {
	if bin == "" {
		bin = "mal"
	}
	return &MalcontentScanner{bin: bin, minRisk: minRisk, dockerConfigDir: dockerConfigDir}
}

// Bucket implements BucketAffinity: every finding this produces is a
// malware-bucket finding, so a malcontent failure blocks fix-detection
// for that bucket alone and leaves CVE findings untouched (see
// MergeFindings' detectFixed and internal/api/scan.go's blockedBuckets).
func (s *MalcontentScanner) Bucket() string { return "malware" }

// args builds the CLI invocation. Split out from Scan for the same
// reason TrivyScanner.args is: it can be asserted in a unit test
// without a malcontent binary present.
//
// Global flags come BEFORE the subcommand -- `mal --format json
// --min-risk critical scan --image REF` -- which is what the binary's
// own usage line specifies ("mal [GLOBAL FLAGS] <command> [COMMAND
// FLAGS]"), and putting --format after `scan` silently gets a different
// parse.
func (s *MalcontentScanner) args(ref string) []string {
	args := []string{"--format", "json"}
	if s.minRisk != "" {
		args = append(args, "--min-risk", s.minRisk)
	}
	return append(args, "scan", "--image", ref)
}

func (s *MalcontentScanner) Scan(ctx context.Context, ref string) ([]artifact.Finding, error) {
	cmd := exec.CommandContext(ctx, s.bin, s.args(ref)...)
	if s.dockerConfigDir != "" {
		cmd.Env = append(cmd.Environ(), "DOCKER_CONFIG="+s.dockerConfigDir)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// No --exit-first-hit/--exit-first-miss is passed, so a non-zero
		// exit here is a real failure (bad ref, pull denied, panic), not
		// "findings were present".
		return nil, fmt.Errorf("malcontent scan %q: %w (%s)", ref, err, truncateForError(stderr.String()))
	}
	return ParseMalcontentReport(stdout.Bytes())
}

// ParseMalcontentReport turns malcontent's `--format json` output into
// findings. Verified against real output (`mal --format json --min-risk
// medium scan --image alpine:3.19`), kept verbatim as
// testdata/malcontent_report_sample.json -- the report is a map of file
// path to that file's behaviours:
//
//	{"Files": {"<path>": {"Path", "SHA256", "Size", "RiskLevel",
//	                      "Behaviors": [{"ID", "RuleName", "Description",
//	                                     "RiskLevel", "RuleURL", ...}]}}}
//
// One finding per RULE, not per file: a rule that matches twenty files
// in an image is one behaviour worth one line, and Finding.ID has to be
// stable across scans for MergeFindings' per-ID lifecycle to work at all
// (a path-based id would churn every time a layer changed). So the
// finding's ID is the rule id ("exec/shell/busybox_exec"), its severity
// is the worst risk that rule scored across the files it matched, and
// the count of matched files rides in the title -- which is what the
// dashboard shows for malware findings, since those lead with the title
// rather than the id.
func ParseMalcontentReport(raw []byte) ([]artifact.Finding, error) {
	var report struct {
		Files map[string]struct {
			Path      string `json:"Path"`
			Behaviors []struct {
				ID          string `json:"ID"`
				RuleName    string `json:"RuleName"`
				Description string `json:"Description"`
				RiskLevel   string `json:"RiskLevel"`
			} `json:"Behaviors"`
		} `json:"Files"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse malcontent report: %w", err)
	}

	type agg struct {
		finding artifact.Finding
		files   map[string]bool
		rank    int
	}
	byRule := make(map[string]*agg)
	order := make([]string, 0, len(report.Files))

	for path, file := range report.Files {
		for _, b := range file.Behaviors {
			id := strings.TrimSpace(b.ID)
			if id == "" {
				// Nothing stable to key a finding on, and a finding whose
				// id changes between scans is a finding that is "new"
				// forever. RuleName is the documented fallback shape;
				// skipping is the honest last resort.
				if id = strings.TrimSpace(b.RuleName); id == "" {
					continue
				}
			}
			g, ok := byRule[id]
			if !ok {
				g = &agg{
					finding: artifact.Finding{
						ID:       id,
						Title:    b.Description,
						Source:   "malcontent",
						Category: "malware",
					},
					files: map[string]bool{},
					rank:  -1,
				}
				byRule[id] = g
				order = append(order, id)
			}
			if p := file.Path; p != "" {
				g.files[p] = true
			} else {
				g.files[path] = true
			}
			if r := malcontentRiskRank(b.RiskLevel); r > g.rank {
				g.rank = r
				g.finding.Severity = malcontentSeverity(b.RiskLevel)
			}
			if g.finding.Title == "" {
				g.finding.Title = b.RuleName
			}
		}
	}

	// Deterministic order: severity first (worst on top, which is how
	// anyone reads a malware list), then rule id. Map iteration order
	// would otherwise reshuffle findings between two scans of the same
	// unchanged image.
	sort.Slice(order, func(i, j int) bool {
		a, b := byRule[order[i]], byRule[order[j]]
		if a.rank != b.rank {
			return a.rank > b.rank
		}
		return order[i] < order[j]
	})

	out := make([]artifact.Finding, 0, len(order))
	for _, id := range order {
		g := byRule[id]
		f := g.finding
		if n := len(g.files); n > 1 {
			f.Title = fmt.Sprintf("%s (%d files)", f.Title, n)
		}
		out = append(out, f)
	}
	return out, nil
}

// malcontentSeverity maps malcontent's risk levels onto this project's
// severity vocabulary (see internal/notify's severityRank and
// artifact.SeverityRank, which agree on these spellings). Anything
// unrecognized becomes "unknown" rather than guessing upward: unknown
// ranks 0 in both tables, so a risk level this parser has never seen
// can never page anyone on its own.
func malcontentSeverity(riskLevel string) string {
	switch strings.ToLower(strings.TrimSpace(riskLevel)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "unknown"
	}
}

func malcontentRiskRank(riskLevel string) int {
	switch malcontentSeverity(riskLevel) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// truncateForError bounds how much of a failed command's stderr ends up
// in an error string -- malcontent is chatty on failure, and the whole
// message is logged and classified by ClassifyScanError upstream.
func truncateForError(s string) string {
	s = strings.TrimSpace(s)
	const max = 2000
	if len(s) > max {
		return s[:max] + "... (truncated)"
	}
	return s
}
