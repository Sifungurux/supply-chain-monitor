package api

import (
	"strings"
	"testing"
)

// The bypass that the first version of csvSafe had: it tested s[0], so
// ONE LEADING SPACE walked a formula straight through. An importer that
// trims leading whitespace then evaluates it.
//
// Table rather than prose because the whole point is that it does not
// matter which whitespace a given spreadsheet trims -- every one of
// these has to come back neutralised.
func TestCSVSafe(t *testing.T) {
	for _, tc := range []struct {
		in       string
		wantSafe bool
		why      string
	}{
		{"=1+1", true, "the plain case"},
		{"+1", true, ""},
		{"-1", true, ""},
		{"@SUM(A1)", true, ""},
		{"\t=1+1", true, "leading tab"},
		{"\r=1+1", true, "leading CR"},

		// The bypass.
		{" =1+1", true, "ONE LEADING SPACE defeated the s[0] check"},
		{"   =cmd|'/c calc'!A1", true, "several spaces"},
		{"\n=1+1", true, "leading newline"},
		{" =1+1", true, "non-breaking space -- trimmed by some importers"},
		{" \t \n =1+1", true, "mixed leading whitespace"},

		// Must NOT be touched: prefixing everything would corrupt the
		// export to buy nothing.
		{"CVE-2024-1234", false, "a CVE id contains - but does not lead with one"},
		{"ghcr.io/acme/app:1", false, ""},
		{"not a formula", false, ""},
		{" leading space, no formula", false, ""},
		{"", false, "empty"},
		{"   ", false, "whitespace only -- nothing to evaluate"},
	} {
		got := csvSafe(tc.in)
		prefixed := strings.HasPrefix(got, "'")
		if prefixed != tc.wantSafe {
			t.Errorf("csvSafe(%q) = %q (prefixed=%v), want prefixed=%v %s",
				tc.in, got, prefixed, tc.wantSafe, tc.why)
		}
		// Neutralised, never destroyed: a human reading the export must
		// still see what the field said.
		if !strings.HasSuffix(got, tc.in) {
			t.Errorf("csvSafe(%q) = %q -- the original text must survive", tc.in, got)
		}
	}
}
