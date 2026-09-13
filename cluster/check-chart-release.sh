#!/bin/sh
# Guards the one class of chart-release bug that is invisible until
# somebody tries to install the result: a version that does not mean
# what it says.
#
# Two things are checked, and they run at two different times:
#
#   1. Chart.yaml's `version:` is valid SemVer 2. Helm REQUIRES this --
#      `helm package` refuses a malformed version -- but it refuses at
#      release time, on a tag, which is the worst possible moment to
#      find out. Run on every PR instead, where the fix is an edit.
#
#   2. With RELEASE_TAG set (the release workflow passes the git tag),
#      the tag and Chart.yaml must agree. A tag of chart-v0.2.0 on a
#      Chart.yaml still saying 0.1.0 publishes a chart whose version is
#      0.1.0 while every human reference to it says 0.2.0. The registry
#      will not catch that: an OCI tag is MUTABLE -- verified against a
#      real registry, a second push under the same tag silently
#      replaces the first -- so nothing rejects the mistake, and the
#      only repair is overwriting a version other people may already
#      have pulled. That is the mutable-tag hazard this project exists
#      to warn about, which makes "refuse before publishing" the only
#      consistent answer. This check is what makes Chart.yaml the
#      single source of truth rather than one of two places a version
#      lives.
#
# appVersion is deliberately NOT checked here: the release workflow
# stamps it from the tagged commit's own short SHA (see
# .github/workflows/release-chart.yml), so whatever is in the working
# tree is a placeholder and asserting anything about it would be
# asserting something about a value nothing ships.
set -eu

chart_file="charts/supply-chain-monitor/Chart.yaml"

# The first top-level `version:` line. "apiVersion:" does not match --
# the anchor is what keeps this from reading the wrong field.
version=$(awk -F': *' '/^version:/ {gsub(/"/, "", $2); print $2; exit}' "$chart_file")

if [ -z "$version" ]; then
	echo "ERROR: no top-level 'version:' in $chart_file" >&2
	exit 1
fi

# SemVer 2, which is what Helm requires of a chart version: three
# numeric parts, an optional -prerelease (this is what makes an RC an
# RC, and what makes `helm install` skip it unless asked), and an
# optional +build.
if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
	echo "ERROR: chart version '$version' is not valid SemVer 2 -- helm package will refuse it." >&2
	echo "       Expected MAJOR.MINOR.PATCH, optionally -prerelease (e.g. 0.1.0-rc.1)." >&2
	exit 1
fi

echo "ok:   chart version $version is valid SemVer"

if [ -n "${RELEASE_TAG:-}" ]; then
	expected="chart-v$version"
	if [ "$RELEASE_TAG" != "$expected" ]; then
		echo "ERROR: tag '$RELEASE_TAG' does not match $chart_file." >&2
		echo "       Chart.yaml says version $version, so the tag must be '$expected'." >&2
		echo "       Fix the tag, or bump Chart.yaml and tag again -- do not publish the mismatch." >&2
		exit 1
	fi
	echo "ok:   tag $RELEASE_TAG matches the chart version"
fi
