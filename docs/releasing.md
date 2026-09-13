# Releasing the Helm chart

The chart is published as an **OCI artifact in ghcr**, versioned with
SemVer and cut from a git tag. Everything below is automated by
[`.github/workflows/release-chart.yml`](../.github/workflows/release-chart.yml);
this page is the why, and the one manual step.

## What a release is, and what it is not

This project's own cluster does **not** consume released charts. Flux
reads the chart straight out of the repository
(`reconcileStrategy: Revision`, see
[`k8s/releases/supply-chain-monitor-helmrelease.yaml`](../k8s/releases/supply-chain-monitor-helmrelease.yaml)),
so every push to `main` reaches the cluster immediately and a release
changes nothing about that loop. A release exists so that *somebody
else* can install a known version:

```
helm install scm oci://ghcr.io/sifungurux/supply-chain-monitor/charts/supply-chain-monitor --version 0.1.0-rc.1
```

Release candidates are marked as such in the version (`-rc.N`), and
that is not cosmetic: `helm install`, `helm upgrade` and Flux all skip
SemVer prereleases unless a constraint asks for one explicitly, so an
RC cannot be picked up by accident.

## Two version numbers, deliberately

| Field | Means | Set by |
| --- | --- | --- |
| `version` | the chart's own version | a human, in Chart.yaml |
| `appVersion` | the monitor-api build this chart was cut against | the release workflow, from the tagged commit's short SHA |

They move **independently**. A values-only fix to this chart is a new
chart version and the same app; a new monitor-api build is a new
appVersion and, often, the same chart. Tying them together would mean
one of the two numbers is always lying.

`appVersion` is stamped rather than committed because there is exactly
one correct value and a human would have to remember it: the short SHA
of the tagged commit is what `publish-image` tagged the monitor-api
image with for that same commit. The working tree keeps `"dev"` as a
placeholder, which is never what ships.

## Cutting a release

1. **Bump the version** in `charts/supply-chain-monitor/Chart.yaml`, in
   a PR, so the number lands in a reviewable diff next to whatever
   justifies it. CI checks it is valid SemVer (`make check-chart-version`).
2. **Merge to main** and wait for `publish-image` to finish. This is the
   step people skip: `publish-image` is main-only, so a tag on any other
   commit names a monitor-api image that does not exist. The release
   workflow refuses that rather than shipping it, but finding out on the
   tag is slower than waiting two minutes here.
3. **Tag and push**:

   ```
   git tag chart-v0.1.0-rc.1
   git push origin chart-v0.1.0-rc.1
   ```

   The tag must match Chart.yaml exactly (`chart-v` + the version). The
   workflow refuses a mismatch, and it has to: an OCI tag is **mutable**
   — a second push under the same tag silently replaces the first — so
   the registry will not reject the mistake, and the only repair is
   overwriting a version other people may already have pulled. That is
   the mutable-tag hazard this project exists to warn about, which makes
   refusing before the push the only consistent answer.

The workflow then re-runs the chart checks (a tag can point at any
commit, including one that never went through a PR), packages, pushes to
ghcr, attests the pushed digest, and creates a GitHub Release — marked
prerelease automatically when the version carries a prerelease part.

## Verifying a release

```
gh attestation verify oci://ghcr.io/sifungurux/supply-chain-monitor/charts/supply-chain-monitor@<digest> --repo Sifungurux/supply-chain-monitor
```

Same provenance path as the monitor-api image, and the same constraint:
it works because this repository is public. See `publish-image` in
[`ci.yml`](../.github/workflows/ci.yml) for what a private repository
gets instead.

## Installing the chart standalone

The chart's default `monitorApi.image` is the locally built
`monitor-api:dev`, so a fresh clone with no ghcr access can still run
it. Installing a *release* somewhere else means pointing that at the
published image — ideally by digest, which is the only reference that
names one specific build:

```
helm install scm oci://ghcr.io/sifungurux/supply-chain-monitor/charts/supply-chain-monitor \
  --version 0.1.0-rc.1 \
  --set monitorApi.image.repository=ghcr.io/sifungurux/supply-chain-monitor/monitor-api \
  --set monitorApi.image.digest=sha256:...
```

The release notes name the appVersion the chart was cut against, which
is the image tag to resolve that digest from.
