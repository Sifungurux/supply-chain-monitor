# flux-system

Flux's controllers are installed here via the community
[`fluxcd-community/flux2`](https://github.com/fluxcd-community/helm-charts)
Helm chart, not `flux bootstrap` -- a deliberate choice for this project.

**This is automated** -- `make cluster-up` runs `cluster/install-flux.sh`
at the end of standing up the cluster, so a fresh `make cluster-up`
leaves you with Flux already installed and its Git sync applied, no
manual steps below required. This file documents what that script does
and why, and gives you the standalone commands for whenever you want to
run a piece of it by hand (e.g. after editing `values.yaml`, or
re-running just the Flux install against a cluster that's already up:
`make flux-install`).

## Why this directory reconciles itself

Every service in this project (registry, clamav, postgres, monitor-api,
dashboard) now deploys as a Helm chart via a `HelmRelease` under
`k8s/releases/` (see `docs/architecture.md`, "All services on Flux +
Helm"). `gotk-sync.yaml`'s root `Kustomization` has `path: ./k8s` --
the *whole* `k8s/` tree, including this `flux-system/` directory itself.
That means Flux reconciles its own bootstrap definition as part of every
sync, which is normal (it's exactly how `flux bootstrap` output behaves
too) and just keeps this directory self-consistent with whatever's
actually committed.

## Prerequisites

1. **This project needs to be a Git repository with a remote.** Flux
   polls Git, not the filesystem. `gotk-sync.yaml`'s `GitRepository.spec.url`
   needs to point at wherever you actually push this repo -- until it's
   pushed and reachable, the install still succeeds, the `GitRepository`
   just won't go `Ready` yet.
2. **Helm 3** and a working kubeconfig context pointing at the target
   cluster (the k3d/colima cluster this project already uses for local
   dev works fine) -- both required by `cluster/install-flux.sh`, which
   fails fast with an install hint if either is missing.
3. **A working `flux-system-git-auth` Secret**, since
   `sifungurux/supply-chain-monitor` is a *private* repo -- see "Private
   repo authentication" below. Without it the `GitRepository` clones
   anonymously, which GitHub answers with a 404 (not a 403 -- see why
   below), and nothing under `k8s/releases/` ever reconciles.

## Private repo authentication

`gotk-sync.yaml`'s `GitRepository` has `spec.secretRef: {name:
flux-system-git-auth}`. That Secret is cluster state, not a file in
this repo -- it's never committed, and needs to be created once per
cluster (and again any time you rotate the token):

```sh
make git-auth   # prompts for a GitHub username + personal access token
                # (or set GIT_USERNAME/GIT_PASSWORD to skip the prompts)
make git-test   # does a plain `git ls-remote` with those same
                # credentials, so you know in seconds whether they work
                # -- much faster feedback than waiting on Flux's own
                # reconcile/retry loop to eventually report the same thing
```

The token needs read access to this repo: a fine-grained PAT scoped to
just `supply-chain-monitor` with "Contents: Read-only" is enough; a
classic PAT with the `repo` scope also works. Create one at
https://github.com/settings/tokens.

`cluster/install-flux.sh` (`make flux-install`, and therefore
`make cluster-up` too) runs `make git-test`'s check automatically right
after applying the Git sync, *if* the Secret already exists -- purely
informational, it won't fail the install either way. If the Secret
doesn't exist yet, it prints a reminder to run `make git-auth` instead
of trying to prompt for credentials mid-install.

Why a 404 and not a 403: GitHub deliberately returns "repository not
found" for both a private repo you're not authorized to see *and* a
repo that doesn't exist at that URL at all -- distinguishing the two
would let an unauthenticated caller confirm a private repo's existence.
So if `make git-test` fails, check the token's scope/expiry and the
URL/owner/name for typos -- the error message looks the same either
way.

## What `cluster/install-flux.sh` (`make flux-install`) does

1. Adds/updates the `fluxcd-community` Helm repo and creates the
   `flux-system` namespace if it doesn't exist yet.
2. `helm upgrade --install flux2 fluxcd-community/flux2 --values
   values.yaml` -- installs or upgrades the controllers (idempotent,
   safe to re-run any time).
3. Waits for Flux's CRDs to reach `Established`, then waits for the
   controller Deployments to reach `Available` -- deliberately *not*
   `helm ... --wait` for the install step itself. This chart applies its
   CRDs as regular templates, and on a fresh install Helm's own
   readiness check can get stuck reporting a CRD as `InProgress` and
   fail with `context deadline exceeded` even though the CRD finishes
   establishing within seconds -- a real error you may see on a first
   run (`Error: resource CustomResourceDefinition/.../...toolkit.fluxcd.io
   not ready`), and a known rough edge of this specific community chart,
   not a sign anything is actually broken. Waiting on each resource
   type's own well-understood condition instead sidesteps that flakiness
   rather than papering over it with a bigger timeout.
4. `kubectl apply -k k8s/flux-system/` -- applies the Git sync (see
   below), since the Helm chart only installs controllers/CRDs, not this
   part (that's normally `flux bootstrap`'s job).
5. Prints `kubectl -n flux-system get pods` and `flux get kustomizations
   -A` / `flux get helmreleases -A` (or the `kubectl` equivalents if the
   `flux` CLI isn't installed) so you can see the result immediately.

Set `SCM_SKIP_FLUX=1` before `make cluster-up` to skip this entirely,
and run `make flux-install` yourself whenever you do want it.

## The Git sync (`gotk-sync.yaml`)

Since the Helm chart doesn't create the `GitRepository`/root
`Kustomization` pair that tells Flux which repo and path to reconcile,
this project keeps those two resources hand-written in `gotk-sync.yaml`
(same filename `flux bootstrap` itself would have used), wrapped in a
plain `kustomization.yaml` so `kubectl apply -k` picks up both in one
shot. `cluster/install-flux.sh` applies this automatically every run --
edit `GitRepository.spec.url` here if the remote ever changes.
`GitRepository.spec.secretRef` points at the `flux-system-git-auth`
Secret described above -- required since this repo is private.

## Verify

```sh
flux get kustomizations -A
flux get helmreleases -A
```

should show `flux-system` (the Kustomization) and all five HelmReleases
(`registry`, `clamav`, `postgres`, `monitor-api`, `dashboard`) as
`Ready` once the repo is pushed and reachable. That's the whole loop
closed, from `git push` to running Deployments, with no `kubectl apply`
on the deploy side involved at all from here on (`make deploy` triggers
reconciliation rather than applying manifests directly -- see the
top-level README's "GitOps (Flux)" section).

## Upgrading the Flux controllers later

Since installation went through Helm, upgrades go through Helm too --
bump the chart version (or edit `values.yaml`) and re-run `make
flux-install` (or `cluster/install-flux.sh` directly), which re-runs the
same idempotent `helm upgrade --install`.

`crds.migration.enabled` in `values.yaml` (left at the chart's default,
`false`) controls whether the chart also migrates CRDs on upgrade
automatically -- worth reading the chart's own release notes before
flipping that on.
