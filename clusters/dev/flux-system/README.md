# flux-system

Flux's controllers are installed here via the community
[`fluxcd-community/flux2`](https://github.com/fluxcd-community/helm-charts)
Helm chart, not `flux bootstrap` -- a deliberate choice for this project
(if you'd rather use `flux bootstrap`, it works too and additionally
commits `gotk-sync.yaml` for you automatically; the manual step 2 below
exists specifically because the Helm chart route doesn't do that part).

## Prerequisites

1. **This project needs to be a Git repository with a remote.** Flux
   polls Git, not the filesystem -- as of this migration the project has
   no `git init` or remote yet. Push it to GitHub/GitLab/wherever your
   cluster can reach before any of this matters.
2. **Helm 3** and a working kubeconfig context pointing at the target
   cluster (the k3d cluster this project already uses for local dev
   works fine).

## Step 1: install the Flux controllers via Helm

```sh
helm repo add fluxcd-community https://fluxcd-community.github.io/helm-charts
helm repo update
kubectl create namespace flux-system --dry-run=client -o yaml | kubectl apply -f -
helm install flux2 fluxcd-community/flux2 \
  --namespace flux-system \
  --values values.yaml \
  --wait
```

`values.yaml` (in this directory) trims the image-automation controllers
since nothing in this repo uses image automation yet -- see the comment
in that file for when to turn them back on. Everything else uses the
chart's defaults, which are fine for a single local dev cluster.

Verify with `kubectl -n flux-system get pods` -- you should see
`source-controller`, `kustomize-controller`, `helm-controller`, and
`notification-controller` all `Running`.

## Step 2: apply the Git sync (the part the Helm chart doesn't do)

The Helm chart only installs controllers and CRDs -- it doesn't create the
`GitRepository`/`Kustomization` pair that tells Flux which repo and path
to actually reconcile (that's normally `flux bootstrap`'s job). This
project keeps those two resources hand-written in `gotk-sync.yaml`
(same filename `flux bootstrap` itself would have used) instead, wrapped
in a plain `kustomization.yaml` so they apply in one shot:

```sh
kubectl apply -k clusters/dev/flux-system/
```

Before running this, edit `gotk-sync.yaml`'s `GitRepository.spec.url` --
it's still a placeholder until this project is actually pushed somewhere
(see prerequisite 1 above).

## Step 3: verify

```sh
flux get kustomizations
```

should show both `flux-system` and `monitor-api` (see
`clusters/dev/monitor-api.yaml`) as `Ready`. That's the whole loop closed,
from `git push` to a running `monitor-api` Deployment, with no
`kubectl apply` on the deploy side involved at all from here on.

## Upgrading the Flux controllers later

Since installation went through Helm, upgrades go through Helm too --
bump the chart version and re-run:

```sh
helm upgrade flux2 fluxcd-community/flux2 \
  --namespace flux-system \
  --values values.yaml
```

`crds.migration.enabled` in `values.yaml` (left at the chart's default,
`false`) controls whether the chart also migrates CRDs on upgrade automatically
-- worth reading the chart's own release notes before flipping that on.
