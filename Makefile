# Runtime backend: colima or podman. See cluster/create-cluster.sh.
#
# Detected from whichever VM is actually running, because getting this
# wrong doesn't fail cleanly: on podman with the old hardcoded `colima`
# default, DOCKER_HOST stayed empty (it's only resolved in the podman
# branch below), so `make build` reached for /var/run/docker.sock and
# died with "check if the path is correct and if the daemon is running"
# -- which reads as a broken Docker install rather than one missing
# flag. It also silently skips the k3d image import, so a `make deploy`
# that appeared to work would roll out the previous image.
#
# The rule, in the order the checks actually run:
#
#   - a podman machine is running and colima is NOT -> podman
#   - anything else                                 -> colima
#
# "Anything else" deliberately includes both running and neither
# running: colima was the previous default, so an ambiguous or
# undetectable environment behaves exactly as it did before this
# existed, and nothing changes under someone who never had a podman
# machine. The podman check runs first because it's the cheap one
# (~20ms, vs ~200ms for `colima status`), and when it says no, the
# answer is colima regardless -- so the expensive check only runs when
# it can still change the outcome.
#
# Override whenever the guess is wrong or you have both running:
# `make build SCM_RUNTIME=podman`, or export it. The `origin` test below
# is what makes that work -- it also means the detection shell runs once
# per make invocation rather than on every reference to the variable
# (which a plain `?=` with $(shell ...) would do, since ?= creates a
# recursively expanded variable).
#
# Still not read back from the running cluster: a machine being up
# doesn't prove the k3d cluster was created on it. A wrong guess is a
# skipped image import, same as before -- hence the override.
ifeq ($(origin SCM_RUNTIME), undefined)
SCM_RUNTIME := $(shell \
	if podman machine ls --format '{{.Running}}' 2>/dev/null | grep -qx true && \
	   ! colima status >/dev/null 2>&1; then echo podman; else echo colima; fi)
endif
SCM_CLUSTER_NAME ?= supply-chain-monitor
IMAGE            := monitor-api:dev
# The command that BUILDS images, as opposed to the docker CLI used for
# `docker run` elsewhere in this file.
#
# podman build, not docker build, when the runtime is podman: the
# Dockerfile's Go stages are pinned to $BUILDPLATFORM so they
# cross-compile instead of running the Go toolchain under emulation
# (see the Dockerfile's own comment), and that is a BuildKit/buildah
# feature. The docker CLI here has no buildx component, so it falls back
# to the legacy builder, which cannot parse $BUILDPLATFORM at all and
# fails with `"" is an invalid OS component`. buildah handles it
# natively -- verified by building both linux/amd64 and linux/arm64 on
# an Apple Silicon machine, which the legacy path could never do.
# Chosen by CAPABILITY, not by SCM_RUNTIME: what matters is whether the
# builder understands $BUILDPLATFORM, and that does not line up with
# which VM the cluster runs in. `docker buildx` does, buildah does, and
# the legacy docker builder does not -- it fails with `"" is an invalid
# OS component`, which reads like a Dockerfile typo rather than a
# missing component. GitHub's ubuntu-latest ships buildx, so CI takes
# the first branch; a machine whose docker has no buildx plugin falls
# through to podman.
CONTAINER_BUILD  := $(shell 	if docker buildx version >/dev/null 2>&1; then echo "docker buildx build"; 	elif command -v podman >/dev/null 2>&1; then echo "podman build"; 	else echo "docker build"; fi)
# The commit the image is built from, stamped into the binary (see the
# Dockerfile's GIT_SHA) and used as a second, UNIQUE tag alongside :dev.
#
# The unique tag is what makes imagePullPolicy: IfNotPresent safe. With
# only a floating :dev, a node that already holds any monitor-api:dev
# keeps it forever -- so a rebuilt binary silently does not deploy, and
# `kubectl get deploy` shows no change to say so. -dirty marks a build
# from an uncommitted tree, which is exactly the build you most want to
# be able to identify later.
GIT_SHA          := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)$(shell git diff --quiet 2>/dev/null || echo -dirty)
IMAGE_SHA        := monitor-api:$(GIT_SHA)
# Scratch tarball the k3d import reads. Written next to the build rather
# than in /tmp so a failed run leaves it somewhere obvious.
IMAGE_TAR        := .monitor-api-image.tar

# On the podman runtime, resolve DOCKER_HOST from podman's own current
# connection list instead of requiring it exported by hand in every
# shell. podman renegotiates the SSH-forwarded port in that URI on every
# `podman machine start` (see cluster/runtimes/podman.sh's own handling
# of this same problem for k3d's connection), so a value exported once
# and left in a shell profile goes stale the next time the machine
# restarts -- symptom: `docker build`/`docker run` failing with something
# like `write |1: broken pipe` even though podman itself is fine.
# Evaluated once, at parse time, in a subshell with its own stderr
# redirect (podman/jq not installed or machine not started yet just
# means an empty value here, silently -- same as DOCKER_HOST being unset
# entirely, not a reason to fail every other target). `export` makes it
# part of every recipe's environment for this invocation, including
# test-api/test-postgres/test-dashboard's own `docker run` calls, not
# just build/deploy.
ifeq ($(SCM_RUNTIME),podman)
export DOCKER_HOST := $(shell (podman system connection ls --format json | jq -r '.[] | select(.Default==true) | .URI') 2>/dev/null)
endif

.PHONY: cluster-up cluster-down cluster-destroy flux-install git-auth git-test chart-secrets gateway-api-install build test-image vulncheck trivy-config deploy undeploy port-forward logs scan-jobs test-artifact test test-api test-postgres test-dashboard test-swagger-docs check-dashboard-configmap check-alert-rules check-duplicate-keys check-k8s-manifests check-go-image-pin helm-lint helm-template test-backup-scripts db-shell lock-deps db-backup db-restore db-backups-list load-test-clamav

cluster-up:
	SCM_RUNTIME=$(SCM_RUNTIME) ./cluster/create-cluster.sh

cluster-down:
	SCM_RUNTIME=$(SCM_RUNTIME) ./cluster/destroy-cluster.sh

cluster-destroy:
	SCM_RUNTIME=$(SCM_RUNTIME) ./cluster/destroy-cluster.sh --delete

# `make cluster-up` already runs this automatically (see
# cluster/create-cluster.sh) -- this target is for installing/upgrading
# Flux on its own, standalone, against whatever cluster your kubectl
# context already points at (e.g. after SCM_SKIP_FLUX=1, or just to pick
# up a newer chart version / a values.yaml edit without touching the
# cluster itself). See cluster/install-flux.sh and
# k8s/flux-system/README.md.
flux-install:
	./cluster/install-flux.sh

# sifungurux/supply-chain-monitor is a private repo, so Flux's
# GitRepository needs real credentials to clone it -- these two targets
# set that up and verify it, in that order:
#   make git-auth   creates/updates the flux-system-git-auth Secret
#                    (prompts for a GitHub username + PAT, or reads
#                    GIT_USERNAME/GIT_PASSWORD from the environment)
#   make git-test    does a direct `git ls-remote` with those same
#                    credentials, so you find out in seconds whether
#                    they actually work instead of waiting on Flux's
#                    own (much slower) reconcile/retry loop.
# See k8s/flux-system/README.md's "Private repo authentication".
git-auth:
	./cluster/git-auth-secret.sh

git-test:
	./cluster/test-git-connection.sh

# Creates/updates the scm-chart-secrets Secret that
# k8s/releases/supply-chain-monitor-helmrelease.yaml's spec.valuesFrom
# sources postgres.credentials.password and monitorApi.apiKey from --
# see cluster/chart-secrets.sh and README's "Bringing your own secrets".
# Generates a random value for anything you don't pass in yourself
# (POSTGRES_PASSWORD=... API_KEY=... make chart-secrets to pin either).
chart-secrets:
	./cluster/chart-secrets.sh

# `make cluster-up` already runs this automatically (see
# cluster/create-cluster.sh) -- standalone target for installing/
# re-running just the Gateway API CRDs against a cluster that's already
# up (e.g. after SCM_SKIP_GATEWAY_API=1). See
# cluster/install-gateway-api.sh and docs/architecture.md ("Ingress:
# Traefik + Gateway API") -- Traefik itself is Flux-managed
# (k8s/releases/traefik-helmrelease.yaml), this only installs the CRDs
# it depends on.
gateway-api-install:
	./cluster/install-gateway-api.sh

# On the colima runtime, this is all you need -- colima's k3s (docker
# runtime) shares the same image store as `docker build`, so there's no
# import step. On the podman runtime, DOCKER_HOST is already resolved
# and exported above so `docker build` here talks to the podman machine
# with no manual export needed -- but that alone isn't enough: each k3d
# node is itself a container with its own embedded containerd, entirely
# separate from podman's own image store, so a locally built image is
# invisible to the cluster until explicitly imported. `k3d image import`
# below does that, gated on SCM_RUNTIME=podman so the (fast,
# no-op-if-mismatched) colima path isn't slowed down by a step it
# doesn't need. Uses the fully-qualified docker.io/library/$(IMAGE) name,
# not the short $(IMAGE) one -- podman's build backend tags images under
# both, but k3d's image lookup only resolves the qualified one (the
# short name fails with "not a file and couldn't be found in the
# container runtime" even though the image exists).
build:
ifeq ($(SCM_RUNTIME),podman)
	@if [ -z "$(DOCKER_HOST)" ]; then \
		echo "SCM_RUNTIME=podman but DOCKER_HOST could not be resolved -- is the podman machine started? Run 'make cluster-up SCM_RUNTIME=podman' or 'podman machine start' first." >&2; \
		exit 1; \
	fi
	@echo "SCM_RUNTIME=podman -- DOCKER_HOST=$(DOCKER_HOST)"
endif
	$(CONTAINER_BUILD) --build-arg GIT_SHA=$(GIT_SHA) -t $(IMAGE) -t $(IMAGE_SHA) services/monitor-api
	@echo "built $(IMAGE) and $(IMAGE_SHA)"
ifeq ($(SCM_RUNTIME),podman)
	@echo "SCM_RUNTIME=podman -- importing into k3d cluster '$(SCM_CLUSTER_NAME)'..."
	@# IMPORT VIA A TARBALL, AND UNDER THE FULLY-QUALIFIED NAME.
	@#
	@# Two separate things made the obvious `k3d image import <ref>`
	@# form fail SILENTLY -- it printed "Successfully imported 2
	@# image(s)" while the cluster kept running the previous binary,
	@# which is the worst way for a deploy step to be wrong.
	@#
	@# 1. podman's docker-compat API lists only ONE tag per image id,
	@#    and :dev and :<sha> are the same image. So k3d could not find
	@#    the sha tag in the list it searches -- `docker image inspect`
	@#    resolves it fine, but `k3d image import` answers "no valid
	@#    images specified". Saving both refs into one tarball sidesteps
	@#    the lookup entirely.
	@#
	@# 2. podman names local builds `localhost/monitor-api:...`, and a
	@#    tarball of those imports under that same name -- while
	@#    Kubernetes resolves the bare `monitor-api:dev` in the chart to
	@#    `docker.io/library/monitor-api:dev`. The node ended up holding
	@#    a fresh localhost/ image AND a stale docker.io/library/ one,
	@#    and kept running the stale one. Tagging explicitly before the
	@#    save is what makes the imported name the one kubelet looks up.
	podman tag $(IMAGE) docker.io/library/$(IMAGE)
	podman tag $(IMAGE) docker.io/library/$(IMAGE_SHA)
	podman save --format docker-archive -o $(IMAGE_TAR) \
		docker.io/library/$(IMAGE) docker.io/library/$(IMAGE_SHA)
	k3d image import $(IMAGE_TAR) -c $(SCM_CLUSTER_NAME)
	@rm -f $(IMAGE_TAR)
	@# Pin it against kubelet image GC. The import is the only copy --
	@# nothing pushes this image to a registry, so a collected image
	@# cannot be re-pulled and any Job landing on that node fails with
	@# what looks like a credentials error. See cluster/pin-image.sh.
	./cluster/pin-image.sh docker.io/library/$(IMAGE) $(SCM_CLUSTER_NAME)
	./cluster/pin-image.sh docker.io/library/$(IMAGE_SHA) $(SCM_CLUSTER_NAME)
	@$(MAKE) --no-print-directory verify-image-imported
endif

# Proves the image actually reached every node, rather than trusting
# `k3d image import`'s own success message -- which was observed
# printing "Successfully imported 2 image(s)" while changing nothing.
#
# CHECKS THE SHA TAG, NOT :dev, and that is the whole point. :dev exists
# on the node whether or not this build landed, so its presence proves
# nothing; the sha tag is unique to this commit, so a stale image cannot
# fake it. This is the concrete payoff of tagging by commit at all.
.PHONY: verify-image-imported
verify-image-imported:
	@nodes="$$(k3d node list -o json 2>/dev/null | grep -o '"name":"[^"]*"' | cut -d'"' -f4 | grep '^k3d-$(SCM_CLUSTER_NAME)-' | grep -v serverlb)"; \
	if [ -z "$$nodes" ]; then \
		echo "" >&2; \
		echo "CANNOT VERIFY: found no nodes for cluster '$(SCM_CLUSTER_NAME)'." >&2; \
		echo "Is the cluster up, and is DOCKER_HOST set (SCM_RUNTIME=podman)?" >&2; \
		exit 1; \
	fi; \
	missing=""; \
	for node in $$nodes; do \
		if ! podman exec "$$node" ctr -n k8s.io images ls 2>/dev/null | grep -q "docker.io/library/$(IMAGE_SHA) "; then \
			missing="$$missing $$node"; \
		fi; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "" >&2; \
		echo "IMAGE DID NOT REACH:$$missing" >&2; \
		echo "docker.io/library/$(IMAGE_SHA) is absent there, so those nodes still run whatever they had." >&2; \
		echo "The import step reports success even when it changes nothing -- see the build target." >&2; \
		exit 1; \
	fi; \
	echo "verified docker.io/library/$(IMAGE_SHA) on every node"

# Builds the image and asserts the properties its Dockerfile is written
# to guarantee -- separate from `build` above because that one also
# imports into a running k3d cluster, which CI has no business doing.
#
# Nothing built this image in CI before, so a broken Dockerfile was only
# ever caught by a human running `make build`. It also covers the one
# thing that cannot be checked on an Apple Silicon dev machine: the
# amd64 half of the Dockerfile's per-architecture checksum table. qemu
# cannot emulate the Go toolchain well enough to run the build stage
# (`go mod download` dies with a register dump under --platform
# linux/amd64), so a native amd64 runner is the only place the amd64
# branch actually executes end to end.
test-image:
	$(CONTAINER_BUILD) -t $(IMAGE)-verify services/monitor-api
	@echo "== runs as non-root (uid 65534) =="
	@id="$$(docker run --rm --entrypoint id $(IMAGE)-verify -u)"; \
		[ "$$id" = "65534" ] || { echo "image runs as uid $$id, want 65534" >&2; exit 1; }
	@echo "== monitor-api is a static binary (CGO_ENABLED=0) =="
	@docker run --rm --entrypoint sh $(IMAGE)-verify -c \
		'ldd /usr/local/bin/monitor-api 2>&1 | grep -q "Not a valid dynamic program"' \
		|| { echo "monitor-api is dynamically linked -- CGO_ENABLED=0 build broken" >&2; exit 1; }
	@echo "== the binary actually starts (fails closed with no API key) =="
	@docker run --rm $(IMAGE)-verify 2>&1 | grep -q "no API key configured" \
		|| { echo "monitor-api did not reach its own startup checks" >&2; exit 1; }
	@echo "== every bundled tool runs =="
	@docker run --rm --entrypoint sh $(IMAGE)-verify -c \
		'set -e; trivy --version >/dev/null; grype version >/dev/null; oras version >/dev/null; unpacker --version >/dev/null; umoci --version >/dev/null'
	@echo "== no downloader left in the runtime image =="
	@docker run --rm --entrypoint sh $(IMAGE)-verify -c 'command -v curl >/dev/null' \
		&& { echo "curl is present in the runtime image -- it belongs to the tools stage only" >&2; exit 1; } || true
	@# GREEN-BY-SKIP. Two scanner tests call t.Skip unless a real binary
	@# is on PATH -- digest_test.go's authenticated-registry leg needs
	@# oras, documents_test.go's needs trivy -- and `make test-api` runs
	@# in a bare golang image that has neither. Both were therefore
	@# skipping in EVERY CI job while reporting ok, which is the worst
	@# possible reading: the suite is green and the code those two
	@# cover (registry authentication, `trivy convert`) is untested.
	@#
	@# They run HERE because this is the only target that has already
	@# built the image the binaries live in -- installing them into the
	@# test-api container instead would mean a second set of version
	@# pins to drift out of step with the Dockerfile's.
	@echo "== the tool-gated scanner tests actually run =="
	@rm -rf .tool-bin && mkdir -p .tool-bin
	@# --user 0 because the image runs as 65534 and .tool-bin belongs to
	@# whoever ran make. Docker Desktop fakes bind-mount ownership so this
	@# passes on a Mac either way; on a Linux runner the copy is denied.
	@docker run --rm --user 0 --entrypoint sh -v "$(CURDIR)/.tool-bin":/dest $(IMAGE)-verify \
		-c 'cp /usr/local/bin/oras /usr/local/bin/trivy /dest/'
	docker run --rm -v "$(CURDIR)/services/monitor-api":/src \
		-v "$(CURDIR)/.tool-bin/oras":/usr/local/bin/oras \
		-v "$(CURDIR)/.tool-bin/trivy":/usr/local/bin/trivy \
		-w /src $(GO_BUILD_IMAGE) \
		sh -c "go mod download && go test ./internal/scanner -count=1 -run 'Oras|Registry|Documents'"
	@rm -rf .tool-bin
	@echo "image checks passed"

# govulncheck against the module's own source. Reports only the
# vulnerabilities whose vulnerable SYMBOLS this code actually reaches,
# not everything in the dependency tree -- that call-graph filtering is
# the whole reason to use this rather than a generic dependency scanner.
#
# Analyzed with the SAME toolchain the Dockerfile builds with, on
# purpose: standard-library findings are a property of the compiler that
# produces the binary, so analyzing with a different Go version reports
# vulnerabilities the shipped binary does not have, or misses ones it
# does. Keep this image and the Dockerfile's in step.
#
# Gating in CI, and clean as of the Go 1.27 bump -- see the govulncheck
# job in .github/workflows/ci.yml. Run it by hand any time; it needs
# network for the vulnerability database.
#
# THIS VERSION MOVES WITH THE TOOLCHAIN. v1.1.4 does not merely misreport
# on Go 1.27, it dies:
#
#   panic: unexpected expr: *ast.KeyValueExpr
#     golang.org/x/tools@v0.29.0/go/ssa/builder.go:958
#
# govulncheck vendors x/tools to build the call graph, and a pinned
# x/tools cannot parse a language version released after it. Bumping the
# Go image without bumping this breaks the job outright -- which is the
# good case. The bad case is the one check-go-image-pin below exists for:
# leave GO_BUILD_IMAGE behind and nothing breaks at all, because
# govulncheck goes on analyzing the old toolchain, green, forever.
GOVULNCHECK_VERSION ?= v1.7.0
# PINNED TO THE SAME DIGEST THE BUILD USES. This ran against the
# floating golang:1.26-alpine tag while services/monitor-api/Dockerfile
# pinned by digest -- so the gating vulnerability check and the actual
# build could disagree about which toolchain they were talking about,
# and on 2026-08-16 they did: the tag moved to a Go release with four
# stdlib CVEs while the build stayed on the pinned one.
#
# Keep GO_BUILD_IMAGE in step with the Dockerfile's FROM lines --
# check-go-image-pin below now enforces that rather than trusting this
# comment, which it had already stopped doing: on 2026-09-03 the two
# were pinned to DIFFERENT digests of golang:1.26-alpine and nothing
# noticed. That pair happened to resolve to the same go1.26.6, so the
# invariant was broken without a consequence, which is the state a
# check exists to catch.
GO_BUILD_IMAGE ?= golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc

# Fails if GO_BUILD_IMAGE and services/monitor-api/Dockerfile disagree
# about the Go toolchain. A bump that moves one and not the other is
# green in every job: govulncheck passes, because it analyzed a
# toolchain the shipped binary is not built with. Dependabot bumps the
# Dockerfile alone -- see PR #179, where it did exactly that.
#
# Both Dockerfile stages are checked, not just the first: `build` and
# `umoci-build` compile different binaries into the same image, and a
# bump that moved one would ship two toolchains in one artifact.
check-go-image-pin:
	@pins="$$(grep -oE 'golang:[^ ]+' services/monitor-api/Dockerfile | sort -u)"; \
		if [ "$$(printf '%s\n' "$$pins" | wc -l)" -ne 1 ]; then \
			echo "Dockerfile pins more than one golang image:" >&2; \
			printf '  %s\n' $$pins >&2; exit 1; \
		fi; \
		[ "$$pins" = "$(GO_BUILD_IMAGE)" ] || { \
			echo "GO_BUILD_IMAGE and the Dockerfile disagree about the Go toolchain:" >&2; \
			echo "  Makefile:   $(GO_BUILD_IMAGE)" >&2; \
			echo "  Dockerfile: $$pins" >&2; \
			echo "govulncheck analyzes with the Makefile's image; the binary ships with the Dockerfile's." >&2; \
			exit 1; }

# Executes the backup/restore SHELL LOGIC -- the one thing helm lint,
# helm template and check-helm-manifests.sh all leave untested. See
# cluster/test-backup-scripts.sh's header for the outage that makes
# this worth a CI job of its own. Needs docker; no cluster, no database.
test-backup-scripts:
	./cluster/test-backup-scripts.sh

vulncheck:
	docker run --rm -v "$(CURDIR)/services/monitor-api":/src -w /src $(GO_BUILD_IMAGE) \
		sh -c "go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) && govulncheck ./..."

# Misconfiguration scan of the two things this repo ships that describe
# infrastructure: its Helm chart and the monitor-api Dockerfile.
#
# Gating, unlike vulncheck: both are clean today (the Dockerfile with no
# exceptions at all, the chart with the two documented entries in
# .trivyignore), so anything new here is a real regression rather than
# pre-existing noise. Chart and Dockerfile are scanned as separate
# invocations because trivy picks a different parser per target type,
# and a directory scan of the repo root would also drag in
# cluster/*.template.yaml -- bare manifests that are not what this
# project deploys.
TRIVY_IMAGE ?= aquasec/trivy:0.73.0
trivy-config:
	docker run --rm -v "$(CURDIR)":/src -w /src $(TRIVY_IMAGE) config charts/supply-chain-monitor \
		--severity HIGH,CRITICAL --exit-code 1 --ignorefile .trivyignore
	docker run --rm -v "$(CURDIR)":/src -w /src $(TRIVY_IMAGE) config services/monitor-api/Dockerfile \
		--severity HIGH,CRITICAL --exit-code 1 --ignorefile .trivyignore

# The whole application is a single Helm chart via Flux now (see
# charts/supply-chain-monitor/, k8s/releases/supply-chain-monitor-helmrelease.yaml,
# and docs/architecture.md's "A single chart for the whole application")
# -- so unlike before, this target no longer runs `kubectl apply -k
# k8s/` itself. Flux owns that application now; `kubectl apply`-ing the
# same resources here too would just fight it. Instead: commit and push
# whatever's in the working tree (so Flux's GitRepository has something
# new to see), force an immediate reconcile (rather than waiting for
# Flux's normal poll interval), then rollout-restart
# monitor-api/dashboard specifically -- that last step is still needed
# because the image tag (monitor-api:dev) doesn't change on a rebuild,
# so neither Flux nor Helm can detect that a restart is warranted on
# their own. Finite and exits when done -- it doesn't babysit the
# cluster afterward; Flux does that continuously on its own from here.
deploy: build
	@# A DEPLOY THAT REPORTS SUCCESS AND CHANGES NOTHING is this repo's
	@# most expensive failure mode, and pinning the HelmRelease to a
	@# published digest creates a fresh one: everything below still runs
	@# -- build, import, push, reconcile, rollout restart -- while the
	@# cluster goes on running the pinned image. Warn rather than fail,
	@# since the rest of this target (the chart, the CronJobs, Traefik)
	@# is still doing real work.
	@if grep -qE '^\s+digest: sha256:' k8s/releases/supply-chain-monitor-helmrelease.yaml 2>/dev/null; then \
		echo ""; \
		echo "  NOTE: the HelmRelease pins monitorApi.image.digest, so this deploy"; \
		echo "  will NOT change which monitor-api binary the cluster runs. The image"; \
		echo "  built above is ignored. To ship a code change: merge to main, let"; \
		echo "  publish-image run, and bump the digest in that file."; \
		echo ""; \
	fi
	@if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
		echo "This project isn't a git repository yet -- Flux polls Git, not the filesystem." >&2; \
		echo "Run: git init && git remote add origin <url matching k8s/flux-system/gotk-sync.yaml's GitRepository.spec.url> && git push -u origin main" >&2; \
		exit 1; \
	fi
	@echo "Committing and pushing the current tree so Flux has something new to reconcile..."
	git add -A
	@git diff --cached --quiet && echo "(nothing to commit)" || git commit -q -m "deploy: $$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	git push
	@echo "Triggering an immediate Flux reconcile (instead of waiting for its normal interval)..."
	@if command -v flux >/dev/null 2>&1; then \
		flux reconcile source git flux-system --timeout=2m && \
		flux reconcile kustomization flux-system --with-source --timeout=3m && \
		flux reconcile helmrelease supply-chain-monitor -n flux-system --timeout=3m && \
		flux reconcile helmrelease traefik -n flux-system --timeout=2m ; \
	else \
		echo "('flux' CLI not found -- brew install fluxcd/tap/flux for a faster,"; \
		echo " per-HelmRelease reconcile trigger. Falling back to annotating the"; \
		echo " GitRepository/root Kustomization so they re-sync right away instead"; \
		echo " of waiting up to their normal interval; the two HelmReleases will"; \
		echo " pick up the change on their own next poll, within a few minutes.)"; \
		kubectl -n flux-system annotate gitrepository/flux-system reconcile.fluxcd.io/requestedAt="$$(date +%s)" --overwrite; \
		kubectl -n flux-system annotate kustomization/flux-system reconcile.fluxcd.io/requestedAt="$$(date +%s)" --overwrite; \
	fi
	@echo "Restarting monitor-api/dashboard so they pick up the freshly built image..."
	kubectl -n supply-chain-monitor rollout restart deployment/monitor-api deployment/scm-dashboard
	kubectl -n supply-chain-monitor rollout status deployment/monitor-api --timeout=120s
	kubectl -n supply-chain-monitor rollout status deployment/scm-dashboard --timeout=120s
	@echo ""
	@echo "Deployed. Flux owns reconciliation continuously from here -- this target"
	@echo "hands off rather than watching the cluster; run 'make logs' or"
	@echo "'flux get helmreleases -A' any time to check on it."

# Deletes everything Flux currently manages under k8s/ -- the two
# HelmReleases (supply-chain-monitor and traefik, which helm-controller
# then correctly un-installs, taking their Deployments/Services/
# Gateway/HTTPRoute/etc. with them), the namespaces, and Flux's own root
# Kustomization/GitRepository. Flux's finalizers handle the cascade;
# this is just telling the API server to delete what's currently built
# from k8s/, the same as before the Helm conversion. Does NOT remove
# the Gateway API CRDs themselves (cluster/install-gateway-api.sh) --
# those are cluster-wide infra outside Flux's remit, same as Flux's own
# CRDs.
undeploy:
	kubectl delete -k k8s/ --ignore-not-found

port-forward:
	kubectl -n supply-chain-monitor port-forward svc/monitor-api 8080:8080

logs:
	kubectl -n supply-chain-monitor logs -l app=monitor-api -f

# Load-tests the register->scan pipeline with 100 concurrent artifacts
# (see cluster/load-test-clamav.sh) to check whether scm-clamav
# (README's "Scaling ClamAV") is keeping up, rather than guessing from
# clamav.replicas alone. Requires `make port-forward` running in another
# terminal. Override PARALLELISM=N to change concurrency.
load-test-clamav:
	./cluster/load-test-clamav.sh

# each image /scan spins up its own short-lived Job (see
# internal/scanner/isolated_unpacker.go) that's normally gone within
# seconds of finishing (TTLSecondsAfterFinished, or an explicit delete
# once monitor-api reads its result) -- this is for catching one
# mid-flight or debugging why a scan is hanging.
scan-jobs:
	kubectl -n supply-chain-monitor get jobs,pods -l app=scm-scan-worker -w

# opens a psql shell inside the in-cluster Percona Postgres pod
db-shell:
	kubectl -n supply-chain-monitor exec -it deploy/scm-postgres -- psql -U monitor_api -d monitor_api

# Triggers an immediate pg_dump backup (see
# charts/supply-chain-monitor/templates/postgres/backup-cronjob.yaml,
# which otherwise only runs on its own daily schedule) as a one-off Job
# cloned from the same CronJob template -- useful right before a risky
# change, or just to confirm backups are actually working.
db-backup:
	kubectl -n supply-chain-monitor create job --from=cronjob/scm-postgres-backup scm-postgres-backup-manual-$$(date +%s)
	@echo "Triggered -- watch it with: kubectl -n supply-chain-monitor get jobs -l app=scm-postgres-backup -w"

# Lists what's in the scm-postgres-backups PVC (see cluster/postgres-list-backups.sh).
db-backups-list:
	./cluster/postgres-list-backups.sh

# Restores a backup into the live database -- destructive, asks for
# confirmation. BACKUP is a filename from `make db-backups-list`, e.g.:
#   make db-restore BACKUP=scm-postgres-20260101T020000Z.sql.gz
#
# A backup whose name ends .sql.gz.gpg is encrypted and needs the
# private key, which lives OUTSIDE the cluster -- pass the file and it
# is lent to the cluster for the length of the restore, then deleted:
#   make db-restore BACKUP=scm-postgres-20260101T020000Z.sql.gz.gpg \
#     GPG_PRIVATE_KEY_FILE=~/keys/scm-backup-private.asc
# Add GPG_PASSPHRASE_FILE=... if that key is passphrase-protected.
#
# See cluster/postgres-restore.sh and README's "Backing up and
# restoring Postgres".
db-restore:
	GPG_PRIVATE_KEY_FILE="$(GPG_PRIVATE_KEY_FILE)" GPG_PASSPHRASE_FILE="$(GPG_PASSPHRASE_FILE)" ./cluster/postgres-restore.sh $(BACKUP)

# quick smoke test against a port-forwarded API (run `make port-forward`
# first). SCM_API_KEY must match whatever's in scm-monitor-api-auth --
# no chart default to fall back to since values.yaml's monitorApi.apiKey
# is deliberately empty (see README's "Bringing your own secrets");
# every endpoint but /healthz requires it (see README's Authentication
# section). No fallback value here on purpose -- guessing wrong would
# just be a confusing 401, a missing SCM_API_KEY should fail loudly
# instead.
test-artifact:
	@if [ -z "$(SCM_API_KEY)" ]; then \
		echo "SCM_API_KEY is required, e.g.: SCM_API_KEY=... make test-artifact" >&2; \
		exit 1; \
	fi
	curl -s -X POST localhost:8080/api/v1/artifacts \
		-H "Authorization: Bearer $(SCM_API_KEY)" \
		-H 'Content-Type: application/json' \
		-d '{"ref":"alpine:3.19","type":"image"}' | tee /tmp/scm-artifact.json

test: test-api test-dashboard check-dashboard-configmap check-openapi-spec check-alert-rules check-duplicate-keys check-k8s-manifests check-go-image-pin

# Runs services/monitor-api's Go test suite (handlers, store, pipeline)
# via a containerized golang image -- no local Go install needed, just
# Docker (which you already have via colima/podman). go.sum is committed
# (see go.mod's comment) -- `go mod download` here verifies the module
# graph against it rather than re-resolving anything, so this only needs
# network access if go.sum itself is out of date with go.mod. This only
# exercises MemStore -- it needs no running Postgres. For a real
# database round-trip, see test-postgres below.
# go vet runs here too -- previously only ran inside lock-deps (a rare,
# manual target), so nothing stopped a vet-flagging change (bad Printf
# verb, a struct with a copied lock, unreachable code) from merging to
# main between dependency updates. See docs/tech-debt-audit.md, #10.
test-api:
	docker run --rm -v "$(CURDIR)/services/monitor-api":/src -w /src golang:1.26-alpine sh -c "go mod download && if [ -n \"$$(gofmt -l .)\" ]; then echo 'gofmt drift in:'; gofmt -l .; echo 'run: gofmt -w <file>'; exit 1; fi && go vet ./... && go test ./..."

# Integration test against a real, throwaway Percona Postgres container
# (internal/artifact/postgres_store_integration_test.go, gated behind
# the postgres_integration build tag so `go test ./...` above never
# needs a database). Uses --network host so the test container inside
# it can reach localhost:55432 -- this works on Colima (a real Linux
# VM) but not Docker Desktop on macOS; run this from inside the Colima
# VM (`colima ssh`) if it hangs.
test-postgres:
	docker rm -f scm-test-postgres >/dev/null 2>&1 || true
	docker run -d --rm --name scm-test-postgres -e POSTGRES_PASSWORD=test -p 55432:5432 percona/percona-distribution-postgresql:17.10 >/dev/null
	docker run --rm --network host -v "$(CURDIR)/services/monitor-api":/src -w /src \
		-e POSTGRES_TEST_DSN="postgres://postgres:test@localhost:55432/postgres?sslmode=disable" \
		golang:1.26-alpine sh -c "go mod download && go test -tags=postgres_integration ./internal/artifact/..." ; \
	status=$$? ; docker stop scm-test-postgres >/dev/null 2>&1 ; exit $$status

# Runs dashboard/index.html's Node+jsdom test suite via a containerized
# node image -- no local Node install needed.
test-dashboard:
	docker run --rm -v "$(CURDIR)/dashboard":/src -w /src node:22-alpine sh -c "npm install --no-save >/dev/null && npm test"

# Starts a real, throwaway monitor-api (plus its own throwaway Postgres,
# same as test-postgres above) and curls /swagger, /openapi.yaml, and the
# README-documented API examples against it for real -- see
# cluster/test-swagger-docs.sh's own header for what this catches that
# internal/api's httptest-based Go tests can't (no real TCP listener, no
# real HTTP round trip). Needs --network host (see test-postgres's own
# comment) -- same Docker-Desktop-on-macOS caveat applies here too.
test-swagger-docs:
	./cluster/test-swagger-docs.sh

# Generates and commits services/monitor-api/go.sum for real, pinned,
# reproducible builds -- see go.mod's own comment on why it isn't
# committed yet. Needs nothing but Docker: runs `go mod tidy` inside
# `golang:1.26-alpine` (which does have real internet access, unlike
# whatever sandbox/CI environment this repo's own tooling was written
# in) and writes go.sum straight into your working tree.
#
# Run this once after cloning, and again any time go.mod's `require`
# lines change. Afterward:
#   git diff services/monitor-api/go.sum   # see what changed
#   git add services/monitor-api/go.sum && git commit
# From then on the Dockerfile's `go mod tidy` (see its own comment)
# becomes a verification step instead of a from-scratch resolution --
# it'll just confirm the committed go.sum still matches go.mod rather
# than fetching anything new.
lock-deps:
	docker run --rm -v "$(CURDIR)/services/monitor-api":/src -w /src golang:1.26-alpine sh -c "go mod tidy && go vet ./... && go mod verify"
	@echo ""
	@echo "go.sum written to services/monitor-api/go.sum -- review with 'git diff' and commit it."

# Catches the exact bug that shipped once already: dashboard/index.html
# edited without updating the copy the application chart actually
# serves (charts/supply-chain-monitor/files/index.html -- Helm's
# .Files.Get can only read files inside the chart directory, so this is
# a real second copy, not a symlink), so the running dashboard silently
# drifts from the source file. Point whatever CI you wire up against
# your own git server at this target (plus test-api and test-dashboard
# above).
check-dashboard-configmap:
	diff -q dashboard/index.html charts/supply-chain-monitor/files/index.html || \
		(echo "charts/supply-chain-monitor/files/index.html is out of date -- run: cp dashboard/index.html charts/supply-chain-monitor/files/index.html" && exit 1)

# Parses internal/api/openapi.yaml and resolves every $ref in it -- see
# cluster/check-openapi-spec.rb's own header for why neither happens
# anywhere else (the spec is served as raw bytes, and the only test
# that reads it greps substrings), so a broken indent or a $ref
# pointing at a schema that doesn't exist ships green and only fails in
# somebody's browser.
#
# Containerized like every other target here, so this needs nothing but
# Docker. Ruby specifically because YAML is in its standard library:
# no gem install, no lockfile, nothing to keep current.
check-openapi-spec:
	docker run --rm -v "$(CURDIR)":/src -w /src ruby:3.4-alpine ruby cluster/check-openapi-spec.rb

# promtool over the chart's alert rules. A PromQL expression that does
# not parse means Prometheus REFUSES THE WHOLE RULE FILE and alerts
# that look configured never evaluate -- silence that is
# indistinguishable from nothing being wrong, which is the failure mode
# this project keeps meeting. helm-lint and helm-template both pass on
# a rule file full of invalid PromQL, because to them it is just
# strings in a CRD.
#
# Piped to the container rather than bind-mounted: on podman the host's
# /tmp is not shared with the VM, and a missing path silently becomes
# an empty directory rather than an error.
# Duplicate mapping keys in the rendered chart. Helm does NOT catch
# these -- lint and template both accept a repeated key, last value wins
# -- but Flux rejects the whole HelmRelease at apply time, leaving the
# cluster stuck on the previous revision. See cluster/check-duplicate-keys.py.
check-duplicate-keys:
	helm template scm-ci charts/supply-chain-monitor | docker run --rm -i \
		-v "$(CURDIR)":/src -w /src python:3.13-alpine \
		sh -c 'pip install --quiet pyyaml && python cluster/check-duplicate-keys.py'

# Same duplicate-key check, but against the SOURCE manifests in k8s/
# rather than the rendered chart.
#
# check-duplicate-keys above renders the chart and inspects the output, so
# it never sees k8s/ at all -- and k8s/ is where the HelmRelease's own
# values live. A duplicate key there does not fail a scan or a template:
# it fails `kustomize build`, which takes the whole Flux Kustomization
# down and freezes everything in k8s/ at its last good revision, silently.
# That happened: a scanConcurrencyPerKind block added next to an existing
# one broke reconciliation, and it went unnoticed because HelmRelease
# chart upgrades kept flowing (they read the chart directly) while the
# HelmRelease's own values stayed frozen.
check-k8s-manifests:
	@for f in $$(find k8s -name '*.yaml'); do 		docker run --rm -i -v "$(CURDIR)":/src -w /src python:3.13-alpine 			sh -c 'pip install --quiet pyyaml && python cluster/check-duplicate-keys.py' < $$f 			|| { echo "duplicate mapping key in $$f"; exit 1; }; 	done
	@echo "ok:   no duplicate mapping keys in k8s/"

check-alert-rules:
	@helm template scm-ci charts/supply-chain-monitor \
		--set monitorApi.prometheusRule.enabled=true \
		-s templates/monitor-api/prometheusrule.yaml \
		| python3 -c "import sys,yaml; print(yaml.safe_dump({'groups': yaml.safe_load(sys.stdin)['spec']['groups']}))" \
		| docker run --rm -i --entrypoint sh prom/prometheus:v3.7.3 \
			-c 'cat > /tmp/r.yaml && promtool check rules /tmp/r.yaml' 

# Structural lint against the chart's own conventions (required fields,
# indentation, etc.). Does NOT validate that a rendered document is a
# well-formed Kubernetes object -- see helm-template below for the
# check that actually catches that class of bug.
helm-lint:
	docker run --rm -v "$(CURDIR)":/src -w /src alpine/helm:4.2.0 lint charts/supply-chain-monitor

# Renders the chart for real and fails if any emitted document is
# missing apiVersion -- see cluster/check-helm-manifests.sh's own
# header for the actual regression this exists to catch (helm lint and
# a bare `helm template` both exit 0 on it; only `helm upgrade`'s
# server-side validation against a real cluster did).
helm-template:
	docker run --rm -v "$(CURDIR)":/src -w /src --entrypoint sh alpine/helm:4.2.0 cluster/check-helm-manifests.sh
	@# Every workload that talks to Postgres must be admitted by the
	@# NetworkPolicy in front of it -- see the script for the three times
	@# this repo has shipped one that was not.
	docker run --rm -v "$(CURDIR)":/src -w /src --entrypoint sh alpine/helm:4.2.0 -c "apk add --no-cache python3 py3-yaml >/dev/null && python3 cluster/check-postgres-netpol.py"
	@# A two-registry values file must render a merged docker config that
	@# is actually usable -- see the script for the three ways it can be
	@# wrong while `helm template` still exits 0, every one of which
	@# degrades to an anonymous pull rather than an error.
	docker run --rm -v "$(CURDIR)":/src -w /src --entrypoint sh alpine/helm:4.2.0 -c "apk add --no-cache python3 py3-yaml >/dev/null && python3 cluster/check-registry-credentials.py"
