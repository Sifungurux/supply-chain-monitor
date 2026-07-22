# Runtime backend: colima (default) or podman. See cluster/create-cluster.sh.
SCM_RUNTIME  ?= colima
IMAGE        := monitor-api:dev

.PHONY: cluster-up cluster-down cluster-destroy flux-install git-auth git-test gateway-api-install build deploy undeploy port-forward logs scan-jobs test-artifact test test-api test-postgres test-dashboard check-dashboard-configmap db-shell lock-deps db-backup db-restore db-backups-list

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
# import step. On the podman runtime, export the DOCKER_HOST printed by
# `make cluster-up SCM_RUNTIME=podman` first, so `docker build` here
# actually talks to the podman machine.
build:
	docker build -t $(IMAGE) services/monitor-api

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
# See cluster/postgres-restore.sh and README's "Backing up and
# restoring Postgres".
db-restore:
	./cluster/postgres-restore.sh $(BACKUP)

# quick smoke test against a port-forwarded API (run `make port-forward`
# first). SCM_API_KEY must match whatever's in scm-monitor-api-auth (the
# dev-only default in charts/supply-chain-monitor/values.yaml's
# monitorApi.apiKey, unless you've rotated it) -- every endpoint but
# /healthz requires it now (see README's Authentication section).
SCM_API_KEY ?= qwe4r56789009876543223456789
test-artifact:
	curl -s -X POST localhost:8080/api/v1/artifacts \
		-H "Authorization: Bearer $(SCM_API_KEY)" \
		-H 'Content-Type: application/json' \
		-d '{"ref":"alpine:3.19","type":"image"}' | tee /tmp/scm-artifact.json

test: test-api test-dashboard check-dashboard-configmap

# Runs services/monitor-api's Go test suite (handlers, store, pipeline)
# via a containerized golang image -- no local Go install needed, just
# Docker (which you already have via colima/podman). `go mod tidy`
# first for the same reason the Dockerfile runs it: go.sum isn't
# committed yet (see go.mod's comment), so it's resolved fresh here.
# This only exercises MemStore -- it needs no running Postgres. For a
# real database round-trip, see test-postgres below.
test-api:
	docker run --rm -v "$(CURDIR)/services/monitor-api":/src -w /src golang:1.22-alpine sh -c "go mod tidy && go test ./..."

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
		golang:1.22-alpine sh -c "go mod tidy && go test -tags=postgres_integration ./internal/artifact/..." ; \
	status=$$? ; docker stop scm-test-postgres >/dev/null 2>&1 ; exit $$status

# Runs dashboard/index.html's Node+jsdom test suite via a containerized
# node image -- no local Node install needed.
test-dashboard:
	docker run --rm -v "$(CURDIR)/dashboard":/src -w /src node:22-alpine sh -c "npm install --no-save >/dev/null && npm test"

# Generates and commits services/monitor-api/go.sum for real, pinned,
# reproducible builds -- see go.mod's own comment on why it isn't
# committed yet. Needs nothing but Docker: runs `go mod tidy` inside
# `golang:1.22-alpine` (which does have real internet access, unlike
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
	docker run --rm -v "$(CURDIR)/services/monitor-api":/src -w /src golang:1.22-alpine sh -c "go mod tidy && go vet ./... && go mod verify"
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
