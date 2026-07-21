# Runtime backend: colima (default) or podman. See cluster/create-cluster.sh.
SCM_RUNTIME  ?= colima
IMAGE        := monitor-api:dev

.PHONY: cluster-up cluster-down cluster-destroy build deploy undeploy port-forward logs scan-jobs test-artifact test test-api test-postgres test-dashboard check-dashboard-configmap db-shell lock-deps db-backup db-restore db-backups-list

cluster-up:
	SCM_RUNTIME=$(SCM_RUNTIME) ./cluster/create-cluster.sh

cluster-down:
	SCM_RUNTIME=$(SCM_RUNTIME) ./cluster/destroy-cluster.sh

cluster-destroy:
	SCM_RUNTIME=$(SCM_RUNTIME) ./cluster/destroy-cluster.sh --delete

# On the colima runtime, this is all you need -- colima's k3s (docker
# runtime) shares the same image store as `docker build`, so there's no
# import step. On the podman runtime, export the DOCKER_HOST printed by
# `make cluster-up SCM_RUNTIME=podman` first, so `docker build` here
# actually talks to the podman machine.
build:
	docker build -t $(IMAGE) services/monitor-api

# `kubectl apply` only restarts a pod when the Deployment *spec*
# changes. Rebuilding monitor-api:dev with new code but the same tag
# looks identical to it, so a running pod can silently keep serving old
# code indefinitely -- the rollout restarts below force it to actually
# pick up whatever was just built.
deploy: build
	kubectl apply -k k8s/
	kubectl -n supply-chain-monitor rollout restart deployment/monitor-api deployment/scm-dashboard
	kubectl -n supply-chain-monitor rollout status deployment/monitor-api --timeout=60s
	kubectl -n supply-chain-monitor rollout status deployment/scm-dashboard --timeout=60s

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

# Triggers an immediate pg_dump backup (see k8s/postgres/backup-cronjob.yaml,
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
# Secret's placeholder, changeme-api-key, unless you've rotated it) --
# every endpoint but /healthz requires it now (see README's
# Authentication section).
SCM_API_KEY ?= changeme-api-key
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
# edited without regenerating the ConfigMap that actually serves it, so
# the running dashboard silently drifts from the source file. Point
# whatever CI you wire up against your own git server at this target
# (plus test-api and test-dashboard above).
check-dashboard-configmap:
	python3 -c "\
import yaml, sys; \
cm = yaml.safe_load(open('k8s/dashboard/configmap.yaml')); \
embedded = cm['data']['index.html']; \
original = open('dashboard/index.html').read(); \
sys.exit(0) if embedded.rstrip(chr(10)) == original.rstrip(chr(10)) else (print('k8s/dashboard/configmap.yaml is out of date -- see README') or sys.exit(1))"
