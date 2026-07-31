# Tech debt audit — supply-chain-monitor

Date: 2026-07-31. Scope: the whole repo (`services/monitor-api`, `charts/supply-chain-monitor`, `cluster/`, `dashboard/`, `docs/`). Method: direct inspection of the current codebase (file contents, git history, test layout), not a rehash of `docs/architecture.md`'s existing "Roadmap / open gaps" section — that section is good and current; this audit cross-references it rather than duplicating it, and adds findings that section doesn't cover (documentation staleness, CI, test-coverage gaps).

Scoring per item follows the brief: **Impact** (1–5, how much this slows the team down), **Risk** (1–5, cost of not fixing it), **Effort** (1–5, cost to fix — inverted in the formula). **Priority = (Impact + Risk) × (6 − Effort)**.

## Status

- **#1 (No CI)**: `.github/workflows/ci.yml` added -- `test-api`,
  `test-postgres`, `test-dashboard`, `check-dashboard-configmap`, and
  `shellcheck` (folding in #8 below at the same time, since it was zero
  extra cost once CI existed at all) on push/PR to `main`. Not yet
  confirmed green against a real GitHub Actions run -- this sandbox has
  no git push credentials or `gh`/Docker access, so pushing this and
  reporting back the first run's results is the next step, iterating
  from there the same way every other real-environment check in this
  project's history has been debugged (real command output pasted back,
  fixed, repeat).
- **#2 (Stale docs)**: fixed -- `go.mod`, `docs/architecture.md`'s two
  stale Roadmap entries, and the `test-api`/`test-postgres` Makefile
  comments all updated to reflect that `go.sum` is committed and the
  cluster automation has been run for real.
- **#5 (Dockerfile still re-resolving deps)**: fixed -- `Dockerfile`'s
  build stage now runs `go mod download && go mod verify` (and copies
  `go.sum` explicitly) instead of `go mod tidy`; `make test-api`/`make
  test-postgres` do the same for consistency between local and CI runs.
- **#8 (No shellcheck)**: addressed by the same CI workflow as #1 above.

Everything else in this document is still open.

## Findings

| # | Item | Category | Impact | Risk | Effort | Priority |
|---|------|----------|:-:|:-:|:-:|:-:|
| 1 | No CI at all | Infrastructure | 5 | 5 | 1 | 50 |
| 2 | Stale docs: go.sum/digest comments say things no longer true | Documentation | 3 | 2 | 1 | 25 |
| 3 | In-process malware-scan fallback has zero unit tests | Test | 4 | 4 | 2 | 32 |
| 4 | PostgresStore's non-trivial logic only runs under a build tag nobody automates | Test | 4 | 4 | 2 | 32 |
| 5 | `go mod tidy` in Dockerfile still re-resolves every build despite go.sum being committed | Dependency | 2 | 3 | 1 | 25 |
| 6 | Plaintext default password/API key committed to values.yaml (already tracked in Roadmap) | Infrastructure/Security | 3 | 4 | 3 | 21 |
| 7 | Single shared API key, no per-client identity (already tracked in Roadmap) | Architecture | 3 | 3 | 4 | 12 |
| 8 | No shellcheck/lint on `cluster/*.sh` (1,074 lines across 13 scripts) | Test | 3 | 3 | 1 | 30 |
| 9 | `handlers.go` (754 lines) and `postgres_store.go` (827 lines) carry a lot of responsibility each | Code | 2 | 2 | 4 | 8 |

(Sorted by priority below, not by table order.)

### 1. No CI — priority 50

Every safeguard this project has (Go tests, dashboard tests, the dashboard-configmap-drift check, `go vet`) exists only as a `make` target someone has to remember to run by hand before pushing. Nothing enforces that on a PR or on `main`.

This isn't hypothetical: in this project's own recent history, two regressions were written by the same process that wrote the rest of the code and were only caught because a human happened to run `go test ./...` afterward — a rate-limiter test whose assertion was backwards, and a duplicate-registration test whose fake resolver didn't actually exercise the case it claimed to. Both would have merged clean on `git push` alone. A private GitHub repo (this one already has one — `github.com/Sifungurux/supply-chain-monitor`) supports Actions on private repos; every test target here already runs inside Docker (`golang:1.22-alpine`, `node:22-alpine`), so a runner needs nothing installed beyond Docker itself.

**Business justification**: the cost of a regression reaching `main` (and from there, `make deploy`'s auto-commit-and-push-to-Flux flow) is a live cluster running broken code, discovered after the fact rather than blocked before merge. Fixing this is one YAML file.

**Fix**: a `.github/workflows/ci.yml` running `make test-api`, `make test-dashboard`, and `make check-dashboard-configmap` on push/PR to `main`. `make test-postgres` needs a bit more (it wants `--network host`, documented as Colima-only) — worth a separate job using a Postgres service container instead of the Makefile's own throwaway-container approach, since GitHub Actions runners don't have Colima.

### 3. In-process malware-scan fallback has zero unit tests — priority 32

`internal/scanner/clamav.go` (`ClamAVScanner.Scan`), `internal/scanner/clamd_client.go` (`scanFileWithClamd`), and `internal/scanner/unpacker.go` (`UnpackerScanner.Scan`) have no `_test.go` files of their own. `isolated_unpacker_test.go` exists and is thorough, but it only exercises `IsolatedUnpackerScanner` — the Kubernetes-Job-wrapping layer, tested against a fake k8s client — never the actual clamd-protocol/oras-pull/file-walking code these three files contain. That code only runs today when `DISABLE_SCAN_ISOLATION=true`, but it's still the code that ran in this cluster for real during the recent multi-node testing (see the `disableScanIsolation` misconfiguration this session already fixed), and it's the malware-scanning path specifically — the one place a bug has the highest plausible blast radius.

**Fix**: unit tests for `scanFileWithClamd` against a fake clamd (a local TCP listener speaking the INSTREAM protocol) and for `UnpackerScanner.Scan`/`ClamAVScanner.Scan` against faked `unpacker`/`clamd` binaries or interfaces, mirroring the faking pattern `isolated_unpacker_test.go` already uses for the Job layer.

### 4. PostgresStore's real logic only runs under a build tag nobody automates — priority 32

`postgres_store.go` is the single largest file in the service (827 lines) and the only persistence path production actually uses (`docs/architecture.md`: "production always talks to a real database"). Its tests (`postgres_store_integration_test.go`) are gated behind `-tags=postgres_integration` specifically so `go test ./...` — what `make test-api` runs, and what CI would run per finding #1 — never touches it. The only way this code gets tested today is `make test-postgres`, a separate target nobody is required to run, that isn't wired into any automated check. Combined with finding #1, this means the most important file in the service can regress silently indefinitely.

**Fix**: once CI exists (#1), add a `test-postgres` job using a Postgres service container (GitHub Actions supports this natively, no `--network host` workaround needed) so this path is exercised on every PR too, not just when a developer remembers.

### 8. No lint on cluster/*.sh — priority 30

13 shell scripts, 1,074 lines total, several with real logic (`podman.sh` alone handles SSH host-key cleanup, cgroup delegation, and DOCKER_HOST resolution). This session alone fixed several real bugs in exactly this code (macOS `date` incompatibility, a `SCRIPT_DIR` variable collision from `source`-ing rather than sub-processing, `set -e` silently swallowing curl/jq failures). `shellcheck` would have caught at least the `SCRIPT_DIR` collision class of bug (it flags variable shadowing/reuse patterns) and is a single static-analysis pass with no runtime dependencies.

**Fix**: add `shellcheck cluster/**/*.sh` as a CI step (finding #1) — a `shellcheck/shellcheck` Docker image exists, so no local install needed either, consistent with every other test target in this Makefile.

### 2. Stale docs — priority 25

Two concrete contradictions found between what the codebase says and what it does:

- `go.mod`'s comment says "go.sum is intentionally NOT committed" and `docs/architecture.md`'s Roadmap repeats this ("`go.sum` still isn't committed"). `git log` shows `services/monitor-api/go.sum` has been tracked since `f0b9c95` (2026-07-22) — someone ran `make lock-deps` and committed it, and neither comment was updated.
- `docs/architecture.md`'s Roadmap also still says "**Never actually run/verified against a live cluster** ... never executed against a real Kubernetes API." This session alone ran `cluster-up`, `deploy`, and `load-test-clamav` against a real multi-node podman/k3d cluster repeatedly. That entry is now false.

**Fix**: update both. Small effort, but worth doing before it misleads the next person (or the next Claude session) into re-deriving conclusions that are already wrong.

### 5. Dockerfile still re-resolves dependencies despite go.sum being committed — priority 25

Follows directly from #2: now that `go.sum` is committed, `Dockerfile`'s `RUN go mod tidy` (line 14) is still what runs on every build. `go mod tidy` can rewrite `go.sum` (re-resolving the module graph) rather than just verifying it against what's committed — the opposite of what committing `go.sum` is for. The Dockerfile's own comment already half-acknowledges this ("Once someone runs `go mod tidy` locally and commits go.sum, this becomes a no-op verification step instead of a resolution step") but that's not quite true either: `go mod tidy` isn't a pure verification command the way `go mod verify` or a plain `go build` (which fails loudly on a checksum mismatch, using exactly what's committed) would be.

**Fix**: change `RUN go mod tidy` to `RUN go mod download && go mod verify`, or drop it entirely and let `go build` do the verification it already does implicitly. Either removes the every-build network dependency `go.sum` was committed to eliminate.

### 6 / 7. Plaintext secrets, single shared API key — priority 21 / 12

Both already tracked in `docs/architecture.md`'s Roadmap ("Secret management", "AuthN/Z is a single shared key"). Repeating them here only to score them against the rest of this list: they're real, but lower priority than #1–#5 for a project still at the "local dev cluster, not yet exposed anywhere" stage the Roadmap itself describes. Worth doing before this cluster holds anything real, not necessarily before Phase 2's Tekton work.

### 9. Two large files — priority 8

`handlers.go` (754 lines: every HTTP handler in one file) and `postgres_store.go` (827 lines) aren't badly structured — both are heavily commented, single-responsibility-per-function, and this session's own manual reviews of them found no confusion attributable to size. Listed for completeness, not urgency: splitting `handlers.go` by resource (artifacts/findings/stages) would be a reasonable future refactor if it keeps growing, not something worth doing today.

## Phased remediation plan

Framed against the fact that Phase 2 (a Tekton pipeline for malware/CVE scanning) is starting next — this plan front-loads the items that make Phase 2 itself safer to build, and defers the rest.

**Before Phase 2 starts** (small, high-leverage, protects the new work too):
1. Stand up CI (#1) — `test-api`, `test-dashboard`, `check-dashboard-configmap` on push/PR. Once this exists, the Tekton pipeline work in Phase 2 gets the same safety net from day one instead of retrofitting it later.
2. Fix the two stale docs (#2) — five-minute fix, removes two landmines for whoever (human or Claude) reads this repo's docs next.
3. Fix the Dockerfile's `go mod tidy` (#5) — small, and Phase 2 will likely touch the Dockerfile anyway (adding a Tekton-facing entrypoint or similar), so it's a natural time to also fix this.

**Alongside Phase 2** (do incrementally, not a blocking prerequisite):
4. Add `shellcheck` to CI (#8) once CI exists — one more `make`-style target, no reason to delay past #1.
5. Add tests for the in-process scanner fallback (#3) — worth doing before Phase 2's pipeline potentially starts exercising `DISABLE_SCAN_ISOLATION` paths in a CI/test context, if Tekton tasks end up running scans outside the isolated-Job path.
6. Wire `test-postgres` into CI as a proper service-container job (#4) — depends on #1 existing first.

**Defer past Phase 2** (real, but lower urgency at this project's current stage):
7. Secret management (#6) and per-client API keys (#7) — do before this cluster ever holds real data or is reachable from outside a local dev machine, not before Phase 2.
8. Splitting up large files (#9) — revisit only if `handlers.go`/`postgres_store.go` keep growing; not worth touching preemptively.
