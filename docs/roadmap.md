# Roadmap

Source of truth for the daily automated review. Seeded from the *Next-Phase
Plan* (2026-09-17).

The review has no memory between runs. Without this file it re-proposes work
that was considered and deliberately rejected, and it cannot tell a genuinely
new finding from something already scheduled three phases out. Everything
below exists to answer one question per item: **has this already been
decided, and if so, what was decided?**

## Accepted

Work in the current phase, tracked to completion. Items graduate here from
**Deferred** as each phase opens.

| ID | Item | Phase | Status | PR |
|---|---|---|---|---|
| H-1 | Scope split (`scan` vs `results:write`) + default-closed enforcement | 0 | done — also added `stage:write`, so a CI key never needs `admin` | #216 |
| S-1 | Dashboard proxy: no master-key fallback, GET-only, ClusterIP, read-only scope | 0 | partial — fallback already fails closed (#212); `limit_except`, ClusterIP and the read-only scope remain | |
| S-4 | No master-key fallback in image scan Jobs; `token_mint_failed` + alert | 0 | partial — refusal, retry and classification already shipped; only the counter and PrometheusRule alert remain | |
| S-2 | `make check-live-secrets` against every cluster that ever ran the chart | 0 | open | |
| S-7 | Tekton examples use a scoped `ci` key | 0 | done — `register\|scan\|read\|stage:write`, no `admin` | #222 |
| L-1 | Split `postgres_store.go` by concern, before H-2 | 0 | open | |

## Deferred

Accepted in principle, not yet in play. No status is tracked until the item
reaches **Accepted** — a Deferred item is never a review finding.

| ID | Item | Lands in |
|---|---|---|
| H-3 | Provenance verification on; bundle support; dogfooded in CI; `require_provenance` | Phase 1 |
| H-5 | Per-source finding ownership in the SBOM sweep; trivy + grype re-evaluate | Phase 1 |
| M-2 | CycloneDX SBOM+VEX export; fleet findings CSV; validated by a Dependency-Track import | Phase 1 |
| S-8 | Registry credentials never on argv | Phase 1 |
| S-9 | Loud warning when backups run unencrypted; `make backup-key` in quickstart | Phase 1 |
| H-2 | API-managed keys: create/list/revoke, expiry, hashed at rest | Phase 2 |
| M-3 | CycloneDX fleet VEX + cached fleet-VEX reads | Phase 2 |
| *new* | Versioned pluggable-scanner schema + conformance test + user-guide page | Phase 2 |
| M-6 | modelscan as the first out-of-tree pluggable scanner | Phase 2 |
| M-1 | Three policy fields + Kyverno external-data example — **not** the CEL engine (see Declined) | Phase 2 |
| S-3 | In-process SSRF: fail closed on unresolvable hosts, dial vetted addresses only | Phase 2 |
| H-4 | Fleet gauges behind the metrics token + PrometheusRule alerts | Phase 3 |
| S-5 | TLS in-cluster by default, ClusterIP, Postgres `verify-full`, `insecureDev` escape hatch | Phase 3 |
| S-6 | Metrics token required when exposed; trusted-proxy CIDRs narrowed; throttle keyed on peer | Phase 3 |
| L-3 | Blast-radius SQL view + endpoint | Phase 3 |
| M-4 | Notification digest CronJob + issue-shaped webhook payload | Phase 3 |
| M-5 | Dashboard: sparkline, top-risks panel, failed-scan recovery state | Phase 3 |
| S-10 | Manual dashboard key override moves to `sessionStorage` | Phase 3 |
| L-2 | PITR/HA: document the CloudNativePG or WAL-G path only — **not** built by hand (see Declined) | Phase 3 |

## Declined

Not being built. Each row carries the reason it was rejected and the single
condition that would justify revisiting it.

| Not building | Why not | Reopen if |
|---|---|---|
| Multi-tenancy: projects/teams as authz boundaries (L-4) | Biggest lift on the list; only pays off with more than one team on one instance. Dependency-Track owns this ground. | A paying client wants two teams on one deployment, or a second maintainer joins. |
| Users, SSO/OIDC, RBAC UI | Same buyer as multi-tenancy. Named scoped keys plus API-managed keys (H-2) cover CI and one ops team. | Same trigger as above, or an audit requires per-person attribution beyond key names. |
| CEL policy engine (M-1) | First non-stdlib dependency beyond pgx, plus an evaluation surface to secure. Two or three policy fields cover the gates people actually write. Kyverno at admission covers the rest. | A concrete client policy cannot be expressed as JSON fields plus a Kyverno rule. |
| SPA dashboard / trend charts beyond M-5 | The static page with 74 tests is a feature (auditable, no build chain). | Someone other than the maintainer uses the dashboard daily. |
| Ticketing sync (Jira), SLA clocks, assignment | Workflow product territory. The digest plus a generic "create issue" webhook payload (M-4) is the ceiling. | A client runs remediation out of SCM rather than out of their tracker. |
| Postgres HA / PITR by hand (L-2) | Document a CloudNativePG or WAL-G migration path in the chart; do not build it. | The store holds evidence a client is contractually required to retain. |
| Horizontal scale-out of monitor-api | Advisory-lock scan slots and one API pod are right-sized for fleets of hundreds, not hundreds of thousands. | Sweep duration exceeds the sweep interval on a real fleet. |
| Adopting GUAC | The component index plus one SQL blast-radius view (L-3) answers the common questions at this fleet size. | Cross-artifact attestation graph queries become a real ask. |

### Two IDs appear twice, with different scopes

**M-1** and **L-2** are listed in both Declined and Deferred. This is not a
contradiction, and reading only the Declined row will cause scheduled work to
be skipped:

- **M-1** — the *CEL engine* is declined. *Three JSON policy fields plus a
  Kyverno example* is Phase 2 work.
- **L-2** — *hand-built Postgres HA/PITR* is declined. *Documenting the
  CloudNativePG or WAL-G migration path* is Phase 3 work.

## How the daily review uses this file

Read it before reporting anything.

- **Declined items are closed.** Never re-propose one unless its reopen
  trigger is *visibly* met in the repo or the conversation — the trigger is a
  fact to be observed, not a judgement call. If a trigger has been met, say
  which one and what met it.
- **Accepted items get one of three verdicts:** done, regressed, or still
  open. Do not redesign them, re-argue their approach, or expand their scope.
- **Deferred items are not findings.** Noting that Phase 3 work has not
  happened is noise.
- **Genuinely new findings go in their own section**, clearly separated from
  the items above, so they can be triaged into this file rather than
  rediscovered next run.

When an item's state changes, edit this file in the same PR that changed it.
