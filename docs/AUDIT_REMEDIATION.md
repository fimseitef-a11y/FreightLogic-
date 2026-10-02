# Audit remediation ledger

The operator authorized remediation after the repository-wide read-only audit.
This branch starts at `e6903330386fe43187c8021eda8e9c0e2e5c9fa3` (main,
application 24.0.58, database schema 16, backup Worker 33).

This is a bounded first remediation batch. It does **not** close the full audit.
No deployment, merge, agent activation, credential rotation or live-data change
is part of this batch. Application/cache generation 24.0.59 is a source candidate;
database schema 16 and Worker 33 remain unchanged.

## Implemented changes

| Audit finding | Implemented behavior | Regression evidence |
| --- | --- | --- |
| ST01 | IndexedDB open failures reject with the original error without deleting the database. Successful connections close and announce reload on version change. | `audit-storage-recovery.spec.mjs`: VersionError, quota error, unknown error and version-change behavior. |
| ST05 (M6 importer portion) | Sparse or ambiguous reused-ID evidence is withheld with provenance; unique merges require shared provider and event-time evidence. More informative evidence is processed first. Invalid calendar dates are rejected. Unknown deadhead/amount cannot create defensible True RPM. | `audit-m6-identity.spec.mjs`: production reconciliation and full CLI fixtures. The separate application identity paths remain open. |
| COOR01 | Local shared-file checks require the current session token. CI validates lock trailers against coordination history at commit time and fails invalid claims. Amend/squash hooks no longer silently bypass trailer generation. | `audit-lock-session.spec.mjs`, existing lane tests and PR Lanes job. |
| PUI04 | Manifest shortcuts use implemented `#do=trip` and `#omega` routes. | Manifest assertions and existing deep-link/browser tests. |
| PUI05 | Push JSON null, primitives and arrays use the fallback notification instead of crashing. | Expanded `sw-push.spec.mjs` payload cases. |
| PUI06 | Notification clicks target a controlled app entry client; companion clients cannot consume the app handoff. | Two new production service-worker handler tests. |
| PUI12 | About copy acknowledges optional external processing. | Source review; consent and real-provider behavior remain external gates. |
| CFG01 (repository portion) | ELI, Agent and native checks cover all main PR/push changes, including upstream contracts outside former path filters. | `audit-ci-integrity.spec.mjs`; current-head workflow execution. Required-check repository settings remain unverified. |
| CFG02 (repository portion) | Backup/API deployment jobs share a concurrency group; contract checks use an independent per-ref group so production approval does not block PR CI. Backup/Admin require main, explicit DEPLOY and named production environments. | Workflow assertions. Environment reviewer configuration and live rollout remain external gates. |
| CFG03 | ELI runtime source is withheld by the actual deploy asset matcher. Private-source probes use the correct broker schema filename and include ELI/Agent paths. | Recursive asset-matcher tests and withholding-probe assertions. No live upload was performed. |
| DOC01 (partial) | Lane ownership, frozen native scope and session-token instructions agree with current authority. | Source review and lane/parser tests. Other documentation drift remains open. |

## Verification discipline

The new specifications are registered in `node tests/run-all.mjs`; existing
assertions remain active. The app.js lock protocol requires the full aggregate
suite on the integrated candidate. Pure V8 probes in the connected session
provide targeted evidence only; they do not substitute for Node, browser,
Swift, Worker, ELI or full CI execution. An attempted service-worker V8 probe
could not run because that sandbox has no URL global; this is an environment
limitation, not a passing test or a product failure.

Current candidate CI results are recorded in the PR and in
`.agents/TEST_LEDGER.md` on `agent-coordination`. Historical green main results
do not certify this candidate. No physical iPhone, authenticated provider,
production notification or live migration is certified here.

## Unresolved audit backlog

The following remain open unless a later reviewed commit and its current-head
evidence explicitly close them. The bounded changes above are not evidence for
unmodified code.

- Freight/storage: ST02-ST04, ST05 application portion, ST06-ST16.
- Money: FIN01-FIN08.
- Backup/API/security: WSEC01-WSEC12.
- ELI: ELI01-ELI12.
- AI agents: AGN01-AGN05.
- Native/companion: NAT01, ANCS01.
- Product/PWA/accessibility: PUI01-PUI03, PUI07-PUI11.
- Verification/performance/legacy: VER01-VER02, PERF01, LEG01.
- Configuration and documentation: external CFG01-CFG02 gates and remaining
  DOC01 drift.

Dependencies: preserve nullable facts and provenance before changing financial
aggregation; establish provider identity before deduplication; validate model
output before persistence; fence replay/idempotency before retries; test storage
upgrade/recovery before deployment; verify environment protections before any
privileged workflow dispatch.

P0 work remains in database/import preservation, operational and financial
unknown handling, credential authority, structured AI validation and queue/data
idempotency. P1 work remains in ELI freshness/lease/receipt handling, provider
identity, Worker deadlines and notification reliability. P2 work remains in
mobile accessibility, scale evidence and observability. P3 includes remaining
documentation and dormant compatibility cleanup.

Only verified defects should be remediated, with regression cases that would
fail on the affected production path. No blind dependency upgrades, inference
as operational truth, or replacement of missing facts with zero is authorized.
