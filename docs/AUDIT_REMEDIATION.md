# Audit remediation ledger

The operator authorized remediation after the repository-wide read-only audit.
This branch starts at `e6903330386fe43187c8021eda8e9c0e2e5c9fa3` (main,
application 24.0.58, database schema 16, backup Worker 33).

This is a series of bounded remediation batches. It does **not** close the full audit.
No deployment, merge, agent activation, credential rotation or live-data change
is part of this batch. Application/cache generation 24.0.59 is a source candidate;
database schema 16 remains unchanged; Worker 34 is a source candidate.

## Implemented changes

| Audit finding | Implemented behavior | Regression evidence |
| --- | --- | --- |
| ST01 | IndexedDB open failures reject with the original error without deleting the database. Successful connections close and announce reload on version change. | `audit-storage-recovery.spec.mjs`: VersionError, quota error, unknown error and version-change behavior. |
| ST05 (M6 importer portion) | Sparse or ambiguous reused-ID evidence is withheld with provenance; unique merges require shared provider and event-time evidence. More informative evidence is processed first. Invalid calendar dates are rejected. Unknown deadhead/amount cannot create defensible True RPM. | `audit-m6-identity.spec.mjs`: production reconciliation and full CLI fixtures. The separate application identity paths remain open. |
| WSEC01 (legacy migration portion) | Plaintext index migration cannot overwrite the canonical user before credential authority is checked. Retired, revoked and orphan credentials fail closed; valid legacy migration preserves current metadata. Other stale whole-account write/concurrency paths remain open. | Five real Worker-handler token-authority regressions; targeted authorization probes. |
| ELI evidence-ordering (partial concurrent contribution) | A concurrent writer added source-time revision ordering, A-to-B-to-A reactivation and repair after raw append/index interruption. Those commits are preserved; this does not establish concurrent writer fencing, equal-time tie correctness or receipt/materialization recovery. | Three SQLite production-path regressions in `audit-evidence-ordering.test.mjs`; current integrated ELI CI. |
| ELI10 (confidence domain portion) | Confidence requires a finite numeric value in [0,1] and a known fresh/aging state; unsupported freshness or confidence remains UNKNOWN. Explicit zero survives. Identity and broader contract issues remain open. | Three ELI contract cases covering valid bounds, invalid types/ranges and unknown freshness. |
| NAT01 (input guard portion) | Original WebKit JSON envelopes are bounded before additional serialization/decoding; unknown fields, deep/large bodies and nonfinite values are rejected. | Native bridge regressions; Swift CI. Physical WebKit/iPhone behavior remains an external gate. |
| ANCS01 (prototype transport portion) | The forwarding prototype requires HTTPS and a scoped relay key, uses the current intake relay envelope, clears credentials on failed reconfiguration and disables redirects. | Exact C initializer compiled/executed on the CI host, plus source protocol assertions. These do not verify ESP-IDF, BLE, TLS or hardware behavior. |
| WSEC07 and WSEC08 (extraction portion) | Text and vision output share strict object, whole-number, real-date, confidence and allowlist validation. Invalid supplied values remain nullable and uncertain. Explicit zero survives; text replies without explicit successful completion metadata fail closed and missing years are not inferred by the text prompt. | Seven real Worker-handler regressions with a stubbed model; real provider behavior remains an external gate. |
| COOR01 | Local shared-file checks require the current session token. CI validates lock trailers against coordination history at commit time and fails invalid claims. Amend/squash hooks no longer silently bypass trailer generation. | `audit-lock-session.spec.mjs`, existing lane tests and PR Lanes job. |
| PUI04 | Manifest shortcuts use implemented `#do=trip` and `#omega` routes. | Manifest assertions and existing deep-link/browser tests. |
| PUI05 | Push JSON null, primitives and arrays use the fallback notification instead of crashing. | Expanded `sw-push.spec.mjs` payload cases. |
| PUI06 | Notification clicks target a controlled app entry client; companion clients cannot consume the app handoff. | Two new production service-worker handler tests. |
| PUI12 | About copy acknowledges optional external processing. | Source review; consent and real-provider behavior remain external gates. |
| CFG01 (repository portion) | ELI, Agent and native checks cover all main PR/push changes, including upstream contracts outside former path filters. | `audit-ci-integrity.spec.mjs`; current-head workflow execution. Required-check repository settings remain unverified. |
| CFG02 (repository portion) | Backup/API deployment jobs share a concurrency group; contract checks use an independent per-ref group so production approval does not block PR CI. Backup/Admin require main, explicit DEPLOY and named production environments. | Workflow assertions. Environment reviewer configuration and live rollout remain external gates. |
| CFG03 | ELI runtime source is withheld by the actual deploy asset matcher. Private-source probes use the correct broker schema filename and include ELI/Agent paths. | Recursive asset-matcher tests and withholding-probe assertions. No live upload was performed. |
| DOC01 (partial) | Lane ownership, frozen native scope and session-token instructions agree with current authority. | Source review and lane/parser tests. Other documentation drift remains open. |

## Resumed remediation scope (2026-10-02)

The last fully green checkpoint was `3da02d21cbfff0439581fc62ffb42fb0d85fb664`:
application 1030 passing assertions across 102 specifications; ELI 85 passing,
zero failed/skipped; Swift 33 passing; Agent phase 42 passing, output guard
11 passing and ELI integration 20 passing. Seven PR workflows succeeded.
These results certify that checkpoint only. The browser harness did not report
an explicit skipped count.

Twenty-three subsequent contributor commits were preserved. At
`e1f163c08d07580d1aa8821c85419a3eb76b469d`, six workflows succeeded but the
application gate failed: 1039 passed, one failed across 102 specifications.
Its registry check found three recovered but unregistered specifications, and
the failure reporter then crashed on a legacy result without a failures array.
This resumed batch registers those specifications and tests the production
result normalizer; missing/invalid counts and zero assertions fail the gate.

| Finding | Bounded correction | Required evidence / remaining scope |
| --- | --- | --- |
| WSEC04-WSEC05 (recovered contribution) | Account erasure delimits the selected namespace, scans exact-owner Shortcut aliases, waits for child batches and deletes the revoked canonical account last. | Four real-handler recovery and isolation cases are now registered. Distributed erasure isolation and eventually consistent KV enumeration remain open. |
| FIN03 (recovered scoring/wizard portion) | Missing/invalid pay and deadhead withhold precise economics; explicit zero survives. Wizard inputs are read after asynchronous history so edits made while waiting are scored. | Three production preview boundary cases and three browser wizard cases are now registered. Other Money aggregation, sanitization and recognition issues remain open. |
| PUI03 | Modern-shell synchronization writes classes/attributes/text/styles only when values change, allowing its observer to settle. | Three Chromium cases exercise shipped adapter quiescence, disclosure and navigation. Physical-device performance/accessibility remain gates. |
| ELI freshness (partial) | Impossible/future evidence times remain UNAVAILABLE; lane and market reads age OPERATOR_PRIVATE freshness without another ingest and preserve stored evidence/provenance. Rule version is operator-freshness-v0.2. Projection rejects confidence outside [0,1]. | Node regressions cover time boundaries, lane/market read-time aging, invalid time, immutable evidence and confidence bounds. Other ELI provenance/identity/public-source policies remain open. |
| AGN01 (additional guard boundaries) | Currency and per-mile units are captured together, unsupported units/malformed monetary values fail closed, cent rounding replaces percentage tolerance, and model verdicts require a canonical verdict. | Existing negation/domain/deadline/provenance tests stay active; new dollar-unit, malformed-value and rounding cases must pass Agent CI. This guard does not certify arbitrary natural-language factual assertions. |
| AGN03 (completion fencing portion) | Result INSERT requires a current unexpired token and matching event fingerprint. Missing claim-capable state fails closed. Stale execution cannot persist or release its successor. | Four actual Worker/state SQLite cases; existing Agent/ELI integration now uses production state SQL. Provider cancellation and other Agent authority concerns remain open. |
| ELI queue completion/recovery (partial) | Receipt/state completion uses one atomic, token-checked batch; materialization precedes completion/ack, and retries recover historical lane repair targets. | Four real SQLite cases cover stale owner, expiry, rollback and interrupted route correction. Per-message materialization adds reads/upserts; global evidence-writer fencing, historical receipts and production migration remain open. |
| VER result reporting | Valid legacy result counts are preserved with safe failure details; malformed counts and empty specifications fail visibly. | Four production helper cases; registry completeness remains mandatory. |

The current source batch requires all seven current-head PR workflows. V8
production-function probes are targeted evidence only. Lease/receipt changes
and any additional concurrency corrections must be reconciled with real
production-path tests before claiming their bounded behavior verified.

## Verification discipline

The new specifications are registered in `node tests/run-all.mjs`; existing
assertions remain active. The app.js lock protocol requires the full aggregate
suite on the integrated candidate. Pure V8 probes in the connected session
provide targeted evidence only; they do not substitute for Node, browser,
Swift, Worker, ELI or full CI execution. An attempted service-worker V8 probe
could not run because that sandbox has no URL global; this is an environment
limitation, not a passing test or a product failure.

The first integrated suite exposed a missed manifest URL; its assertion stayed
active and the source was corrected. Worker generation tests now expect the
source candidate 34. The login-refusal fixture supplies CORS/preflight responses and awaits the actual 403 response and visible UI. The invalid-invite test starts in an independent app and
uses visible UI readiness instead of fixed sleeps after a manually removed
setup wizard; all error/no-wizard assertions remain active.

Current candidate CI results are recorded in the PR and in
`.agents/TEST_LEDGER.md` on `agent-coordination`. Historical green main results
do not certify this candidate. No physical iPhone, authenticated provider,
production notification or live migration is certified here.

## Unresolved audit backlog

The following remain open unless a later reviewed commit and its current-head
evidence explicitly close them. The bounded changes above are not evidence for
unmodified code.

- Freight/storage: ST02-ST04, ST05 application portion, ST06-ST16.
- Money: FIN01-FIN02, remaining FIN03 aggregation/recognition paths, FIN04-FIN08.
- Backup/API/security: remaining WSEC01 concurrency/write-authority paths, WSEC02-WSEC06, WSEC09-WSEC12, and remaining WSEC08 provenance/provider-verification concerns.
- ELI: ELI01-ELI09, remaining ELI10 identity/contracts, ELI11-ELI12.
- AI agents: AGN01-AGN05.
- Native/companion: remaining NAT01 platform and ANCS01 ESP-IDF/hardware, relay provenance and end-to-end gates.
- Product/PWA/accessibility: PUI01-PUI02, PUI03 pending current-head Chromium verification, PUI07-PUI11.
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
