# FreightLogic Completion Release — Certification State

Date: 2026-09-02
Candidate: `fc51067c9b9fd6e5df0c73fdd505d4bc2aa07946`
Release: FreightLogic v24.0.2 / DB v15 / Worker v13
Supersedes: COMPLETION_RELEASE_CERTIFICATION_STATE_2026-08-27.md, COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-08-28.md
Status: **HOLD — IPHONE UPDATE PATH FAILED; LIVE AND PHYSICAL CERTIFICATION PENDING**

This is the current certification-state record for the completion candidate. It
supersedes the two earlier HOLD records named above without deleting their audit
history. The canonical milestone order remains
`docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`.

## Exact-candidate evidence

The Issue #119 code-side completion batches are present on the candidate:

- PR #124 merged the Batch A/B/C implementation as `6cce967`.
- PR #125 merged the v24.0.2 release documentation as `fa63be5`.
- PR #126 repaired the two time-rotting M4 lifecycle fixtures and merged as
  `e7fe4d2`.
- PR #127 recorded the completed v24.0.2 documentation handoff and merged as
  the initial exact candidate, `14c489582f65716fc2f33d88918184477e7060d9`.
- PR #134 repaired the service-worker update handshake with a real
  update/activation/exactly-one-reload regression and merged as the current
  exact candidate, `fc51067c9b9fd6e5df0c73fdd505d4bc2aa07946`.

GitHub Actions run `33676594807` tested that initial exact candidate with:

- `node tests/run-all.mjs`
- **318 passed / 0 failed across 32 spec files**

The fast automated release preflight on that initial candidate reported **13 PASS,
0 FAIL, and 1 SKIP**. The skipped item is the full suite by design in fast mode;
the initial-candidate GitHub Actions result above supplies the separate full-suite
evidence. Static checks confirmed v24.0.2 app/PWA/service-worker parity, Worker
v13, DB v15, CSP parity, critical offline-shell coverage, and release-gate
wiring.

The Cloudflare Workers build checks attached to PRs #126 and #127 succeeded.
Those build checks establish deploy-pipeline acceptance, not production-origin
identity or runtime behavior.

On the current exact candidate, GitHub check run `100463413904`
(`playwright-suite`) and Cloudflare check run `100463941013` (`Workers Builds:
freightlogic-v2`) both completed successfully. The Cloudflare build identifies
production Worker version ID `7b543f0a-b9bf-4203-bb60-5dcf885e5297`. These
checks prove repository integration and acceptance by the configured Worker
project; they still do not prove that the installed iPhone PWA's original web
origin is that project or serves this generation.

## Resolved disposition of the earlier source blockers

The source defects and missing regressions itemized in the 2026-08-27 state and
2026-08-28 addendum were completed through the Issue #119 Batch A/B/C work. The
initial-candidate suite covers the corresponding migration, lifecycle,
durability, unknown-value, intake, Worker-projection, evidence, and M6
reconciliation behavior. The former 241-test baseline is therefore historical;
the recorded automated result for that initial candidate is 318/0/32. The
current candidate additionally carries the PR #134 update-handshake regression
and has a green exact-head `playwright-suite` check.

This statement closes the earlier enumerated source blockers. It does not
convert unobserved deployment or device checks into passes, and later field
evidence may reopen a code-side gate as described below.

## Remaining release gates

The candidate remains on HOLD until both evidence classes below are observed on
this exact release generation.

### Observed A1 failure — installed iPhone remained on v23.7.0

On 2026-09-02, the operator supplied screenshots from the installed iPhone Home
Screen PWA. The app launched, but its More screen reported **FreightLogic
v23.7.0**, not v24.0.2. It also presented first-run onboarding.
`FIELD_TEST_CHECKLIST.md` A1 is therefore **FAIL**, not pending or passed.

Exact-current source review found an uncovered update handshake defect:

- `sw-bridge.js` reloads on `controllerchange` only after its private request
  flag is set through `_flRequestSWUpdate`;
- the `app.js` update-ready button bypasses that helper and sends
  `SKIP_WAITING` directly to the installing worker;
- the helper itself targets the active controller rather than deliberately
  targeting the waiting worker; and
- the automated suite contains no real regression for update-ready -> waiting
  worker -> controller change -> exactly one reload.

PR #134 repaired this defect: the app routes the update action through the
bridge, the bridge deliberately targets the waiting/installing worker, and a
bounded fallback plus an exactly-once guard prevents both a stuck stale page
and a reload loop. The regression drives an actual service-worker byte change,
activation, controller handover, and exactly one reload. The exact merged
candidate's Playwright and Cloudflare checks are green.

The older v23.7.0 bridge performs an immediate `registration.update()` and an
unconditional controller-change reload. That makes an old/wrong production
origin, a stale Pages/assets deployment, or a failed network update the primary
investigation for this exact device observation. The repaired v24.0.2 defect
cannot by itself explain why this device is still executing v23.7.0.
Certification requires exact installed-origin and production-generation
verification and a safe retest on the operator's iPhone. Do not use PWA deletion
or Safari website-data clearing as the primary remedy because those actions can
erase local IndexedDB evidence.

### 1. Live Cloudflare verification

Verify against the production Pages and Worker origins:

- the served app/PWA generation is v24.0.2 and the live Worker reports v13;
- Worker `/health` succeeds;
- unauthorized admin access is rejected;
- non-sensitive `/evaluate` and `/extract` smoke requests preserve the canonical
  authority boundary; and
- the deployed assets match the frozen candidate rather than an older cache or
  build.

The automated review environment could not reach the live origins: the Pages
request ended at an upstream 502 connection refusal and the Worker origin was
blocked by the client environment. These are **UNOBSERVED**, not product
failures and not passes.

### 2. Physical iPhone verification

Complete the finite device checks in `FIELD_TEST_CHECKLIST.md`, including:

- install, update, launch, and offline behavior;
- one-handed UNKNOWN-versus-zero presentation;
- M5B manual/email-compatible intake durability;
- local export/import on-device;
- GPS/background/permission-loss behavior; and
- stale-edit conflict handling.

No physical-device result was available to this review. These checks remain
**PENDING** and must not be inferred from desktop Chromium automation.

## Rollback point

The executable pre-v24.0.2 rollback reference is
`07d7e4ae46a8765bd60b21c18a7b920503782ff7`, the parent of the v24.0.2 version
freeze and the last v24.0.1 generation. It is identified for operator use only;
performing a rollback remains a deliberate operator decision after confirming
the deployment target and data-compatibility implications.

## Repository and integration disposition

- The exact candidate has a green automated suite and the code-side update
  handshake repair is merged, but the physical A1 observation remains failed
  until the installed origin serves the current generation and the device is
  safely re-tested.
- Issue #119 remains open as the finite completion tracker until the outstanding
  observations are recorded.
- No open pull request was present when this state was prepared.
- GitHub reports `main` branch protection disabled. The repository owner should
  enable protection and require the existing Playwright, path-ownership,
  commit-prefix, lock-trailer, and Cloudflare build checks; this is a repository
  administration action, not release evidence.
- Do not label, tag, freeze, or announce the completion release while this record
  remains HOLD.

## Certification rule

Change this state from HOLD only after the live Cloudflare and physical iPhone
results are recorded for the exact candidate (or for a newer candidate that has
its own exact-SHA automated evidence). Until then, v24.0.2 is a green code
candidate, **not a certified completion release**.

The controlling rule remains: **EVIDENCE -> TEST -> CHALLENGE -> RECONCILE ->
CERTIFY -> ADOPT**.
