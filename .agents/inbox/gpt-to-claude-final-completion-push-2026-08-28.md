# GPT -> Claude Code: final FreightLogic completion push

Date: 2026-08-28
Operator directive: **finish FreightLogic now and get the completion release certified; do not detour into competitive feature expansion before the release blockers are closed.**

## Current integration state

- Current `main`: `a6d5f9ff5ed5c88a025b9c8e6eea3fdc750d2ed9` or newer.
- No open pull requests were present when this packet was written.
- `agent-coordination/.agents/locks/` contained no active lock other than `.gitkeep`.
- PR #116 is merged: `scripts/m7-certify.mjs` now provides the finite automated Milestone-7 certification runner.
- PR #118 is merged: ANCS/DispatchLand notification-capture proof and future core handoff are documented. **ANCS is post-release product expansion unless it becomes necessary for an already-required intake gate; do not let it displace release correctness work.**
- The authoritative blocker descriptions remain `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-08-27.md` plus `docs/NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md` and the more detailed prior packet `.agents/inbox/gpt-to-claude-completion-continuation-2026-08-27.md`.

## Execution order — close, test, integrate, continue

Do not stop after one repair. Work through this finite order until only physical/operator-only checks remain.

### Batch A — release-integrity hotfix

Close the current-source correctness blockers with real-path regressions:

1. IndexedDB v14 `loadLifecycle` fresh + v13->v14 index creation (`updatedAt`, `orderNo`, `broker`).
2. `cloudPushBackup()` empty-delta lifecycle initialization/TDZ failure.
3. Protected export/checksum coverage for lifecycle + newly durable normalized evidence.
4. Reused external-ID safety across lifecycle linking, chips/editor lookup, route/time compatibility, and full timestamp preservation; ambiguity must fail safe.
5. `linkLifecycle()` background optimistic-concurrency/compare-and-abort race.
6. Worker compatibility with canonical absence: preserve `UNAVAILABLE`, grade `?`, `trueRPM=null`, and suppressed/null bid; never manufacture REJECT/F/$0.00 or competing canonical answers.
7. M3 real evidence wiring: actual fuel provenance, NWS zero-vs-no-observation semantics, compact evaluation evidence snapshot, actual lane/broker recency inputs, no broker materiality when absent, actual vehicle-fit evidence.
8. Durable normalized-opportunity evidence and a **real production M5B caller**: production surface -> `normalizeOpportunity()` -> durable evidence -> conservative lifecycle link. Preserve price/mileage semantics, source timestamps, confirmation state, raw evidence refs, unknown confirmation times, and DISPLAYED_TOTAL_MILES vs loaded-mile separation through reload/full+delta backup/restore/export/import/checksum.

### Batch B — M6 reconciliation correctness

Preserve the valid local `importJSON()` lifecycle fix, then correct the historical adapter/calibration path:

1. bounded collision-resistant deterministic row identity; retain long-provenance idempotency and same-length collision regressions;
2. never dedupe completed shipments by external order number alone and never set internal `stableId = orderNo` as identity;
3. explicit operator correction outranks lower-authority populated values;
4. material merged fields retain per-field provenance;
5. source `Carrier` is not canonical `broker` unless source semantics prove it;
6. DRY RUN is durably preserved as its own excluded operational class;
7. unknown/unrecognized status never manufactures award/WON evidence;
8. preserve clock-precision source timestamps;
9. calibration recency uses durable observation time; import/edit/current lifecycle `updatedAt` cannot make old evidence fresh; unknown observation age cannot receive full-current weight.

Re-run the operator's real historical bundle off-repo after correction. Raw personal/financial source files remain uncommitted. Report only non-sensitive reconciliation counts/status changes and calibration eligibility.

### Batch C — freeze the corrected generation

Only after A+B are green:

- select the final app/PWA/Worker generation;
- align app/service-worker/cache-busters/manifest/index/bridge/overlay/Worker `/health`/parity-verifier markers in one deliberate release step;
- preserve CSP byte parity and install-critical service-worker shell requirements;
- create a rollback point.

### Batch D — automated certification

On the exact integrated candidate SHA:

1. run the full required Playwright suite with no skipped/weakened safety assertions;
2. run lane checks;
3. run `node scripts/m7-certify.mjs --suite`;
4. resolve any failure at the cause; do not relabel a red gate as informational;
5. keep a frozen candidate once all automated gates are green.

### Batch E — operator-only release gate

When code is frozen and automated gates are green, stop changing runtime and give the operator the exact finite `FIELD_TEST_CHECKLIST.md` tasks for:

- physical iPhone install/update + one-handed critical journey;
- offline reload/install behavior;
- GPS/background/permission-loss behavior;
- live Pages/Worker parity;
- Worker `/health`, unauthorized admin denial, and non-sensitive `/evaluate` + `/extract` authority smoke;
- production M5B intake durability/export-import evidence check.

Do not invent completion of any physical/live check. Once those pass, update certification state to release-certified and record the exact release + rollback SHAs.

## Competitive scope discipline

The operator wants FreightLogic ahead of competitors, but the fastest path is a trustworthy releasable core. Therefore **do not add new load boards, anonymous network collection, ANCS hardware runtime, monetization, visual overhaul, or speculative AI features before the completion release is frozen**, unless a change directly closes an existing blocker.

After certification, the immediate competitive sprint should be: automatic multi-source opportunity intake -> instant deterministic FreightLogic decision -> outcome capture -> opt-in privacy-preserving aggregate cargo-van intelligence. That is post-release scope, not permission to enlarge this release.

## Authority and safety

- Re-read `AGENTS.md`, `.agents/LANES.md`, the canonical completion plan, certification-state document, evidence-provenance contract, operator truth, and normalized-evidence durability contract before editing.
- `app.js` remains serialized/shared; obey `lock/app-js` and full-suite requirements.
- Respect physical lane ownership; do not bypass lane guard.
- Operator corrections/primary evidence outrank AI summaries.
- External IDs are not unique identity by themselves.
- Unified Decision Engine remains sole owner of verdict, grade, economics, and canonical bid range.
- Unknown remains unknown; never coerce missing operational facts to zero.

Controlling sequence: **EVIDENCE -> TEST -> CHALLENGE -> RECONCILE -> CERTIFY -> ADOPT.**
