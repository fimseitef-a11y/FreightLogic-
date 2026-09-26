# GPT -> Claude Code: FreightLogic completion continuation

Date: 2026-08-27
Target application branch: current `main`
Active Claude draft: PR #108 (`claude/audit-reconcile-lane-mechanics-hteibi`)
Operator instruction: continue completing FreightLogic in the repository without requiring the operator to re-explain project state.

## Read-first authority

Before editing, re-read these current-main files and treat them as authoritative over older AI summaries, stale PR descriptions, or older doctrine snapshots:

1. `AGENTS.md`
2. `.agents/LANES.md`
3. `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`
4. `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-08-27.md`
5. `docs/NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md`
6. `docs/EVIDENCE_PROVENANCE.md`
7. `docs/OPERATOR_TRUTH.md`
8. `docs/OPEN_QUESTIONS.md`

Current main at handoff creation: merge head `7e34fdf24e6a7b42bac603c0abaadf928811998d` or newer. Rebase/reconcile PR #108 onto current `main` before integrating runtime fixes. Do not restore stale roadmap wording from earlier PR bodies.

## Important correction to earlier M5 claims

M5A helper machinery exists, but M5B is NOT production-complete on current main. `intakeOpportunity()` exists and helper-level tests call it through `window.__FL_TESTS`, but production review found no driver-facing manual/email-compatible caller in `app.js`, `voice-load.js`, `admin-driver-ui.js`, `midwest-stack-authority.js`, or `index.html`.

Completion requires a real shipped path that performs:

`production intake surface -> normalizeOpportunity() -> durable normalized evidence persistence -> conservative lifecycle linking`

A transient helper return value is not sufficient.

## Current completion blockers to close in code + real-path regressions

Use `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-08-27.md` as the exact blocker list. In practical implementation order, close all of the following without weakening existing authority tests:

1. **IndexedDB v14 lifecycle migration/indexes**
   - ensure `loadLifecycle` has `updatedAt`, `orderNo`, and `broker` indexes after fresh DB creation and v13->v14 migration;
   - test actual resulting `indexNames`, not only store existence.

2. **Cloud delta-sync lifecycle TDZ**
   - repair `cloudPushBackup()` so an empty delta cannot read `lc` before declaration;
   - add real empty-delta regression.

3. **Local export checksum/integrity coverage**
   - lifecycle and all newly durable normalized evidence must participate in protected export integrity;
   - prove mutation changes checksum and import validates protected data.

4. **Reused-ID lifecycle safety + full timestamp preservation**
   - broker+order alone is not enough when supplied route/time facts conflict;
   - preserve pickup/delivery clock time (not date-only truncation);
   - ambiguous matches fail safe instead of choosing a lifecycle;
   - UI chips/editor lookup must not use order number alone.

5. **Background-link optimistic concurrency**
   - `linkLifecycle()` must carry the revision it read into `expectedRevision` or otherwise compare-and-abort stale writes;
   - add an actual stale background-link race regression.

6. **Worker canonical-absence compatibility**
   - Worker must preserve client-owned `UNAVAILABLE`, grade `?`, `trueRPM=null`, and suppressed/null bid range;
   - do not manufacture `REJECT`, `F`, `$0.00`, or a substitute canonical answer;
   - client-owned confidence/evidence labels may be explained/challenged but not replaced by model output.

7. **M3 confidence/evidence real-path wiring**
   - explicit fuel provenance at the write/apply point: EIA health is not proof the active price came from EIA;
   - NWS successful-zero vs no-observation/failure semantics;
   - persist compact secret-free evidence/confidence snapshot with evaluation history where storage already supports additive JSON;
   - wire real lane/broker samples and recency from the actual evaluator inputs;
   - exclude irrelevant broker domain when no broker was entered;
   - vehicle-fit evidence must reflect actual supplied measurements/profile/defaults, never a hardcoded `checked=true`;
   - confidence remains descriptive-only and never changes authority/grade/bid.

8. **Durable normalized opportunity evidence + real M5B path**
   - persist money, mileage, price semantic, mileage semantic, source type/name, observation/source timestamps, raw evidence reference, confirmation state, field confidence, and operator-confirmed time under `NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md`;
   - do not place `DISPLAYED_TOTAL_MILES` in a field named `loadedMi`;
   - preserve ISO timestamps; do not accept numeric-only normalization that drops valid ISO source timestamps;
   - unknown historical operator confirmation time stays unknown; never default it to `Date.now()`;
   - extend vocabulary to canonical `EVIDENCE_PROVENANCE.md` semantics;
   - prove evidence survives reload, backup/full+delta restore, local export/import, and checksum verification.

9. **PR #108 historical adapter reconciliation**
   - preserve the valid local `importJSON()` lifecycle support;
   - replace 32-bit DJB2 identity with a bounded collision-resistant deterministic digest;
   - keep both long-provenance idempotency and demonstrated same-length collision regressions;
   - do NOT dedupe completed history by order number alone;
   - remove identity laundering via `stableId = orderNo`;
   - later explicit operator correction outranks lower-authority populated values;
   - preserve per-field provenance across merged sources;
   - preserve DRY RUN as a distinct operational-history class rather than dropping it;
   - unknown/unrecognized secondary statuses never auto-promote to awarded/WON;
   - do not guess source `Carrier` -> canonical `broker` semantics;
   - raw operator history/financial source files remain uncommitted.

10. **M6 observation recency provenance**
    - calibration age must use durable source observation time when known;
    - unknown observation age must not receive full freshness weight;
    - lifecycle `updatedAt`/import time/correction time must not refresh old market observations.

11. **Release-generation parity only after runtime stabilizes**
    - current source still advertises app `24.0.1` and Worker v12 despite later milestone code;
    - select final app/PWA/Worker generations only after corrective runtime is green;
    - align `APP_VERSION`, service-worker/cache-busters, manifest/index/bridge/overlay markers, Worker `/health`, and parity verifier together.

## Warp MCP / API semantics to preserve

Official Warp material was rechecked 2026-08-27. Treat the pasted secondary-AI summary only as discovery aid; the following repo semantics are the important part:

- public Warp MCP package: `warp-agent-mcp` v0.18.0, ~31 shipper-side tools;
- hosted MCP endpoint: `https://mcp.wearewarp.com/api/mcp`;
- quote tools include `van_quote`, `box_truck_quote`, `ftl_quote`, `ltl_quote`, `compare_modes`, `batch_quote`, and LTL market options;
- quote operations are publicly/keylessly usable according to Warp docs; booking/history/tracking/account operations require authenticated Warp access;
- public MCP/API surface does **not** expose a carrier available-load feed, bid/counter/tender tools, or "loads matched to my van";
- Warp can still have carrier opportunities in its network; absence from public MCP/API is not proof those opportunities do not exist;
- Warp cargo-van quote money remains `SHIPPER_BOOKABLE_PRICE` evidence, never carrier payout/operator revenue;
- do not assume the operator's existing Warp credentials have every permission until account/key type is actually tested;
- any future carrier-feed integration requires explicit provider authorization and a separate provenance contract before influencing carrier opportunity state.

Do not use Warp shipper quotes as completed-trip revenue, winning carrier rate, or load-board availability.

## Historical operator data

The operator has explicitly said ChatGPT has been given completed/accepted load history extending back to approximately November and wants Claude Code to receive the trips data. However, repository policy already forbids reconstructing authoritative rows from AI memory alone.

Therefore:

- use operator-verified source files/screenshots/exports when loading real M6 data;
- preserve completed/accepted trips separately from live quotes, submitted bids, lost/expired bids, dry runs, board observations, and external shipper quotes;
- preserve source/confidence/provenance and later explicit corrections;
- do not commit raw personal financial/history source files to the public repo;
- report only non-sensitive aggregates/row counts/status reconciliation results in commits/PRs.

## Execution rule

Do not stop after one blocker is fixed. Continue through the completion plan in order until the repository reaches the point where only operator-dependent field/live checks remain. For every `app.js`, storage, service-worker, or core runtime change, obey the lock protocol and run the required full suite. Do not weaken, skip, quarantine, or rewrite valid safety assertions to make CI green.

Before claiming completion release:

- all current-source blockers above are closed with real-path regressions;
- existing Level X+ authority/money-integrity tests remain green;
- normalized evidence survives reload/backup/export/import with semantics intact;
- real M5B production intake exists;
- M6 real import is re-run off-repo with verified source data and conservative reconciliation;
- full automated suite + lane checks are green on exact candidate SHA;
- Cloudflare Pages/Worker live generation, `/health`, auth denial, non-sensitive `/evaluate` and `/extract` smoke checks pass;
- rollback point is recorded;
- physical iPhone Safari/offline/GPS checks are completed by/with the operator before certification is marked final.

If a physical/operator-only check is the last remaining blocker, leave the code release candidate frozen and provide the operator the exact finite checklist. Do not invent a passed field test.

Controlling rule: **EVIDENCE -> TEST -> CHALLENGE -> RECONCILE -> CERTIFY -> ADOPT**.
