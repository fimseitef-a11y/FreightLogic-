# FreightLogic Completion Release Plan — 2026-08-25

Status: **active finite completion plan and the only roadmap file on `main`.**

Current status update: **2026-09-14, after PR #193.** Named candidate `d58bfbea3b6f5d0ebc100795d1320c033a1a5bc0` is **FreightLogic v24.0.10 / IndexedDB v15 / Worker v17**. Exact merged-main Tests [34884711942](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34884711942) passed **457/0 across 49 spec files**. Worker deployment [34884719806](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34884719806) succeeded; live parity [34885000070](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34885000070) passed for app24.0.10 / Worker17 and all 23 declared runtime assets. Authenticated run [34884786623](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34884786623) recorded **5 authority passes / 3 NOT RUN** and **21 synthetic backup passes / 0 failures**. Three paid-model probes, token rotation, real private-history reconciliation, complete mobile/device acceptance, and standalone final B5 evidence remain unverified by those runs. Formal certification remains **HOLD**.

Current certification authority: `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-14.md`. The earlier September 14 v24.0.9 addendum is historical and is explicitly superseded.

Vision ingestion and provider-adapter expansion remain approved but non-blocking. Do not enlarge the completion definition to chase new providers, booking, or model features.

## Roadmap discipline

1. This file is the single active roadmap; GitHub Issue #119 is the execution/certification tracker, not a second roadmap.
2. Operator corrections and primary evidence outrank summaries or inference.
3. UNKNOWN is not zero. Loaded, deadhead, displayed-total, map-estimated, and reposition mileage remain distinct facts.
4. Price semantics remain explicit; shipper/bookable, bid, target, benchmark, carrier payout, and settled amount are not interchangeable.
5. The Unified Decision Engine is the sole client authority for verdict, grade, economics, and canonical bid range. Evidence, overlays, providers, and AI may explain or supply bounded evidence but may not become a competing decision engine.
6. Green tests never overrule a newly proved correctness defect; a proved invariant violation is repaired inside existing scope rather than treated as scope expansion.
7. Provider-account access is not API/partner authorization.
8. Raw private operator financial/history source files remain outside the public repository unless explicitly authorized.
9. Successful vision-model extraction, provider approval, provider booking, and provider-adapter expansion are not required to freeze this completion release.
10. Live deployment evidence outranks stale deployment assumptions in docs/scripts. A dead hostname, missing runtime asset, or stale Worker must be corrected rather than rationalized once a reachable production probe proves the mismatch.
11. A successful Cloudflare build/deploy is deployment evidence, not byte/content parity. Exact live-origin verification remains a separate gate.
12. UNOBSERVED is not FAILURE and is not PASS. A live verifier may return UNOBSERVED only when no HTTP observation is possible; an actual 4xx/5xx response is observed and must be judged as pass/failure evidence.

## Gate 0 — Operator truth and evidence provenance

Status: **COMPLETE.**

Durable operator-truth, evidence-provenance, and open-question contracts exist. External IDs are not destructive identity; source mileage/price/status semantics remain typed; uncertain facts remain unresolved instead of promoted by inference.

A Canada-rate authority conflict is intentionally retained in `docs/OPEN_QUESTIONS.md`: materially different cross-border numbers exist with different provenance, and no runtime protective floor may be changed by inference until explicit operator correction or stronger primary evidence resolves whether each figure is a floor, target, or market observation.

## Milestone 1 — Doctrine and money integrity

Status: **IMPLEMENTED; EXACT-CANDIDATE REGRESSIONS GREEN.**

The current invariant set includes:

- Level X+ grade bands and ordinary/DZ floors;
- Cincinnati, Toledo, and the Chicago/Gary belt as intended Tier-1 geography;
- canonical Gary, Indiana mapping that cannot be confused with Calgary;
- blank/underspecified markets fail closed;
- explicit deadhead `0` remains a known zero while missing/invalid deadhead remains UNKNOWN/null through parser, evaluator, persistence, and history;
- default usable cargo length is 121 inches unless a provenance-bearing operator override exists;
- operator-measured 54.8-inch wheel-well and 3,000-pound practical payload boundaries are enforced by regression coverage;
- True Profit/precise economics are unavailable when required cost or mileage denominators are not defensible;
- advisory Midwest evidence cannot own canonical verdict/grade/bid authority;
- approved MPG fallback remains subordinate to explicit operator settings;
- v24.0.9 pickup feasibility runs before economics only when the operator supplies enough facts: no default planning speed is invented, unknown deadhead never becomes zero, an unreachable/passed cutoff blocks, and a reachable narrow window is advisory only.

## Milestone 2 — Expense/fuel concurrency integrity

Status: **IMPLEMENTED; GREEN.**

Optimistic concurrency protects trip, expense, and fuel edits; stale writes fail rather than silently overwriting newer data. Same-millisecond revision behavior is regression-tested.

## Milestone 3 — Confidence + Evidence

Status: **IMPLEMENTED; GREEN.**

Confidence is categorical and descriptive, source-aware, and cannot relax floors or replace canonical decisions. Successful zero observations remain distinct from failed/unobserved evidence. Persisted snapshots are secret-free and backward-compatible.

## Milestone 4 — Load Lifecycle

Status: **IMPLEMENTED; GREEN.**

Opportunity, execution, and settlement remain separate dimensions. `EXPIRED`, `LOST`, `CANCELLED`, `FELL_THROUGH`, `DELIVERED`, and `PAID` are not collapsed. Stable lifecycle identity does not depend on reused external IDs. Backup/delta/restore/export/import and revision-conflict semantics are covered.

## Milestone 5 — Freight-source ingestion foundation

Status: **5A + 5B IMPLEMENTED; 5C + 5D NON-BLOCKING.**

Approved sequence remains:

**normalized contract -> manual/email-compatible intake -> vision -> provider adapters**

The shipped foundation preserves provenance, price/mileage semantics, UNKNOWN values, conservative lifecycle state, and provider-independent durable evidence. A shipper/bookable price, bid, target, or benchmark cannot silently become canonical carrier revenue. Future vision/provider integrations must enter through this contract.

## Milestone 6 — Historical import + Personal Intelligence calibration

Status: **MACHINERY IMPLEMENTED AND SYNTHETIC REGRESSIONS GREEN; PRIVATE SOURCE BUNDLE RECOVERED; REAL APPLICATION ROUND TRIP / IDEMPOTENCE / CONFLICT REVIEW STILL OPEN.**

Implemented rules include idempotent/collision-resistant import, conservative linking, per-field provenance, source-timestamp recency, no broker guessing, distinct status classes, DZ exclusion from normal-market calibration, `WON / (WON + LOST)` denominators, and exclusion of unknown RPM/deadhead rather than coercion to zero.

The original August 27 five-file M6 bundle was recovered privately in an earlier session. Existing preflight evidence reports **216 source rows -> 149 deterministic candidate records** under the unchanged adapter. Those candidates still must pass the actual FreightLogic import -> reload -> export/re-import path, repeated-import/idempotence checks, and source-conflict review before this milestone can be certified on real data.

The private bundle was not accessed or reconciled in this documentation pass. Earlier recovery/preflight evidence is preserved, but no actual application round-trip result is present in the reviewed certification evidence. Keep this gate NOT RUN until the original private source files complete the required path; do not reconstruct rows from summaries.

The separate **125-row master** referenced by an older handoff remains unavailable. Do not reconstruct it from summaries, do not invent missing rows, and do not treat the recovered 216-row bundle as proof that the distinct 125-row master has been found.

## Milestone 7 — Completion release certification

Status: **EXACT MERGED CI, LIVE PARITY, AND SYNTHETIC BACKUP CHECKS PASS; REMAINING AUTHORITY / ROTATION / PRIVATE DATA / MOBILE / IPHONE / FINAL RECOVERY EVIDENCE OPEN.**

### Exact observed evidence

All current rows below name `d58bfbea3b6f5d0ebc100795d1320c033a1a5bc0`:

- Tests **34884711942**: **457 passed / 0 failed across 49 spec files**.
- Six-width browser spec: **2/0**; Worker key regression: **3/0**, including frozen-clock WPR-03; rollback-verifier regressions: **6/0**.
- Deploy Backup Worker **34884719806**: SUCCESS, post-deploy health version **17**.
- Verify Live Parity **34885000070**: **PASS**, app24.0.10 / Worker17, all **23 declared assets** fetched, no static asset masked by an HTML shell.
- Verify Authenticated Worker **34884786623**: **5 authority passes, 0 failures, 3 NOT RUN**; **21 synthetic backup passes, 0 failures, 0 skipped**.

The three unrun authority probes are paid complete-decision projection, paid REJECT/F projection, and paid extraction. The backup helper verifies snapshot/delta retrieval and ordering, not in-place token rotation or restore through the installed app UI.

The existing six-width spec passes in desktop Chromium at 320/375/390/393/430/440, with both themes and five surfaces. Claude's recorded coarse-pointer, clipped-overflow, and expanded-field coverage follow-ups remain open. Its two passing tests must not be represented as full mobile acceptance or physical-iPhone certification.

The parity verifier checks markers, asset delivery, content type/fallback behavior, and source/security invariants. It does not hash-compare every live asset against the repository. An installed service worker's update/offline behavior still needs direct observation.

### Source changes and prior observations

PR #192 supplies the v24.0.10 cache generation and evaluator field-size repair. PR #193 supplies Worker v17's same-millisecond key repair, a rollback verifier that derives its candidate/generations, and matching regressions. They are merged; no parallel implementation is required for those handoffs.

The older `10430bf` test run **34874397656** was **452/1**, with CBP-03 failing. The new exact-candidate 457/0 baseline supersedes that result without claiming a diagnosis of CBP-03. The immediate v17 push parity run **34884711957** also failed before the successful post-deploy observation. These historical results remain linked in the current certification state.

### Blocking evidence still required

1. **Service-worker / offline production behavior** — observe the named candidate's normal installed-PWA update, launch, persistence and offline navigation without destructive clearing.
2. **Remaining live authority / rotation / app restore checks** — complete the applicable B3/B4 probes, preserve explicit paid-probe NOT RUN states until observed, and prove in-place token rotation and installed-app restoration.
3. **Private operator-history reconciliation** — original M6 bundle through actual import/reload/export/re-import, idempotence and source-conflict review; never fabricate the separate unavailable 125-row master.
4. **Complete mobile acceptance** — close the existing six-width coverage follow-ups; retain the observed desktop browser spec PASS as bounded evidence.
5. **Physical iPhone certification** — A1–A10 and applicable B checks against the same live candidate, including v24.0.9 pickup behavior retained in v24.0.10.
6. **Final rollback/fix-forward evidence** — the derived verifier is integrated and regression-tested; preserve its standalone output for the final candidate and the recovery procedure. No older release is approved as a safe rollback.

Do not mark an unrun private/device/paid-model/rotation check PASS from an overall successful workflow. Do not clear Safari website data or delete the installed PWA to force an update.

## Completion definition

The named release is complete when one named source/runtime candidate has:

- one canonical decision authority and correct doctrine/economics/UNKNOWN semantics;
- durable lifecycle and normalized evidence with provenance;
- production manual/email-compatible intake;
- historical import/calibration machinery plus real private-bundle reconciliation proof;
- deterministic green automated suite and repository governance;
- backup/restore/import/export integrity with secret exclusion;
- exact live production app/all-asset parity and controlled service-worker/offline behavior;
- live Worker-v17 health/CORS plus the applicable authenticated authority/backup/rotation checks;
- six-width visual acceptance;
- finite physical-iPhone field checks;
- truthful release and rollback/fix-forward SHAs/procedure recorded in a superseding certification-state document.

## Execution order from here

1. Retain the verified exact-candidate CI, app/Worker parity, and synthetic backup results in the current certification record. Re-observe affected gates if runtime changes.
2. Finish the applicable live authority/rotation and app-level restore checks using a dedicated non-published test identity.
3. Run the original private M6 bundle through the real application reconciliation path; publish only non-sensitive outcomes.
4. Close the existing mobile-layout coverage follow-ups and perform physical-iPhone A1–A10 on the same candidate.
5. Preserve standalone output from the repaired read-only rollback verifier, naming the final SHA and FIX FORWARD procedure.
6. If a gate fails, repair the cause in its owning lane and repeat the affected exact-candidate checks.
7. Clear HOLD only in a superseding certification record after all existing required evidence passes; then close Issue #119.

Do not expand this finite release into new providers, booking, model features, or branding.

