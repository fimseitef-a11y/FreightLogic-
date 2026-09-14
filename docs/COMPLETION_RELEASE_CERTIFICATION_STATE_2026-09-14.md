# Completion release certification state — v24.0.10 / Worker v17

Date: 2026-09-14
Evidence cutoff: 2026-09-14T19:09:00Z
Supersedes: `docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-14.md`
Status: **HOLD — exact merged CI, live parity, and synthetic backup checks pass; remaining authority, rotation, private-history, device, and final recovery evidence stays open.**

## Named candidate

- Runtime/source candidate: `d58bfbea3b6f5d0ebc100795d1320c033a1a5bc0`, merged [PR #193](https://github.com/fimseitef-a11y/FreightLogic-/pull/193).
- App / PWA / service worker: **24.0.10**; IndexedDB: **15**; backup/API Worker: **17**.
- App origin: `https://freightlogic-v2.fimseitef.workers.dev`.
- Worker origin: `https://freightlogic-backup.fimseitef.workers.dev`.
- This is the certification snapshot for the named candidate. Any later runtime change requires evidence against its own SHA.

PR #192 delivered the v24.0.10 cache generation and evaluator field-size fixes. PR #193 subsequently integrated Worker v17's same-millisecond key repair and the rollback verifier that derives its candidate and versions. This documentation change implements the separate GPT handoff in `claude-to-gpt-v24010-merge-reconcile-2026-09-14.md` on `agent-coordination`.

The earlier September 14 addendum remains historical. Its v24.0.9 / Worker v15 candidate, unrun live checks, and green 442-test baseline are not current release evidence.

## Observed evidence

These results were read from the workflow metadata and job logs, including their checked-out SHA. They are not copied from a PR summary.

| Check | Result for the named candidate | Evidence |
|---|---|---|
| Full merged-main suite | **457 passed, 0 failed across 49 spec files** | [Tests 34884711942](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34884711942), `node tests/run-all.mjs`, GitHub-hosted Node 22 / Chromium |
| Six-width browser spec | **2 passed, 0 failed**, within that suite | `integration/six-width-layout.spec.mjs`; 320/375/390/393/430/440, five surfaces, both theme states |
| Worker key regression | **3 passed, 0 failed**, including frozen-clock WPR-03 | `unit/worker-pointer-race.spec.mjs`, same suite |
| Rollback-verifier regression | **6 passed, 0 failed** | `unit/rollback-verifier-current.spec.mjs`, same suite |
| Worker deployment | **SUCCESS**, post-deploy health reports version **17** | [Deploy Backup Worker 34884719806](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34884719806), health observed 19:05:33Z |
| Live app/Worker parity | **PASS**, all **23 declared assets** load; no asset returns an HTML fallback; app24.0.10 / Worker17 | [Verify Live Parity 34885000070](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34885000070), observed 19:07:58Z |
| Model-free authority probes | **5 passed, 0 failed, 3 NOT RUN** | [Verify Authenticated Worker 34884786623](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34884786623) |
| Synthetic full/delta backup retrieval | **21 passed, 0 failed, 0 skipped** | Same authenticated run; byte-exact snapshot/delta retrieval, ordering, auth boundaries, synthetic cleanup |

The authenticated run checked out the named candidate and followed the successful Worker deployment. Neither it nor the parity verifier is an installed-iPhone application restore test.

The live verifier observes release markers, declared-asset delivery, content-type/fallback behavior, and its source/security checks. It does **not** compute a source-versus-production cryptographic hash for every asset. An all-green run must not be described as a blanket byte-for-byte comparison of all 23 assets.

### Failures retained in the record

The immediate post-merge parity run [34884711957](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34884711957) failed before the successful post-deploy observation above. The later manual run is the current PASS evidence; the earlier failure is not deleted.

The preceding candidate `10430bffc0da0648930f0cc940cf3d56983275ef` had **452 passed / 1 failed** in [34874397656](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34874397656): `cloud-backup-paused.spec.mjs` CBP-03. WPR-01/02 passed in that particular run. The new exact-candidate 457/0 run supersedes its baseline result; this record does not assert that the Worker key patch diagnosed or repaired CBP-03.

## Scope of the passing checks

The five live authority passes cover unauthenticated denial, UNAVAILABLE projection, `factsComplete:false`, `economics.available:false`, and refusal to invent a missing bid range. The run explicitly did not execute:

- paid projection of a complete canonical decision;
- paid projection of a real REJECT/F decision;
- paid `/extract` field extraction.

The 21 backup passes cover synthetic snapshot and delta storage/retrieval, chronological order, counters, device-scoped listing, denied unauthorized access, and cleanup. They do not certify in-place token rotation or restoration through the installed app UI.

The six-width spec passes its existing desktop-Chromium geometry assertions. It uses the default `launchApp()` context, not `isMobile: true, hasTouch: true`. Claude's handoff notes about coarse-pointer coverage, clipped overflow, and expanded evaluator fields remain open follow-ups. The observed **browser spec PASS** is not a claim that all mobile acceptance or physical-iPhone A1–A10 checks passed.

## Remaining evidence

- [ ] Complete canonical decision/REJECT live projection checks required by B3; record optional paid extraction separately where applicable. Successful vision/provider expansion remains non-blocking under the canonical plan.
- [ ] Observe in-place token rotation preserving user identity and backup history while invalidating the old token.
- [ ] Perform the actual private M6 import/reload/export/re-import, idempotence, and conflict review.
- [ ] Close the existing six-width coverage follow-ups with verified controls before claiming complete mobile acceptance.
- [ ] Observe physical-iPhone Safari / Home Screen PWA A1–A10, including non-destructive update, offline launch, and app-level restoration.
- [ ] Preserve standalone B5 output naming the final candidate and recovery procedure. PR #193 repairs the tooling and its tests pass; this documentation pass did not execute the standalone verifier.

Earlier preflight evidence records a privately recovered five-file bundle with **216 source rows → 149 candidates**. No actual private source files were accessed or reconciled in this documentation pass. The distinct 125-row master remains unverified; neither dataset may be reconstructed from summaries. Public evidence contains only non-sensitive results.

Recovery policy remains **FIX FORWARD**. A passing verifier does not approve any older app/Worker release as a safe rollback target. Issue #119 stays open. A later certification record may clear HOLD only after the existing required gates are actually observed on one named final candidate.
