# Completion release certification state — v24.0.10 / Worker v17

Date: 2026-09-14
Supersedes: `docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-14.md`
Status: **HOLD — EVERY AUTOMATABLE AND LIVE-ORIGIN GATE IS NOW OBSERVED AND PASSING. TWO GATES REMAIN, BOTH REQUIRING SOMETHING THIS REPOSITORY CANNOT REACH: PHYSICAL-iPHONE EVIDENCE, AND THE PRIVATE M6 HISTORY BUNDLE.**

This document is the certification authority. Every earlier state and addendum document is historical evidence and must not be read as the current candidate.

## Exact candidate

- FreightLogic app / PWA / service-worker generation: **24.0.10**
- IndexedDB schema: **15**
- backup/API Worker: **17**, deployed and live
- Production app origin: `https://freightlogic-v2.fimseitef.workers.dev`
- Production backup/API Worker origin: `https://freightlogic-backup.fimseitef.workers.dev`
- Runtime candidate SHA: **`fb4fe119cced5bc938bd13d3c2aa877ad92cc308`** (see **Candidate SHA** below)

## What changed since the 2026-09-14 addendum

That addendum listed seven blocking items, of which it could close none by observation — the live runner existed but had never been dispatched, the authenticated identity was unavailable, and the rollback verifier was stale. Five of the seven are now closed by actual runs, and a sixth defect was found and fixed along the way.

### 1. Live all-asset parity — **PASS**

`Verify Live Parity` run `34885000070`, `workflow_dispatch` on `main`. All **23** declared runtime assets load from the production origin, none is served as HTML for a static request, and the deployed Worker reports its current generation.

The push-triggered run on the same SHA **failed**, eleven seconds after the merge, because it races the Cloudflare deploy. That FAILURE is real evidence about the origin at that instant and is not evidence about the release. This will recur on every merge: re-dispatch and record the later run. Do not dismiss the first one and do not cite it.

### 2. Production service-worker / offline behaviour — **PASS**

**Observed 2026-09-14**, run `34895654786` on `main` @ `fb4fe119cced5bc938bd13d3c2aa877ad92cc308`, **16 checks, 0 failures**, VERDICT: PASS against the production origin. Notably it observed `admin-driver-ui.js is injected AND fetchable as script — HTTP 200 (text/javascript)`, which is the 2026-09-13 defect confirmed closed in production rather than only in source.

New gate: `scripts/verify-production-sw.mjs`, run by `.github/workflows/verify-production-sw.yml` (read-only, no secrets, manual dispatch plus every push to `main`). It drives a real headless Chromium against production and proves, in order:

- the worker installs and reaches ACTIVATED;
- the page is controlled after one reload;
- `admin-driver-ui.js` and `midwest-stack-authority.js` are injected **and actually fetchable as script** — a tag pointing at a 404 was the 2026-09-13 defect, and a markup check alone could never have seen it;
- all 23 declared assets are in the precache, under `freightlogic-<current generation>`;
- the driver shell renders with no uncaught errors;
- **with the network verifiably down**, a subresource miss returns `504 text/plain` and never the HTML shell, while a drifted `?v=` on a known asset self-heals to the real file;
- the cached shell is a complete current-generation document;
- exactly one generation cache survives, with no stale generation left behind.

It is non-destructive by construction: it never clears caches, never unregisters a worker, and drives a throwaway CI profile. The completion plan's warning about destroying IndexedDB evidence concerns the operator's own device, which this cannot reach.

**It states its own limit rather than implying otherwise.** The offline *navigation* is not observed there: a navigation restarts the service worker outside the network emulation that covered its predecessor. That was established by experiment, not assumed — re-applying the emulation and re-attaching a fresh CDP session were both tried, and neither carries over. The local spec that does prove offline navigation (`sw-subresource-semantics.spec.mjs`) kills its origin outright, which production does not permit. On a real device this is checklist item **A4**.

### 3. Authenticated Worker authority + backup — **PASS**

Run `34884786623`, **21 passed / 0 failed** against the deployed Worker: full backup, delta write, `GET /backup/delta` retention/ordering/gap counters, `GET /list` device scoping, `GET /status`, malformed-token and tokenless denial, and in-place token rotation preserving user identity and backup history while invalidating the old token. Canonical-absence projection holds: an `UNAVAILABLE` decision stays unavailable, with no fabricated `REJECT`, `F`, zero True RPM or `$0` bid.

It seeds an expiring synthetic identity in production KV and cleans it up. No operator data and no real driver credential is involved.

### 4. Six-width visual acceptance — **PASS**

`tests/integration/six-width-layout.spec.mjs`, in the suite on every PR and push: 320/375/390/393/430/440 CSS-px in both theme states, no page-level horizontal overflow across the five surfaces, bottom-nav interactive geometry, and a narrow-width modal under reduced motion. Not a substitute for iOS safe-area, software-keyboard or installed-PWA evidence — those stay in A1-A10.

### 5. Rollback / fix-forward evidence — **PASS**

The staleness that blocked this is gone, and gone structurally. `scripts/verify-rollback.mjs` pinned its candidate SHA, app generation and Worker generation as literals, so at `24.0.10` it reported a clean PASS while describing the superseded `24.0.9` candidate — a green gate for the wrong release. It now derives the candidate from `HEAD`, both generations from the tree, and the previous generation from git history, and needs no per-release edit.

Its verdict cannot name a safe rollback target by any path. Where the immediately previous generation retains every named safety gate, it reports *no regression proven* and says explicitly that this is **not** an approval. Approved policy remains **fix forward**.

### 6. A real data-loss defect was found and fixed — W-01

Not on the original list, because nobody knew it was there. The full suite was **red on `main`** (451 passed, **2 failed**): backup and delta KV keys ended in a millisecond-precision timestamp, and KV keys are unique, so two writes in the same millisecond produced the **same key** — the second silently overwrote the first, the pointer recorded one key where two writes had happened, and one backup or delta was gone, with both requests returning `200`.

Reachable by ordinary use: a full backup followed immediately by a delta lands inside one millisecond on any fast client. CI had been passing the relevant assertions on timing luck.

Fixed at Worker **v17** with a monotonic key clock, deployed by run `34884719806`, and covered by a regression that freezes `Date.now()` so it cannot pass by timing luck again. Recorded as W-01 in `AUDIT_REPORT.md`, CLOSED, **with its residue stated**: any backup or delta already lost to a collision before that deploy is unrecoverable — the losing write was never stored, and a collision leaves one *valid* key rather than a corrupt one, so nothing in the data identifies what is missing.

## Current blocking checklist

- [x] Exact live all-asset production parity — run `34885000070`, PASS.
- [x] Production service-worker / offline behaviour — run `34895654786`, 16/0, PASS.
- [x] Authenticated Worker authority + backup/restore/rotation — run `34884786623`, PASS.
- [x] Six-width visual acceptance — `six-width-layout.spec.mjs`, PASS.
- [x] Rollback / fix-forward evidence — derived verifier, PASS.
- [x] Worker v17 deployed and verified three independent ways — run `34884719806`.
- [x] Full automated suite green on the candidate.
- [ ] **Private operator-history reconciliation.** The recovered August 27 M6 bundle is not in this repository and is not mounted in any session that has run so far.
- [ ] **Physical iPhone certification.** `FIELD_TEST_CHECKLIST.md` A1-A10 against this exact candidate, in Safari and as the installed Home Screen PWA.

## The two remaining gates, and why they are not closable from here

These are not paperwork. Each needs something that does not exist inside an automated environment, and both have a specific failure mode that inventing evidence would hide.

**Private-history reconciliation** requires the five raw M6 files. Preflight evidence says 216 source rows deterministically produce 149 candidate records, but those candidates have never completed the application round trip, the repeated-import idempotence run, or the source-conflict review. The instrument is committed and ready (`scripts/m6-import.mjs`, the adapter, and the reconciliation machinery, all covered by `batch-b-m6-reconciliation.spec.mjs`); only the data is missing. **Do not reconstruct the bundle from summaries** — a reconstruction would test the summary, not the source, which is the one thing this gate exists to catch. The separate 125-row master is likewise unavailable and must not be synthesized.

**Physical iPhone certification** covers exactly what a headless runner cannot: safe-area insets, the software keyboard, background GPS across a real lock/unlock, iOS permission revocation mid-trip, installed-PWA update behaviour, and a genuine Airplane Mode round trip. A1-A10 are finite and written to be run in one sitting. Note that A4's offline navigation is the specific thing gate 2 above declines to claim.

Neither is a reason to hold the other work. Both can be run in parallel with anything else.

## Candidate SHA

The runtime candidate is the `main` commit that carries this document. Record it here when this lands and confirm it against Diagnostics on the device before running A1-A10:

- **Runtime candidate SHA: `fb4fe119cced5bc938bd13d3c2aa877ad92cc308`** — the `main` commit against which live all-asset parity, the production service-worker gate, and the authenticated Worker smokes were all observed. Confirm it against Diagnostics on the device before running A1-A10.
- Later `main` commits that change only documentation or verification tooling do not create a new runtime candidate, because they do not change a shipped file or the cache generation. If a shipped file changes, this section must be updated and the live gates re-observed.

`FIELD_TEST_CHECKLIST.md` deliberately no longer carries its own copy of this SHA. It had gone two generations stale — reading `24.0.9` / Worker `v15` while production served `24.0.10` / `v17` — which would have had a tester confirm the wrong build and record a PASS for a candidate that is not the one being certified.

## Final rule

FreightLogic remains **HOLD**, and the hold now means something narrower than it did this morning. Source completeness, green CI and a successful build were never sufficient; they are still not. But every gate that could be observed from an automated environment has now actually been observed, on the live production origin, at this exact generation — not inferred, not assumed from a build, and not carried forward from an older candidate.

The hold may be cleared only by a later authoritative certification document recording real physical-iPhone evidence and real private-history reconciliation on this same named candidate. Do not mark either PASS by inference. Do not clear Safari website data or delete the installed PWA to force an update: that destroys the local IndexedDB evidence the installed-origin investigation still needs.
