# Cloudflare Deployment Parity Checklist

Purpose: prove that the **production** Cloudflare app and backup/API Worker serve the exact FreightLogic completion candidate. Green source CI, a successful Cloudflare build, or a source version bump is not enough by itself.

**Target — v24.0.42 / DB16 / Worker v27 (source candidate, 2026-09-25).** **Deploy Worker v27
first** (Deploy Backup Worker, typed `DEPLOY`), then let Cloudflare deploy the app. Expected markers:
`app.js?v=24.0.42`, `sw-bridge.js?v=24.0.42`, `SW_VERSION = '24.0.42'`, cache `freightlogic-24.0.42`,
manifest `FreightLogic v24.0.42`, `modern-shell.js?v=24.0.42`, and `/health` `{"ok":true,"version":"27"}`.

*History:* **Target — v24.0.41 / DB16 / Worker v26 (source candidate, 2026-09-25).** Worker-only generation:
the app is unchanged at 24.0.41, so only the Worker deploys (Deploy Backup Worker, typed `DEPLOY`).
Expected: every app marker below stays `24.0.41`, and `/health` reports `{"ok":true,"version":"26"}`.

*History:* **Target — v24.0.41 / DB16 / Worker v25 (source candidate, 2026-09-25).** **Deploy Worker v25
first** (Deploy Backup Worker, typed `DEPLOY`), then let Cloudflare deploy the app. Expected markers:
`app.js?v=24.0.41`, `sw-bridge.js?v=24.0.41`, `SW_VERSION = '24.0.41'`, cache `freightlogic-24.0.41`,
manifest `FreightLogic v24.0.41`, `modern-shell.js?v=24.0.41`, and `/health`
`{"ok":true,"version":"25"}`. **21** declared runtime assets.

*History:* **Target — v24.0.40 / DB16 / Worker v24 (source candidate, 2026-09-25).** App-only
generation (paste an invite into the installed app): the Worker is unchanged, so **do not redeploy
it**. Expected markers: `app.js?v=24.0.40`, `sw-bridge.js?v=24.0.40`, `SW_VERSION = '24.0.40'`,
cache `freightlogic-24.0.40`, manifest `FreightLogic v24.0.40`, `modern-shell.js?v=24.0.40`, and
`/health` `{"ok":true,"version":"24"}`. **21** declared runtime assets.

*History:* **Observed 2026-09-25 UTC: production serves v24.0.39 / DB16 / Worker v24.** Re-dispatched Live Parity `36099921819` and Production Service Worker `36099923630` PASS on `main` @ `6c99980` (PR #355). The target below was the source candidate and is now what production serves.

**Target — v24.0.39 / DB16 / Worker v24 (source candidate, 2026-09-25).** App-only
generation (Load Intake: Score This Load scores; screenshot errors visible): the Worker is
unchanged, so **do not redeploy it**. Let Cloudflare deploy the app, then **re-dispatch** Verify
Live Parity rather than citing the push-triggered run. Expected markers: `app.js?v=24.0.39`,
`sw-bridge.js?v=24.0.39`, `SW_VERSION = '24.0.39'`, cache `freightlogic-24.0.39`, manifest
`FreightLogic v24.0.39`, `modern-shell.js?v=24.0.39`, and `/health` `{"ok":true,"version":"24"}`.
**21** declared runtime assets.

*History:* **Observed 2026-09-25 UTC: production serves v24.0.38 / DB16 / Worker v24.** Re-dispatched Live Parity `36096515728` and Production Service Worker `36096517168` PASS on `main` @ `a3bdf1f` (runtime identical to `9c3564c`, PR #352). The target below was the source candidate and is now what production serves.

**Target — v24.0.38 / DB16 / Worker v24 (source candidate, 2026-09-25).** App-only
generation (Next Move S3): the Worker is unchanged, so **do not redeploy it**. Let Cloudflare
deploy the app, then **re-dispatch** Verify Live Parity rather than citing the push-triggered run.
Expected markers: `app.js?v=24.0.38`, `sw-bridge.js?v=24.0.38`, `SW_VERSION = '24.0.38'`, cache
`freightlogic-24.0.38`, manifest `FreightLogic v24.0.38`, `modern-shell.js?v=24.0.38`, and
`/health` `{"ok":true,"version":"24"}`. **21** declared runtime assets.

*History:* **Observed 2026-09-25 UTC: production serves v24.0.37 / DB16 / Worker v24.** Re-dispatched Live Parity `36093836038` and Production Service Worker `36093837857` PASS on `main` @ `0af03d4`. The target below was the source candidate and is now what production serves.

**Target — v24.0.37 / DB16 / Worker v24 (source candidate, 2026-09-25).** App-only
generation (Next Move S2): the Worker is unchanged, so **do not redeploy it**. Let Cloudflare
deploy the app, then **re-dispatch** Verify Live Parity rather than citing the push-triggered run.
Expected markers: `app.js?v=24.0.37`, `sw-bridge.js?v=24.0.37`, `SW_VERSION = '24.0.37'`, cache
`freightlogic-24.0.37`, manifest `FreightLogic v24.0.37`, `modern-shell.js?v=24.0.37`, and
`/health` `{"ok":true,"version":"24"}`. **21** declared runtime assets.

*History:* **Observed 2026-09-24 UTC: production serves v24.0.36 / DB16 / Worker v24.** Re-dispatched Live Parity `36045433308` and Production Service Worker `36045436407` PASS on `main` @ `b3d1ec9`. The target below was the source candidate and is now what production serves.

**Target — v24.0.36 / DB16 / Worker v24 (source candidate, 2026-09-24).** App-only
generation (Next Move S1): the Worker is unchanged, so **do not redeploy it**. Let Cloudflare
deploy the app, then **re-dispatch** Verify Live Parity rather than citing the push-triggered run.
Expected markers: `app.js?v=24.0.36`, `sw-bridge.js?v=24.0.36`, `SW_VERSION = '24.0.36'`, cache
`freightlogic-24.0.36`, manifest `FreightLogic v24.0.36`, `modern-shell.js?v=24.0.36`, and
`/health` `{"ok":true,"version":"24"}`. **21** declared runtime assets.

*History:* **Observed 2026-09-24 UTC: production serves v24.0.35 / DB16 / Worker v24.** Re-dispatched Live Parity `35941949948` and Production Service Worker `35941952081` PASS on `main` @ `c58a9f9`. The target below was the source candidate and is now what production serves.

**Target — v24.0.35 / DB16 / Worker v24 (source candidate, 2026-09-24).** App-only
generation: the Worker is unchanged, so **do not redeploy it**. Let Cloudflare deploy the app, then
**re-dispatch** Verify Live Parity rather than citing the push-triggered run. Expected markers:
`app.js?v=24.0.35`, `sw-bridge.js?v=24.0.35`, `SW_VERSION = '24.0.35'`, cache
`freightlogic-24.0.35`, manifest `FreightLogic v24.0.35`, `modern-shell.js?v=24.0.35`, and
`/health` `{"ok":true,"version":"24"}`. **21** declared runtime assets. The withheld set still
covers `admin-console/` and `native-ios/`.

*Superseded, kept as history: **observed 2026-09-23, production served v24.0.34 / DB16 / Worker
v24**. Worker v24 deployed by `35932504325`; re-dispatched Live Parity `35932842955` and
Production Service Worker `35932845279` PASS on `main` @ `8f4585e`; settled authenticated gate
`35936015903` PASS.*

*Superseded below and kept as history: **observed 2026-09-22, production served v24.0.33 / DB16 /
Worker v23**. Live Parity `35776465060` and Production Service Worker `35776467510` PASS on `main`
@ `8caf6a4`; Worker v23 deployed by `35771229876`.*

**Observed 2026-09-22 UTC: production serves v24.0.32 / DB16 / Worker v22.** Live Parity run
`35762451735` PASS on `main` @ `d3c02ca` with the `workerVersion` pin at 22, and Verify
Authenticated Worker run `35762633659` PASS, reporting
`live /extract-image provider path — HTTP 422 via workers-ai / @cf/moondream/moondream3.1-9B-A2B`.
422 is the pass for the synthetic 1x1 PNG: the provider ran and the normalizer fail-closed. The
deployed v21 answered the same call 502, so Issue #252 screenshot intake works live for the first
time. The app generation did **not** move for this Worker-only repair, and must not be bumped for
one. See `AUDIT_REPORT.md` P-08 and CLAUDE.md's Worker v22 section.

**Deploy-gate note:** the deploy run (`35762229263`) uploaded and deployed successfully and then
reported **failure**, because its post-deploy check slept once for 10 seconds and read `/health`
before Cloudflare finished the rollout. That raced failure also skipped the `workflow_run`
authenticated gate, which requires `conclusion == 'success'`. The check now polls for the
expected version instead of sleeping once. A deploy that reports failure is worth re-observing
before re-running: the deploy had already landed.

*Superseded below and kept as history: production served v24.0.31 / DB16 / Worker v21.*
Merged as `ad6a6fb2` (PR #314 — Issue #278 rate basis + the backup-watermark data-loss fix).
Live parity was **re-dispatched after propagation**: run `35690508284`, PASS. Production Service
Worker run `35690173735`, PASS. The two earlier parity attempts failed naming the previous
generation (`Manifest name v24.0.31 — FreightLogic v24.0.30`) because the re-dispatch was fired
about a minute after the merge — the propagation race, not a mismatch.
PR #311 merged as `ea0416713ae716918745cad148f96a8f7664112b` (Issue #278's `DEACTIVATED`
outcome class, plus the long-haul thresholds pinned on both sides). Exact PR-head Tests
`35683496425`, Lanes `35683496430` and CodeQL `35683496439` passed; exact-main Tests
`35683976838` and CodeQL `35683976839` passed on the merge commit. The local exact-head full
suite was **758/0 across 74 specs**, first attempt.

Both live gates were **re-dispatched** on `main` @ `ea041671` rather than cited from the
push-triggered runs: Live Parity `35684405039` and Production Service Worker `35684408029`,
both **success**. The Worker was not redeployed — `/health` stays **v21**, which is what this
generation requires.

The push-triggered pair (`35683976801`, `35683976815`) also passed. Recorded precisely: the ten
documented push races are all about a run FAILING while it observed the previous generation
mid-deploy, and a parity PASS cannot occur unless production already serves the source-derived
generation. The re-dispatch remains the observation of record.

Runtime merge `ca99d50abf18557682f38e641c2b023041088ea6` (PR #306) has exact PR-head
Tests `35678726412` at **748/0 across 73 specs**, with Lanes `35678726404`
and CodeQL `35678726418` passing.

On settled checkpoint `98e447e3dc1ffe5d00e5793ab0725bde4e6a063a`,
Live Parity `35679841528` (job `106594200002`) and Production Service Worker
`35679841496` (job `106594196748`) both returned **PASS** on attempt 1. Logs directly
observed app/SW/manifest 24.0.29, Worker v21, all 22 runtime assets, 20 repository-only
paths withheld, `freightlogic-24.0.29` as the sole generation cache, and the five-tab
driver shell with Today visible after reload. CodeQL `35679841490` (job
`106594197964`) passed. Exact-main Tests `35679841575` (job `106594197228`)
passed **748/0 across 73 specs**.

The runtime-merge push preserved the deployment-propagation race rather than hiding it:
Live Parity `35679161628` and Production Service Worker `35679161632` first observed
the prior v24.0.28 generation while Cloudflare was still settling, then both passed on
attempt 2 with no code change once v24.0.29 was served. Those first attempts are valid
evidence about production at that instant; the settled pass is the release observation.

**Live vision remains UNOBSERVED.** The authenticated synthetic image probe exists, but the
privileged provider invocation has not been observed and a Worker version check cannot close
provider execution, image quality, or physical A13. Admin Console, later #278 policy work,
repository-admin controls and Safari/native Apple work remain separate. The current dated
authority is `docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-21.md`.

## Historical v24.0.28 observation — 2026-09-21

Production v24.0.28 / DB16 / Worker v21 was directly observed before #304 advanced the
runtime. Documentation checkpoint `675e6fb0` passed Live Parity `35661894518`,
Production Service Worker `35661894391`, CodeQL `35661894363`, and exact-main
Tests `35661894446` at **746/0 across 72 specs**. The detailed evidence remains in
`docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-21.md`; it is historical
evidence only now that production serves v24.0.29.

## Historical v24.0.25 observation — 2026-09-20

**PRODUCTION SERVED 24.0.25 / DB16 / Worker v21, and BOTH generations are
OBSERVED.** Observation of record, both `workflow_dispatch` on `main` @
`266d74e` (PR #280; the runtime generation merged as `436d677`, PR #277, the
operator-directed Apple-style driver IA slice):

- live all-asset parity run `35542846195`, job `106163516058`, `VERDICT: PASS` —
  manifest name `FreightLogic v24.0.25`, Worker `/health`
  `{"ok":true,"version":"21"}`, all **22** declared runtime assets loading, none
  served as HTML, and **20** repository-only paths confirmed non-public (Issue
  #228's live half), every one answering with a definite status;
- production service worker run `35542851411`, job `106163528152`,
  `VERDICT: PASS` — precache `freightlogic-24.0.25` carrying all 22 assets, both
  injected scripts fetchable as script (HTTP 200, `text/javascript`), an offline
  subresource miss `504 text/plain`, a drifted `?v=` self-healing, the cached
  shell requesting `?v=24.0.25`, exactly one generation cache, and **after reload
  the driver shell rendering five tabs and a visible Today surface with no
  uncaught errors** — this generation's own IA restructure, observed rather than
  asserted from source.

`266d74e` modifies only `.agents/LANES.md`, so the runtime tree observed is
byte-identical to the v24.0.25 tree. `scripts/verify-release-generation.mjs`
agrees: *"No deployed app bytes changed."*

**Neither of these runs was push-triggered, and that is deliberate.** A parity or
service-worker run that fires on the merge push races the Cloudflare deploy and
has been recorded failing for that reason nine times. Such a failure is real
evidence about the origin at that instant and is **not** evidence about the
release. The converse holds too: a re-dispatch that fails *the same way* is a
real finding, which is what made the v24.0.17 Worker-generation mismatch evidence
rather than noise.

The historical certification record for this observation is
`docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-20.md`.

*The 24.0.24 block this replaced is kept as history below, with the 24.0.22 and
24.0.19 blocks beneath it. Those run IDs are permanent provenance for the exact
trees their gates looked at, and stay correct permanently.*

**PRODUCTION SERVED 24.0.24 / DB16 / Worker v21 — kept as history.** Observation
of record was both `workflow_dispatch` on `main` @ `f75f9cc` (PR #275, the Issue
#268 accessibility completion): live all-asset parity run `35434716935`, job
`105875325854`, `VERDICT: PASS`; production service worker run `35434719454`,
job `105875332085`, `VERDICT: PASS`, 16 checks / 0 failures, precache
`freightlogic-24.0.24`. Its push-triggered parity (`35434651294`) FAILED eleven
seconds after the merge — the ninth recorded occurrence of the race — and was
not the evidence.

*The 24.0.22 block this replaced, and the 24.0.19 block below it, are kept as
history. Those run IDs are permanent provenance for trees a gate actually looked
at.*

*The block below certified **24.0.19** and was the production fact until this
correction. It is kept because the runs it names are permanent provenance for a
tree a gate actually looked at.*

**v24.0.19 WAS DEPLOYED AND OBSERVED, and so was Worker v20.** This was the first
fully-green live parity in the v24.0.x line: every prior run in this release line
failed at least one check, most recently the Worker v19-vs-v20 mismatch.

Observation of record at the time: live parity run `35291475396`, `workflow_dispatch` on `main`
@ `eac5994`, job `105435050613`, **`VERDICT: PASS`** with every check green —
`index.html` referencing `app.js` and `sw-bridge.js` at **24.0.19**, `index.html`
**not** referencing `voice-load.js` (the inverted #230 assertion, observed live),
service worker **24.0.19**, `sw-bridge` importing and the worker precaching
`modern-shell.js` at 24.0.19, manifest name `FreightLogic v24.0.19`, Worker
`/health` returning `{"ok":true,"version":"20"}`, all **22** declared runtime
assets loading with none served as HTML, CSP byte-identity, the unauthenticated
admin boundary still denying, and **20 repository-only paths confirmed non-public
(Issue #228's live half)**.

Worker v20 was deployed by run `35291404482` on the same SHA, with its own
post-deploy checks green: `/health` at the expected version, CORS on the real app
origin, and both unauthenticated boundaries still returning 401.

*Earlier revisions of this block described 24.0.19 (three generations stale, this
correction), before that 24.0.15/24.0.14, and before that
24.0.13/24.0.12 — four and two app generations stale respectively. Corrected
rather than overwritten, because a parity document that keeps a superseded
deployment claim is exactly the drift it exists to catch. The rule that prevents
it is unchanged: a superseding record is due the day a shipped file deploys, not
the day it merges.*

## Runtime state at the 2026-09-22 checkpoint

- App/PWA/SW **24.0.31**, DB **16**, Worker **v21**; source and observed production agree.
- Runtime merge: `ea041671` (PR #311); exact PR-head Tests `35683496425` and exact-main Tests
  `35683976838` both passed. Re-dispatched Live Parity `35684405039` and Production Service
  Worker `35684408029` both **success** on that exact SHA.
- Runtime merge: `ca99d50a` (PR #306); exact PR-head Tests `35678726412`:
  **748 passed / 0 failed across 73 specs**.
- Settled current observation checkpoint: `98e447e3`.
- Live Parity `35679841528`, job `106594200002`: **PASS** — app/SW/manifest
  24.0.29, Worker v21, 22/22 runtime assets, 20 repository-only paths withheld.
- Production Service Worker `35679841496`, job `106594196748`: **PASS** —
  activated/controlled worker, `freightlogic-24.0.29` precache with all 22 assets,
  five tabs + visible Today after reload, exactly one generation cache.
- Exact-main Tests `35679841575`, job `106594197228`: **748/0 across 73 specs**;
  CodeQL `35679841490`, job `106594197964`: **PASS**.
- **HOLD remains** for physical A1-A13 and authenticated live vision-provider /
  real-screenshot evidence. Admin Console live proof, later #278 policy/evidence work,
  repository-admin controls, and Safari/native Apple work remain separate.

Important: `https://freightlogic.pages.dev` is a legacy/stale origin and is not the production app origin.

## 1. Exact app deployment

Record:

- GitHub runtime SHA;
- current repository/tooling SHA used to run the verifier;
- Cloudflare production build/version identifier;
- production app origin;
- production backup/API Worker origin;
- rollback/fix-forward reference.

### Historical source/deploy evidence — v24.0.9 through v24.0.12

**v24.0.11 live parity is OBSERVED, not inferred.** Run `34929870640` (Verify Live
Parity, attempt 2) on `fb408a0a8635d89ee0ed44a471ca11ef032a71a5` reports the Pages
index and its `app.js`, `voice-load.js` and `sw-bridge.js` references at `24.0.11`,
the service worker at `24.0.11`, `sw-bridge` importing `modern-shell.js` `24.0.11`
and the worker precaching it, the manifest name at `24.0.11`, Worker `/health`
returning `{"ok":true,"version":"17"}`, all **23** declared runtime assets loading
from the app origin, and none served as HTML. `VERDICT: PASS`. The production
service-worker gate (`34929870633`) and the full suite (`34929870661`) are green on
the same SHA.

**v24.0.12 live parity is now OBSERVED.** The paragraph that stood here said 24.0.12 had
not been observed live and that its parity run must be re-dispatched after it deployed.
That re-dispatch happened and passed; the paragraph is replaced rather than left standing,
because a checklist asserting "not deployed" about a generation production is serving is
worse than one that says nothing.

Run `34939229143` (Verify Live Parity, `workflow_dispatch` on `main` @
`4f2daf22819feb8d7aeba40324e53ce971f22418`, 2026-09-15T06:56:35Z) reports `sw-bridge`
importing `modern-shell.js` `24.0.12` with the worker precaching it at that generation,
the manifest name `FreightLogic v24.0.12`, the overlay and shell each loading and
exposing their globals, the SW critical shell still carrying `midwest-stack-authority.js`
and `vendor/xlsx.full.min.js`, Worker `/health` returning `{"ok":true,"version":"17"}`,
the admin endpoint rejecting an unauthenticated request with 401, all **23** declared
runtime assets loading from the app origin, and none served as HTML. `VERDICT: PASS`.

The production service-worker gate (`34939417958`, **16 checks / 0 failures**,
`VERDICT: PASS`) confirms it from the browser side on the same SHA: precache
`freightlogic-24.0.12` holding all 23 assets, the cached shell requesting `?v=24.0.12`,
`admin-driver-ui.js` and `midwest-stack-authority.js` injected **and fetchable as
script** (HTTP 200, `text/javascript`), an offline subresource miss answered `504
text/plain` rather than the HTML shell, a drifted `?v=` self-healing to the real file,
and exactly one generation cache surviving. The full suite (`34938834977`) is green on
the same SHA.

**The push-race recurred and is recorded so it is not mistaken for a release defect.**
Both workflows also fired on the push at 06:51Z and both FAILED — `34938834929` and
`34938834924` — about five minutes before the dispatched runs above passed. They
observed the previous generation still being served while Cloudflare finished deploying.
Re-dispatch and record the later run; do not dismiss the earlier one and do not cite
it.

This entry records generations and directly observed run evidence only. It is **not**
a certification: physical iPhone A1-A11 and section C private-history reconciliation
remain open, and neither is reachable from a hosted runner.


For v24.0.9, GitHub's Cloudflare check attached to runtime merge SHA `5446b097fe8791f3d7c79b5a5833a0930ee83cf2` completed successfully as check run `103831029587`, build `d66b1b47-9ca6-4736-994a-ff02fc6f5490`, version `7582ec81-bbc6-40b4-b85b-7b5e34c3ad70`. The earlier checklist draft named a different build/version pair; re-reading the exact SHA's check-runs showed that pair was not the check currently attached to `5446b097...`, so the release record now uses only the directly observable SHA-bound metadata. Subsequent PRs #177 through #180 changed verification tooling/tests/docs only; they did not change shipped runtime files or the app/PWA/cache generation. Build evidence is **not** a substitute for a live origin parity run.

The prior v24.0.8 admin-script defect is repaired in source: `.assetsignore` no longer excludes `admin-driver-ui.js`, and the deploy-asset regression gate derives the complete runtime inventory and asserts that every requested runtime asset exists and is deployable. The current derived source inventory is 23 assets. A full live-green parity run must fetch **every derived runtime asset**, not a curated subset, and must reject an HTML shell returned with HTTP 200 for a JavaScript/CSS/JSON/image request.

PR #177 added a repository-hosted, **manual-only and read-only** GitHub Actions runner named **Verify Live Parity**. It executes the real `scripts/verify-cloudflare-parity.mjs` from a GitHub-hosted runner, uses no secrets, performs no deploy/repository write, and preserves three explicit outcomes:

- `PASS` / exit 0 — live checks were observed and passed;
- `FAILURE` / exit 1 — the origin was observed and one or more parity checks failed;
- `UNOBSERVED` / exit 2 — no HTTP observation could be made because of transport/network unreachability.

HTTP error responses such as 404/500 count as **observed failures**, not UNOBSERVED. A static/source defect also outranks network unreachability and remains FAILURE.

That NOT RUN / UNOBSERVED state is closed and has been since 2026-09-14: the all-asset live sweep has been dispatched and recorded at every generation from 24.0.10 onward, most recently `34939229143` at 24.0.12 above. The standing rule it carried is unchanged and still binding — do not infer PASS from Cloudflare build success, from a version bump, or from the verifier's static-only tests. Only a dispatched run against the production origin closes this.

### Manual dispatch procedure

From the repository UI:

1. Open **Actions**.
2. Select **Verify Live Parity**.
3. Choose **Run workflow** on `main`.
4. Leave both optional origin inputs blank so the verifier uses the production defaults above.
5. Run the workflow.
6. Record the run ID, checked-out SHA, `VERDICT: PASS|FAILURE|UNOBSERVED`, derived runtime-asset count, and any failed checks.

Do not add a push/comment/schedule trigger merely to avoid this explicit release-gate action.

## 2. App / PWA generation

**Read the expected generation from the source rather than from this section.** It stood at
**24.0.9** while production served 24.0.25 — sixteen generations stale — and it still listed
`voice-load.js`, a file **deleted in v24.0.17** by operator decision (Issue #230). An operator
following it would have verified the wrong generation and hunted for an asset whose absence is
the removal working correctly. It is written as a derivation now, for the same reason section 3
below and `scripts/verify-rollback.mjs` stopped pinning theirs: a number transcribed here goes
stale at the next release, and the release that bumps it is precisely when nobody remembers to
edit this file.

| Fact | Derive it from |
|---|---|
| expected app generation | `APP_VERSION` in `app.js` |
| expected service-worker generation | `SW_VERSION` in `service-worker.js` (CG-01 asserts the two are equal) |
| expected precache name | `freightlogic-${SW_VERSION}` |
| the exact asset set and its `?v=` markers | `scripts/lib/deploy-assets.mjs` — the same derived inventory the gate and `tests/unit/deploy-asset-coverage.spec.mjs` both import |

PASS requires production to serve, at that derived generation:

- every asset in the derived runtime inventory, each answering **200** and **not** `text/html`;
- `manifest.json` whose `name` is `FreightLogic v<generation>`;
- `service-worker.js` whose `SW_VERSION` equals `APP_VERSION`;
- current `modern-shell.js` bytes from the named runtime candidate, imported by `sw-bridge.js`
  and precached by the worker at that same generation;
- bundled `vendor/xlsx.full.min.js`;
- the current `styles.css` visual layer, which carries **no version string by design** (CG-11
  asserts its absence — do not add one to "check" it here);
- matching CSP/security headers, byte-identical between `index.html` and `_headers`;
- no failed JavaScript/static request answered with an HTML shell fallback.

**Assets that must NOT be present** are as much a part of parity as the ones that must:

- `voice-load.js` — removed in v24.0.17. A **404 is the correct result**; a 200 means a stale
  deployment or a reintroduced reference. `scripts/verify-cloudflare-parity.mjs` asserts the
  inverted condition, that `index.html` does not reference it at all.
- every repository-only path — the live sweep checks **20** of them and a `200` is the defect
  (Issue #228).

Do not reuse an earlier generation's production observation as exact-generation evidence for the
current candidate. Each observation is provenance for the exact tree its gate looked at, and for
no other.

## 3. Worker live checks

**Read the expected generation from `cloud-backup-worker.js`'s own header rather than from this
heading.** This section stood at **v15** while source reached v21 — six generations stale, in the
one document whose job is catching exactly that. It is written as a derivation now for the same
reason `scripts/verify-rollback.mjs` stopped pinning its candidate SHA: a number transcribed here
goes stale at the next Worker bump, and the release that bumps it is precisely when nobody
remembers to edit this file. `tests/unit/cache-generation.spec.mjs` CG-09 already asserts that the
header, `/health` and the parity gate's `workerVersion` all name the same number, so there is one
source of truth and this is not it.

Do not transcribe the expected generation here. Read the source generation from
`cloud-backup-worker.js`'s header and the deployed generation from `GET /health`; the two agreeing
is the check. The line this replaced read *"Current source generation ... 21. Production serves
20"* — which was stale the moment v21 deployed, in the very section that tells you not to trust a
transcribed number.

PASS requires:

- `GET /health` returns HTTP 200 and JSON whose `version` equals the source header's generation;
- unauthenticated `POST /extract-image` is denied — it sits **inside** the driver-token gate,
  unlike `POST /claim`, because it spends a limited provider allocation;
- requests from `https://freightlogic-v2.fimseitef.workers.dev` receive that exact origin in `Access-Control-Allow-Origin`;
- unauthorized admin requests are denied;
- unauthorized driver/evaluate/extract/backup requests are denied;
- authenticated `/evaluate` preserves canonical available and `UNAVAILABLE` decisions;
- `/extract`, when enabled, returns bounded evidence only;
- authenticated full backup, delta backup, and restore smoke paths succeed without changing the data/authority contract;
- no token or secret is exposed in client-visible output;
- in-place token rotation preserves the existing user identity and backup history.

### Worker evidence, checked 2026-09-21

Worker `/health` reports **v21** in the exact-checkpoint parity log at the top of this file.
The older v15 and v20 observations remain evidence for their own execution dates. The latest
observed authenticated workflow in the dispatch/trigger history is `35291452993`, predating
the new `--vision` verifier. Do not carry its success into a claim of live image extraction.

Dispatch **Verify Authenticated Worker** on current main to exercise the expiring synthetic
identity, authority, vision-provider and backup/claim checks. Read the explicit verdicts.
Provider/model-provenanced 422 on the synthetic blank image is fail-closed invocation evidence,
not OCR-quality evidence. Keep the deployment workflow's manual boundary intact.

## 4. Canonical authority smoke

Use non-sensitive fixtures only.

PASS requires:

- canonical verdict, grade, True RPM/economics, and bid range remain client-owned;
- Midwest overlay remains advisory;
- an incomplete canonical decision remains `UNAVAILABLE` with unknown grade, null True RPM, and no invented bid;
- missing deadhead remains UNKNOWN while explicit `0` remains real zero;
- blank/underspecified market text cannot manufacture favorable geography;
- Gary, Indiana stays the intended U.S. Midwest Tier-1 market;
- 121-inch default cargo boundary remains enforced;
- 54.8-inch wheel-well width and 3,000-pound practical payload limits remain enforced;
- precise True Profit is not asserted without defensible cost/mileage inputs;
- v24.0.9 pickup feasibility remains fail-closed: no planning speed means no invented reachability verdict; unknown deadhead never becomes zero; once an operator planning speed and pickup cutoff are supplied, an unreachable pickup blocks before economics.

## 5. Structural shell parity

Production parity must confirm:

- primary navigation is **Today / Loads / Evaluate / Trips / Money**;
- Loads uses the existing canonical load inbox/state rather than a second queue;
- Evaluate still maps to canonical `#omega`;
- direct `#loads` launch renders correctly;
- More still exposes the secondary tools/settings surfaces;
- offline precache contains the structural adapter and the app launches offline without a blank shell;
- the Trip Planning setting and optional pickup-cutoff field introduced in v24.0.9 are present without changing the default decision when planning speed is unset.

## 6. Lifecycle / evidence durability

With synthetic data:

- manual/email/notification-compatible intake persists normalized evidence before linkage;
- provenance, source times, mileage semantics, and price semantics survive reload;
- external IDs never become destructive internal identity;
- non-carrier prices do not become canonical revenue without allowed evidence;
- UNKNOWN mileage/deadhead never becomes zero;
- lifecycle progression remains evidence-backed;
- full backup + deltas + restore preserve protected records without downgrade/duplication;
- local export/import preserves lifecycle/evidence and excludes credentials/PIN/lockout state;
- the optional `planningAvgMph` setting, when explicitly set, round-trips as a durable setting; absent/cleared remains absent and must not be invented or clamped during restore/import.

## 7. Automated helpers

Source-side:

- `node tests/run-all.mjs`
- `node scripts/verify-cloudflare-parity.mjs --static-only`
- `node scripts/m7-certify.mjs --suite`

Historical repository baseline at the 24.0.12 candidate (not current evidence):

- main SHA `4f2daf22819feb8d7aeba40324e53ce971f22418`;
- run `34938834977` (push on `main`), and `34933327774` on the PR head `aaa3569`;
- **483 passed / 0 failed across 52 spec files**, reproduced locally against real headless Chromium at the same total;
- includes 11 dedicated live-parity-runner assertions and the 14 cache-generation assertions.

Live production, from a network that can reach Cloudflare:

- preferred: **Actions → Verify Live Parity → Run workflow** with blank optional origins;
- equivalent CLI: `node scripts/verify-cloudflare-parity.mjs`.

Derive expected app/SW/Worker versions and the asset inventory from current source.
The former literals (app 24.0.12, Worker 17, 23 assets) described an old checkpoint, not
the current requirement. The top of this file records the latest observation in this revision.

Authenticated authority checks when a valid non-published driver token is available:

- `FL_BACKUP_TOKEN=... node scripts/verify-live-authority.mjs --vision`
- `FL_BACKUP_TOKEN=... node scripts/verify-live-backup.mjs`

Network inability is `UNOBSERVED`, not PASS and not product failure. Any actual HTTP response makes the target observed and therefore eligible for PASS or FAILURE.

## 8. Rollback / fix-forward evidence

Run `node scripts/verify-rollback.mjs` on the exact candidate and retain its output.
The current verifier derives app/Worker generations and the adjacent candidate from source
and git history. The former text saying it was pinned to Worker v14 is superseded.
The 2026-09-21 read-only run verified v24.0.26 / Worker v21 and the fix-forward procedure;
no older SHA was approved as safe. Re-run when the runtime candidate changes.

No older build may be labelled a safe rollback merely because it exists. Known-regression older generations require explicit defect disclosure; the default policy remains fix-forward unless a genuinely safe rollback target is proved.

## 9. Completion rule

Live Cloudflare parity is complete only when the same named final candidate has:

- exact production app/PWA generation parity PASS;
- all derived runtime assets fetched successfully from the production origin, with no HTML-shell masquerade;
- structural-shell parity PASS;
- backup/API Worker `/health` and CORS parity PASS **at the generation
  `cloud-backup-worker.js`'s header names** — not at a number written here, for the reason
  section 3 gives;
- auth boundaries PASS, including unauthenticated `POST /extract-image` denied;
- canonical `/evaluate`/`/extract`/`/extract-image` checks PASS where applicable;
- authenticated backup/delta/restore/rotation smoke PASS;
- truthful rollback/fix-forward evidence recorded.

Only after this live gate, the real private-history reconciliation, six-width visual acceptance, and the physical-iPhone checklist all pass may a later certification-state document clear HOLD.
