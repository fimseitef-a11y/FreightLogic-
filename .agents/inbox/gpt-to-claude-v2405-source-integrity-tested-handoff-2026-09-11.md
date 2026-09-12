# GPT → Claude: v24.0.5 source-integrity patch is fully tested; foreign-lane landing required

Date: 2026-09-11 CDT / 2026-09-12 UTC
Operator instruction: proceed and complete FreightLogic.

## Why this handoff exists

The exact source defects were reproduced and a bounded patch was built and tested on `agent/gpt/final-source-integrity`, but PR #145 correctly fails the mechanical path-ownership gate because six required release files are Claude-owned. Do **not** bypass the lane guard. Please land this slice from the Claude lane (or explicitly reassign the affected files) and preserve the tested semantics below.

Tested reference PR: #145 `Finalize v24.0.5 source integrity`
Tested source commit containing the actual runtime/test/release changes: `654a77195306179b0a9974b0d3d4c26fdc6bce4c`
Baseline main used: `5dede5c88bf24d387f24243a691f2fc007c42a9b` (v24.0.4 / DB15 / Worker13)
Coordination lock used during proof: `app-js/6d3a9fd1-2c42-4ef4-91d4-f9c3f0a24b11`

## Verified defects and required semantics

1. **Persisted trip deadhead UNKNOWN was being manufactured as numeric zero.**
   - `newTripTemplate`, `sanitizeTrip`, CSV intake, evaluator book-as-trip, and trip wizard write/display paths all had zero-coercion seams.
   - Missing/blank/invalid/negative/out-of-range deadhead must persist as `null`/UNKNOWN.
   - Explicit `0` must remain a real known zero.
   - Positive known deadhead must survive unchanged.
   - Do **not** migrate ambiguous historical stored zeroes to null: provenance cannot be recovered safely.
   - Unknown/unverifiable deadhead trips must be excluded from rate/calibration paths that would otherwise compute all-mile RPM. The tested patch guards score baselines, broker stats, lane stats, broker trip intel, lane-history recording, and lane RPM trend.

2. **Gary, Indiana was absent from canonical geography.**
   - Add canonical U.S. market: `gary` = MIDWEST / anchor / very_strong, Census representative coords lat `41.5955922`, lng `-87.3452279`.
   - Add `gary` to canonical `MW.tier1`.
   - Gary must resolve as `gary/MIDWEST/US/anchor`; Calgary must continue resolving as `calgary/ALBERTA`.

3. Because `app.js` behavior changes, advance the coherent release generation from v24.0.4 to **v24.0.5**, while keeping IndexedDB **15** and Worker **13**.

## Exact proof already obtained

The patch was applied in a clean GitHub-hosted checkout and ran:

- full suite: **371 passed / 0 failed across 40 spec files**;
- `[V2405-01] sanitizeTrip preserves UNKNOWN vs explicit zero deadhead` — PASS;
- `[V2405-02] IDB round-trip never manufactures unknown deadhead as zero` — PASS;
- strengthened Gary canonical/Tier-1 regression — PASS;
- cache-generation/release-marker suite — PASS;
- `node scripts/verify-cloudflare-parity.mjs --static-only` — PASS.

The earlier parity red result was only from accidentally passing unsupported `--static`; the script then attempted live origins. Re-run with its actual `--static-only` flag passed.

## Files in tested patch

SHARED/runtime paths in PR #145:
- `app.js`
- `index.html`
- `manifest.json`
- `service-worker.js`
- `sw-bridge.js`

Claude-owned paths that caused the correct lane failure and therefore need Claude landing:
- `CLAUDE.md`
- `midwest-stack-authority.js`
- `midwest-stack-config.json`
- `scripts/verify-cloudflare-parity.mjs`
- `tests/integration/v2404-fail-closed.spec.mjs`
- `voice-load.js`

The Claude-owned overlay/config/parity/voice changes are generation-marker synchronization; the test file also contains the new regressions. Inspect PR #145 patches rather than re-deriving them.

## Landing instruction

Please take the serialized `app-js` lock, recreate/cherry-pick the tested semantics into a Claude-owned branch, run the complete suite and static-only parity gate again, and merge only green. Do not mark live Cloudflare parity, private operator-history reconciliation, or physical iPhone gates as passed from source tests.

After landing, send GPT the exact merged main SHA so GPT can reconcile the completion/certification docs and PR #140 to the exact final generation.
