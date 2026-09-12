# Cloudflare Deployment Parity Checklist

Purpose: prove that the **production** Cloudflare deployment serves the exact FreightLogic completion candidate. A preview deployment or green repository CI is useful evidence, but neither is production parity.

Current source/runtime candidate:

- source/tooling evidence head: `556f5b0141cf658ba76a8ed32105e5bf9258bb20`;
- app / PWA / service worker generation: **24.0.5**;
- IndexedDB schema: **15**;
- Worker generation: **13**;
- certification authority: `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-11.md`;
- certification status: **HOLD — live production and physical/private evidence remain.**

The automated source gate is green at **372 passed / 0 failed across 40 spec files**, with lane/path/lock enforcement green. This checklist is therefore about live deployment evidence, not another source-development milestone.

## 1. Establish the exact deployment

Record before testing:

- GitHub `main` SHA deployed to production;
- production Pages/app origin;
- production Worker origin;
- deployment timestamp/identifier where available;
- rollback SHA chosen for this candidate.

Do not treat a branch/commit preview URL as production. If production cannot be reached from the verification environment, record the gate as `UNOBSERVED`/`NOT RUN`, not PASS.

## 2. Pages / PWA generation

Production must serve the v24.0.5 generation consistently:

- `app.js?v=24.0.5`;
- `voice-load.js?v=24.0.5`;
- `sw-bridge.js?v=24.0.5`;
- `midwest-stack-authority.js?v=24.0.5`;
- `manifest.json?v=24.0.5` with matching visible version/name metadata;
- `service-worker.js` declaring `SW_VERSION = '24.0.5'`;
- bundled `vendor/xlsx.full.min.js` available with no CDN fallback;
- icons/static assets available;
- no failed JavaScript/static request answered with the HTML app shell;
- old app-shell caches retired after normal worker activation/update;
- offline reopen works after an online install/load.

Security checks:

- production `_headers` policy is present;
- `index.html` CSP meta and deployed CSP header are consistent with the source contract;
- no unexpected cross-origin API response is cached by the service worker.

## 3. Canonical decision boundary

Use non-sensitive fixtures.

Pass requires:

- canonical verdict, grade, True RPM/economics, and bid range originate from the client-owned Unified Decision Engine;
- the Midwest overlay remains advisory only;
- a complete canonical decision projects through Worker `/evaluate` without a competing recalculation;
- an incomplete/`UNAVAILABLE` canonical decision stays unavailable: no fabricated `REJECT`, `F`, numeric zero True RPM, or `$0` bid;
- missing deadhead remains UNKNOWN while explicit `0` remains a known zero;
- blank/underspecified market text does not fabricate a favorable market/corridor;
- Gary, Indiana resolves as the intended U.S. Midwest Tier-1 market, not Calgary;
- default cargo-fit behavior uses the 121-inch usable-length boundary unless an explicit provenance-bearing override exists;
- precise True Profit is not asserted without defensible cost/mileage inputs.

## 4. Worker v13 live checks

Expected Worker source generation: **13**.

Observe:

- `GET /health` returns healthy status and version `13`;
- admin routes deny requests without the admin credential;
- driver/evaluate/extract/backup routes enforce their required auth boundary;
- authenticated `/evaluate` preserves canonical available and unavailable decisions;
- `/extract`, when deployed/enabled, returns bounded evidence only and does not invent verdict/bid/lifecycle state;
- backup/full-delta/restore smoke paths work with the expected authenticated user/device envelope;
- `OPTIONS`/CORS behavior matches the configured app origin;
- no token/secret is exposed in client-visible output.

## 5. Lifecycle / evidence durability

With synthetic records only, verify the deployed app preserves the already-tested source contract:

- manual/email-compatible opportunity intake persists normalized evidence before linkage;
- provenance, source timestamps, mileage semantics, and price semantics survive reload;
- external IDs do not become internal identity;
- non-carrier prices do not become canonical revenue without allowed semantics/operator confirmation;
- UNKNOWN mileage/deadhead does not become zero;
- lifecycle state remains conservative unless evidence supports progression;
- full backup + delta + restore and local export/import preserve lifecycle/evidence without duplication or downgrade;
- produced portability export excludes tokens, PIN material, and device-local lockout state.

## 6. Automated helpers

Against the exact candidate source:

- `node tests/run-all.mjs` — must be green;
- `node scripts/verify-cloudflare-parity.mjs --static-only` — local/static parity only;
- `node scripts/m7-certify.mjs --suite` — automated preflight/full-suite evidence; while the canonical state is HOLD it must report NOT CERTIFIABLE rather than pretending live/device gates passed;
- `node scripts/verify-cloudflare-parity.mjs` — live Pages/Worker checks from an environment that can reach the deployed origins;
- `FL_BACKUP_TOKEN=... node scripts/verify-live-authority.mjs` — free live authority checks where supported; add `--paid` only when explicitly appropriate for quota-spending extract checks.

A network/proxy inability to reach production is **UNOBSERVED**, not product failure and not PASS.

## 7. Production parity result

Record each item as `PASS`, `FAIL`, or `NOT RUN/UNOBSERVED` with the exact production SHA and evidence.

The live gate is complete only when:

- production is tied to the exact intended `main` candidate;
- all app/PWA/service-worker markers are v24.0.5;
- Worker health is version 13;
- security/auth boundaries pass;
- canonical available/unavailable authority smokes pass;
- backup/delta/restore and relevant extraction smokes pass;
- the result is recorded against the same candidate used for the physical iPhone checklist.

Only after this live gate, the private-history reconciliation, and the blocking iPhone checks all pass may a new certification-state record supersede the 2026-09-11 HOLD.