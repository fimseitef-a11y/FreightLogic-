# FreightLogic Completion Release — Certification State

Date: 2026-09-03
Merged source head reviewed: `a1f4775a24fb1a912ebe9d061dd002efd4f1144e`
Merged identity: FreightLogic v24.0.3 / DB v15 / Worker v13
Supersedes: `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-02.md`
Status: **HOLD — v24.0.3 IS NOT THE FINAL CANDIDATE; PROOF-BACKED CORE CORRECTIONS + LIVE/PHYSICAL CERTIFICATION REMAIN**

This is the current certification-state record. It preserves the 2026-09-02 iPhone evidence but updates the repository state after PR #139 and the subsequent exact-current-source reconciliation.

## What v24.0.3 proved

PR #139 merged the release-generation/cache-identity advance after the v24.0.2 update-handshake repair. The v24.0.3 freeze moved the governed app/PWA/service-worker asset identity so a previously installed v24.0.2 shell has a new worker/cache/query-string generation to fetch.

The v24.0.3 core freeze commit records:

- **350 passed / 0 failed across 38 spec files** on the full suite;
- static Cloudflare parity PASS for app/PWA/service-worker v24.0.3, DB v15, Worker v13;
- no DB or Worker generation change.

Those results are automated source evidence only. They are not certification.

## Why v24.0.3 cannot be certified

The read-only reconciliation merged with PR #139 proved behavioral defects that were not part of the release-generation-only v24.0.3 change. Because the later source changes on main were presentation/version metadata rather than behavioral repairs, those findings remain applicable to the merged v24.0.3 runtime.

A v24.0.4 core correction slice is therefore required before a new exact candidate can be selected. The protected core lane is actively working that slice under the repository lock protocol. Required outcomes include:

1. blank/underspecified North-American market lookup must fail closed instead of fabricating a favorable Canadian/other market;
2. every production intake, especially Quick Evaluate, must preserve missing deadhead as UNKNOWN and distinguish it from an explicit numeric `0`;
3. the Midwest overlay must remain advisory/evidence-only and may not emit a competing canonical grade/verdict/bid authority;
4. service-worker static-subresource failures must never return the HTML app shell for JavaScript/assets and same-origin `.js` caching must be bounded/query-safe;
5. portability/export paths must exclude secrets/device-local lock state from the actual produced payload and checksum input, with SHA-256 described as corruption/integrity detection rather than authenticated tamper proof;
6. True Profit must remain unavailable/estimated when a defensible operating-cost-per-mile denominator is unavailable;
7. vehicle-fit behavior must honor the operator-confirmed **121-inch usable cargo length** unless an explicit operator override with provenance exists.

Two additional reconciliation items are now routed as proof obligations to the core lane:

- **Gary, Indiana doctrine parity:** the active Level X+ authority keeps the Chicago/Gary belt in Tier 1. Gary must be added to the app's canonical/mirror geography rather than removed from the overlay. U.S. Census representative coordinates supplied to the core lane are `41.5955922, -87.3452279`.
- **trip `emptyMiles` persistence:** current `sanitizeTrip()` numeric coercion must be proven safe-by-construction or remediated if any production/import/restore path can turn unknown deadhead into stored `0`. Historical calibration/True RPM may not consume a fabricated zero as verified deadhead.

Until these are merged with regressions and the governed release identity advances atomically, v24.0.3 is an intermediate merged generation, not the completion candidate.

## Prior iPhone evidence still controls the physical gate

The 2026-09-02 operator screenshots showed the installed Home Screen PWA executing **v23.7.0**, not the then-current v24.0.2 generation. That A1 observation remains a real failure/evidence point. v24.0.3's new cache identity addresses one separate stale-generation hazard but does not prove which production origin the installed iPhone is using or that the device has received current assets.

Do **not** use PWA deletion or Safari website-data clearing as the primary remedy because those actions can erase local IndexedDB evidence. Do not add real operator trips merely to test a candidate. Record Diagnostics/install identity first and use the safe normal update path only against the corrected exact candidate.

## CI gate discovered during this reconciliation

A GPT-owned one-line lane-map PR (#140) passed the dedicated Lanes workflow but the full Tests workflow failed twice before any spec executed with `tests/lib/harness.mjs: Error: server did not start`.

Current harness source launches a floating `npx http-server` while CI installs only pinned Playwright/Chromium and gives the server 10 seconds to appear. Two cold GitHub-hosted runners timed out with an orphan `npm exec http-s` process. This is a test-infrastructure reproducibility defect, not evidence that the one-line lane-map change broke runtime behavior. It has been routed to the Claude-owned test/tooling lane; red required CI must not be bypassed merely because the changed file is non-runtime.

## Remaining certification gates after the corrected candidate is merged

Automated/source gate on the **exact final SHA**:

- full suite green with the new regressions and negative controls;
- lane/path/lock CI green and deterministic;
- governed app/PWA/service-worker generation markers atomic and `scripts/verify-cloudflare-parity.mjs --static-only` green;
- Worker build green;
- no open proof-backed source blocker in Issue #119 or this certification state.

Live deployment gate on the same exact SHA:

- production Pages origin serves that exact app/PWA generation;
- Worker `/health` reports Worker `13` unless the final source intentionally changes it;
- unauthorized admin/driver requests are denied;
- non-sensitive `/evaluate`, `/extract`, backup/delta/restore smoke tests preserve authority and data semantics;
- live assets match the frozen source generation rather than a stale preview/cache.

Physical iPhone gate on the same exact SHA:

- A1 install/update/launch path reaches the corrected generation without destructive data clearing;
- Quick Evaluate and full Evaluate preserve blank deadhead as UNKNOWN and explicit `0` as known zero;
- production manual/email-compatible intake survives reload with provenance/semantics intact;
- offline close/reopen, local export/import, GPS/background/permission-loss, and stale-edit conflict checks pass per `FIELD_TEST_CHECKLIST.md`.

## Certification rule

Issue #119 stays open and the release stays **HOLD** until a corrected generation is merged, its exact automated gate is green, production parity is observed, and the finite physical-iPhone checks pass. Only then may a later certification-state record explicitly supersede this HOLD and freeze the named completion release.

The controlling rule remains: **EVIDENCE -> TEST -> CHALLENGE -> RECONCILE -> CERTIFY -> ADOPT**.
