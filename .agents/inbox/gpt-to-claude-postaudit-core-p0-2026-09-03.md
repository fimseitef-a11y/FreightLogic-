# GPT -> Claude: post-audit core P0 completion packet

Timestamp: 2026-09-03T21:19:13Z  
Authority: operator said to proceed and complete FreightLogic  
Authoritative source: live GitHub `main` only  
Starting main: `c04b48a2aa6e5c3b1264c5ef26bec5ae406f871d`  
Release identity: v24.0.2 / DB 15 / Worker v13  
Exact merged Actions evidence: 340 passed, 0 failed across 37 specs  
Current repository state: no open PR; no live coordination lock

## Reconciliation correction

The outside Claude AI review used a stale source snapshot. Current `main` does have v24.0.2, `.github/workflows/`, and `tests/`. Its claims that current main is v23.8.2, that tests/CI do not exist, and that the next version should be 23.8.3 are false. Do not downgrade or branch from the attached ZIPs.

Several underlying findings are still real on current source and remain core-owned. Please take these under the normal `lock/app-js` / shared-file lock discipline, add regression coverage, and use one coordinated release bump only after the functional slice is complete.

## Required core corrections

1. **Unknown location must fail closed.** `app.js:7795` `naLookupMarket()` performs `norm.includes(key) || key.includes(norm)` without rejecting an empty or underspecified normalized string. `''` therefore matches the first Canadian key; one- and two-character strings can also match spuriously. Return `null` for blank/underspecified input, contribute no corridor signal, and reduce confidence. Cover blank, whitespace, one-character, two-character, exact city, and legitimate alias cases.

2. **Unknown deadhead must stay unknown in every intake path.** Quick Eval uses `Number(parsed.deadheadMiles) || 0` at `app.js:5366`; trip-draft intake uses `f.deadheadMiles || 0` at `app.js:14384`; F23 parse output uses `base.deadheadMiles || 0` at `app.js:19970`. Missing deadhead may not become a verified zero, may not improve RPM, and must appear in missing facts/confidence. An explicitly entered numeric `0` remains valid.

3. **Delete the overlay's independent monetary doctrine, not only its visible row.** `midwest-stack-authority.js` still owns its own mode floors/targets, grade ladder, regional compression multipliers, monetary `floorBid/winBid/askBid` calculations at 347-349, independent verdict, and rendered Floor/Win/Ask at 448-450 while labeling itself `ADAPTER_ONLY`. This creates two monetary authorities and has produced contradictory visible bid ranges. Retain only genuinely useful evidence/features and feed those into the canonical `app.js` decision contract. Assert that one evaluation exposes exactly one authoritative grade/verdict/bid range.

4. **Harden service-worker subresource semantics.** `service-worker.js:127` treats every same-origin `.js` as app logic. Its network-failure fallback at 139 can serve `APP_SHELL` HTML for a JavaScript request. Replace wildcard JS caching with an explicit known-app asset policy (or equivalent finite authority), use query-insensitive lookup where version-query drift must self-heal, and never return HTML for a script/static subresource. Add a genuinely cold-offline boot regression plus a version-query mismatch case and a wrong-MIME/no-shell-for-JS assertion. Current `?v=` markers are aligned at 24.0.2; this is a latent structural defect, not the stale 22.1/23.1 mismatch reported from the ZIP.

5. **Use an export-safe settings policy.** `exportJSON()` at `app.js:3287` excludes only `fmcsaApiKey` and `eiaApiKey`, while the import-only `ALLOWED_SETTINGS_KEYS` at 3427 includes `cloudBackupToken` and `appLockPin`. Centralize a deny-by-default export policy and exclude at minimum the bearer backup token, app-lock PIN hash, lockout/device-local state, and API credentials from local and cloud portability payloads. Update wording: an unauthenticated SHA-256 stored beside the payload is a corruption/integrity check, not proof against malicious tampering. Regression must inspect the real downloaded/exported payload and checksum inputs.

6. **Keep profitability claims conditional on configured operating cost.** Do not display “True Profit” or equivalent as factual when cost-per-mile inputs are absent. Capture monthly miles with monthly fixed costs and represent economics as unavailable/estimated until denominator and provenance are valid.

7. **Reconcile operator vehicle truth.** The confirmed cargo-length baseline is 121 inches; any 130-inch default/profile copy must not silently score freight as fitting. Preserve explicit operator overrides and expose provenance.

8. **Finish release/deployment truth.** Production app static assets report v24.0.2, but the completion certification remains HOLD because the installed physical iPhone stayed on v23.7.0 and live Worker parity is unproven. Deploy/verify Worker v13 `/health`, unauthorized admin denial, and live smoke tests; do not instruct the operator to uninstall the PWA or clear Safari data because IndexedDB evidence may be lost. Main branch protection is still off and should require the Tests and Lanes checks as an owner setting.

## Version rule

If this packet becomes the next shipped candidate, the monotonic next version from current live main is **24.0.3**. Bump once, at the end, across every version/cache marker; do not create partial cache generations during the work.

## GPT concurrent slice

GPT is changing `styles.css` only on `agent/gpt/mobile-release-polish`. The slice is presentation-only and does not touch shared/core files. Please avoid editing `styles.css` until that PR lands or coordinate first.
