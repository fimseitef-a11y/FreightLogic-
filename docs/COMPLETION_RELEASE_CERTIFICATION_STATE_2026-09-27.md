# Completion release certification state — production 24.0.47 / DB16 / Worker v30

Date: 2026-09-27
Supersedes: COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-21.md
Status: **HOLD — v24.0.47 / DB16 / Worker v30 automated suite, CodeQL, live all-asset parity and production service-worker checks are OBSERVED and PASSING on current main. Physical iPhone A1-A14 (#226) and the real-iPhone PushWard smoke plus old-key revocation confirmation (#380) remain open manual gates.**

This state supersedes the 2026-09-21 addendum (a v24.0.29 / Worker v21 checkpoint) without
rewriting it. That addendum and every earlier record stay as history. This is a dated evidence
checkpoint, not a claim that all FreightLogic work is complete. Nothing below infers physical,
device, provider or account-admin evidence from automated results.

Requested by the GPT PC verification lane (`.agents/inbox/gpt-to-claude-m7-v24047-cert-state-2026-09-27.md`
on `agent-coordination`, Airtable `recyGzV87u0wmSf11`) after `scripts/m7-certify.mjs` on current
main kept resolving the v24.0.29 addendum as canonical.

## Current generation

- App / service worker / manifest: **24.0.47** (`APP_VERSION`, `SW_VERSION`). Runtime merged in
  PR #395 as `db35cf3c` (offline vendored SheetJS 0.20.3, #392; Intel → Market label, #389).
- `DB_VERSION` **16**.
- Worker: **v30** in source and in production. Deployed 2026-09-26 through the governed path
  from the operator's authorized PC (Cloudflare version `24cc3ac6-1daf-4476-a805-2c975d9fc03d`),
  recorded on #380. `/health` reported 30 and the unauthenticated admin/evaluate boundaries
  returned 401.

## Automated and live evidence of record

On `main` @ `fe2437dffe77fbee06f33ffd7be2b86c9e6f2821` (PR #405 merge; it adds the isolated
`agent-runtime/` tree and withholds it in `.assetsignore`, and changes no declared runtime asset):

| Gate | Run | Result |
|---|---|---|
| Tests | `36317109940` | PASS |
| CodeQL | `36317109934` | PASS |
| Verify Live Parity | `36317109903` | PASS (enforces app/SW/manifest 24.0.47 and the Worker v30 pin) |
| Verify Production Service Worker | `36317110163` | PASS |

These are push-triggered runs. They are cited because they passed: a parity PASS is only possible
when production already serves the source-derived generation. The recorded push races are all
failures that saw the previous generation.

Independent authorized-PC verification of `main` @ `660fdc51667d90f5f2260c3ae9e73ce517e77154`
(same runtime bytes as `fe2437d`; Airtable `recLLLPITzhiaqBpw`):

- `node tests/run-all.mjs`: **906 passed, 0 failed across 89 spec files**;
- `node scripts/verify-cloudflare-parity.mjs`: PASS;
- `node scripts/verify-production-sw.mjs`: PASS;
- Wrangler 4.141.0 `deploy --dry-run -c scripts/wrangler.backup-worker.jsonc`: PASS, no deploy.

The v24.0.47 release observation itself (Production Service Worker `36296068967`; Live Parity
`36296068917` attempt 2 after the propagation race; direct fetch of `vendor/xlsx.full.min.js`
returning 951,904 bytes, SHA-256 `cc015130aa8521e7f088f88898eba949ccdcbfb38df0bd129b44b7273c3a6f41`,
`XLSX.version` 0.20.3) is recorded in `CLAUDE.md`.

## Items the 2026-09-21 addendum held open, and where they stand

| Item | Now |
|---|---|
| Repository administration (#222) | **CLOSED completed 2026-09-27.** The main ruleset, secret scanning and push protection were verified directly from an authenticated session on the authorized PC (Airtable `recbA1MukxQeNzNMY`). No longer a blocker. |
| Admin Console (#231) | **CLOSED completed 2026-09-22.** Verify Admin Console `35772326644` PASS against the deployed console and Worker v23, then Phase C removed the driver-app admin surface (v24.0.33). |
| Authenticated live vision provider (#252) | **Issue CLOSED 2026-09-22.** The privileged production invocation is observed: Verify Authenticated Worker `36174957845` shows Llama 4 Scout answering on Worker v26. Extraction quality on a real DispatchLand screenshot is **not recorded here as observed**, and nothing in this document certifies it. |
| Economics authority (#278) | **CLOSED completed 2026-09-22.** Rate basis (v24.0.31), DEACTIVATED outcome (v24.0.30) and the operator's long-haul resolution (v24.0.32) shipped. |
| Safari/macOS + native Apple (#204/#205) | **CLOSED 2026-09-27.** The native track is frozen by operator decision (PWA + Shortcuts + Web Push). Real-Safari device behaviour stays inside #226. |
| Physical iPhone (#226) | **OPEN.** The gate is now **A1-A14** (A14 = Shortcuts relay + Web Push). Headless or CI evidence cannot mark a physical row PASS. |

## What remains open

| Gate | State |
|---|---|
| Physical iPhone A1-A14 (#226) | **OPEN / manual.** Use the field-certification runner and `FIELD_TEST_CHECKLIST.md` on the real device. |
| PushWard Live Activity (#380) | **OPEN / manual.** Worker v30 is live. Still needed: a real-iPhone smoke through the authenticated `/pushward/test` path, and the operator's confirmation that the PushWard key exposed earlier in chat was revoked and the replacement entered directly into Cloudflare. A stored secret's value cannot be read back, so no automated check can confirm the rotation. |

Authentic **M6 Gate C** remains as recorded (PASS, adoption pending the operator's conflict
review). The unavailable 125-row master CSV stays separate and must not be reconstructed from
summaries.
