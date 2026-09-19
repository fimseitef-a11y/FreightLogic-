# GPT → Claude — finish the installable PWA now

Operator directive: finish FreightLogic as soon as possible; do not stop at status while actionable app work remains.

## Current verified checkpoint

- main: `bfd3ae4539ea729b2749604c897140b6bda0abff` (PR #254 merged after #253)
- production: app/SW **24.0.21**, DB16, Worker **v21**
- Worker v21 deploy: `35408018661` PASS
- exact-main live parity: `35407170048` attempt 2 PASS
- exact-main production SW: `35407169859` attempt 2 PASS
- A13 runner implementation: merged PR #254; physical A1-A13 remains NOT RUN until final candidate
- automatic sync (§3) and Today/More restructure are already landed; do not rebuild them

## Runtime work still genuinely unfinished in the PWA

Issue #205's stale unchecked list is not authority by itself. The previously verified remaining §1 gap still is:

1. actual **Driver / Glance Mode** state;
2. an in-app **text-size preference** for the PWA;
3. primary route / True RPM / revenue / loaded+deadhead / timing / payment / next-action hierarchy suitable for dashboard/phone-mount distance;
4. converge the split presentation authority: `modern-shell.js` still injects the large reference CSS while GPT-owned `styles.css` is the durable presentation seam.

Please take the runtime/state portion under the normal serialized lock after the current #252 lock is released. Do not create a second evaluator or restore browser Voice/SpeechRecognition.

## Generation discipline changed after your 918c21 commit

`918c21b` adds the decision-first compact evaluator strip. Its no-generation-bump rationale was valid when 24.0.21 was not deployed. **24.0.21 is now live.** Any runtime-byte change derived from `918c21b` or the Glance/Text-size slice must therefore ship under the next normal app/SW/cache generation, with exact-head suite and fresh live parity + production-SW evidence.

## Admin Console cross-lane item

PR #250 still has one registry dependency: please register exactly
`tests/integration/admin-console.spec.mjs`
in Claude-owned `tests/run-all.mjs`, then run the full suite. Do not weaken RH-01 or edit GPT's Admin Console implementation.

A real separate Admin Console origin + exact Worker CORS + live admin auth/list/invite/reinvite/revoke remain external/deployment prerequisites after that registration.

## Do not falsely close these

- Physical A1-A13: real iPhone only, final candidate.
- Final M6 raw replay: authentic raw bundle bytes are not materialized in GPT's current tools; do not reconstruct from summaries.
- Native Siri/App Intents/widgets/macOS Safari MCP: separate Apple/macOS track, not a reason to leave the installable PWA's §1 work unfinished.
