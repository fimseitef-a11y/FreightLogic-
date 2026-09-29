# FreightLogic Security & Readiness Controls — 2026-09-29

Scope: production backup/API Worker, isolated Admin Console, local-first PWA, and CI readiness gates.

## Credential lifecycle

- Driver bearer credentials have a 365-day absolute lifetime and a 90-day inactivity lifetime.
- Existing pre-v31 credentials receive migration grace beginning on their first successful v31 request; rollout does not mass-lock existing devices.
- Rotation and re-invite mint a fresh credential window while preserving the canonical userId and cloud history.
- The operator ADMIN_TOKEN is never persisted in plaintext by the Worker. A hash-keyed lifecycle record starts on first successful v31 use and expires after 90 days. Rotating the Cloudflare secret creates a new lifecycle identity.
- Ephemeral certification-admin credentials retain their existing 15-minute TTL and narrower permissions.

## Abuse/resource controls

- JSON/text request ceilings are enforced while streaming the body and therefore do not trust Content-Length.
- Production rate/provider-spend counters use a SQLite-backed Durable Object. The KV read/increment/write path exists only as a unit/local compatibility fallback.
- Production /health reports the limiter mode and finite credential policy; deploy/parity gates reject a production generation that does not report the hardened mode.
- High-volume load tests are staging/local only. scripts/load-test.mjs refuses known FreightLogic production hosts unless an operator deliberately passes --allow-production.

## Privileged audit trail

Privileged admin actions write a server-side audit event before mutation. Records keep only:
- UTC timestamps
- actor class (operator or certification)
- action class
- state (started/succeeded)
- one-way truncated SHA-256 subject pseudonym
- deletion count where applicable

The audit record never stores driver names, raw user IDs, tokens, IP addresses, request bodies, load economics, payment data, or backup payloads. Retention is 400 days.

## Account revocation vs permanent erasure

Revocation remains reversible from a data perspective: it disables authority and retires credentials without deleting cloud history.

Permanent erasure is a separate operator-only action. It requires:
1. the account to already be revoked;
2. a POST to /admin/users/:id/erase;
3. an exact body confirmation { confirm: "ERASE", userId: "<same canonical id>" }.

Erasure removes the canonical user record, all device backup/delta/pointer keys, bearer-token indexes including stale race residue, bound invite codes, Web Push subscriptions, relay inbox/dedup state, reminders/index membership, Shortcut credentials, and per-user abuse counters. It preserves unrelated accounts, global VAPID state, and privacy-safe audit evidence.

## Data retention

- Full encrypted cloud snapshots retain the existing rolling cap (three per device).
- Delta snapshots retain the existing rolling cap/7-day TTL.
- Relay items retain their existing 72-hour TTL.
- Invite claim codes retain their existing 72-hour TTL and hash-only storage.
- Admin audit metadata retains 400 days.
- Other account-scoped metadata remains while the account exists and is removed by permanent erasure.
- The Worker cannot decrypt client-side encrypted backups; user-controlled local export remains the authoritative readable data-export path.

## Performance/readiness evidence

CI now runs:
- compressed asset budgets, with a 200 KiB gzip enterprise target for app.js and a 400 KiB regression ceiling while decomposition work remains;
- three local Lighthouse performance runs with median gates for performance score, LCP, CLS, and TBT;
- a bounded local 500-request/20-concurrency load smoke producing RPS and p50/p95/p99 latency/error metrics;
- Wrangler dry-run validation of the production backup/API Worker config.

INP is not fabricated from a lab run. The CI gate reports TBT as a lab responsiveness proxy; production INP requires real-user field measurement and a separately approved telemetry/privacy design.

## Remaining external evidence

These controls do not replace physical-device UAT. Issue #226 real-iPhone A1–A14 certification and Issue #380 PushWard real-iPhone smoke/key-rotation confirmation remain manual evidence gates. The production Agent release remains separately gated by verified GitHub Environment required-reviewer protection.
