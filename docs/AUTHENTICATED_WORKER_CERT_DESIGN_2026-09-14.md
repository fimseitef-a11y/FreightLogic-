# Authenticated Worker certification — synthetic identity design

Date: 2026-09-14

This note documents the safety boundary for the one-time authenticated production gate. It does not contain credentials.

The gate uses the already-configured `CLOUDFLARE_API_TOKEN` GitHub Actions secret only to create a short-lived synthetic driver identity directly in the existing production KV namespace. The synthetic bearer token is generated inside the runner, immediately masked from logs, never committed, and its two identity keys receive a short TTL. The existing `verify-live-authority.mjs` free checks and `verify-live-backup.mjs` then exercise the deployed Worker using only synthetic decision/backup payloads.

All Worker writes are isolated to the synthetic user/device namespace. Cleanup runs through an EXIT trap and removes the synthetic `user:`, `tokh:`, backup/delta/pointer, and rate-limit keys by exact key or synthetic-user prefix. The identity keys also expire automatically as a backstop if the runner is interrupted.

This gate does not attempt the live admin token-rotation endpoint because the Worker admin secret is intentionally not retrievable from Cloudflare/GitHub. The existing unit suite continues to cover rotation semantics; a live rotation smoke remains a private-admin operational check rather than a reason to expose or replace the production admin credential.
