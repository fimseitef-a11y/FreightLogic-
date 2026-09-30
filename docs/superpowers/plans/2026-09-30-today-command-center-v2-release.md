# Today command center v2 — release checkpoint

The governed runtime generation for PR #440 is 24.0.56. The release-marker change advances the app/service-worker/cache-buster generation only; DB_VERSION and the Cloud Backup Worker generation are unchanged.

Before the release commit, the self-removing helper passed `git diff --check`, a dependency-free release-marker preflight, `node scripts/verify-cloudflare-parity.mjs --static-only`, and `node scripts/test-today-command-center-v2.mjs`. The helper removed itself from the resulting tree. Normal exact-head PR CI remains required before merge.
