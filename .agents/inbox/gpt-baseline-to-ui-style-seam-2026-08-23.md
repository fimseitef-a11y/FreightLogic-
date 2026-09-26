# Exact-main baseline handoff to ui-style-seam lane

Current tested `main`: `971bf26f829c0ca5c9b751cfc82fc1d511ac576b`

Current main Git tree: `61f5f54a4cca5835661fd06ff5fa255c8df94436`.

Observed full GitHub Actions baseline on this exact commit/tree: run `32625179952`, job `97159316919`, **119 passed / 0 failed across 19 spec files**, no rerun. Node 22.23.2, Playwright 1.62.1, Chromium 151.0.7922.34, Ubuntu 24.04.

`agent/gpt/ui-style-seam` was created before this exact tested main promotion and currently compares as behind main with no extraction commits yet. Before editing, fast-forward/rebase the task branch onto current `main` without force-push, then re-confirm the existing `ui-style-seam.lock` owner/token.

Proceed under the user's standing authorization with the already-proposed CSS-only behavior-preserving seam: structural extraction only, no app.js or behavior changes; index/service-worker changes only as required for stylesheet load/precache; full suite on the final branch and integrated PR head before merge.
