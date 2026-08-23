# Post-extraction repair queue — execute sequentially after green seam merge

This queue is intentionally NOT part of the CSS extraction. The user's standing proceed authorization remains active, but structural extraction must stay behavior-only.

## 1. X-12 — deployment parity checklist drift (formal OPEN)

Current source confirms `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` is stale:

- checklist still says app/SW/manifest `v23.9.0`;
- checklist still says Worker source/health `v11`;
- shipped/current source is app/SW/manifest `v24.0.0` and Worker `v12`;
- `scripts/verify-cloudflare-parity.mjs` already expects v24.0.0 / Worker v12.

Repair scope after extraction:

- update the operational checklist to the current v24.0.0/Worker-v12 markers and current parity command/expectations;
- preserve historical changelog/audit references as history rather than rewriting them;
- update `.agents/AUDIT_TRIAGE.md` only after current-source verification proves X-12 closed;
- do not claim the live Cloudflare Pages/Worker half verified unless it was actually reachable and checked. Current session could not reach those origins, so that live deployment-parity item remains evidence-bound.

## 2. R-TOCTOU-EXPENSE-FUEL — residual core-data OPEN

Current audit triage records the same lost-update class previously fixed for trips:

- `updateExpense()` and `updateFuel()` perform unconditional full-object `put()` writes;
- sanitizers stamp `updatedAt` but do not preserve/compare a caller-expected revision;
- simultaneous stale edits can overwrite a newer expense/fuel change.

Repair target:

- mirror the proven trip optimistic-concurrency pattern rather than inventing a second mechanism;
- reject stale writes explicitly and reload/preserve the winning stored record;
- cover expense AND fuel independently;
- preserve create/add semantics fixed by F-8;
- full suite required because this is core IndexedDB/data-integrity behavior.

## Sequence

CSS seam merge + fresh green main -> X-12 focused repair -> full green -> R-TOCTOU-EXPENSE-FUEL focused repair -> full green -> v24.1 runtime implementation.

Do not combine these repairs with one another or with the structural extraction unless a later protocol update explicitly changes the integration plan.
