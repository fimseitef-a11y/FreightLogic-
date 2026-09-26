# GPT → Claude: post-structural release handoff

Date: 2026-09-13
Operator authorization: continue FreightLogic work without redundant approval.

## Current main

- `main`: `d2c9a9ed25752cb4605c5433a52e2f4eb615e64d`
- app/PWA: v24.0.7
- IndexedDB: 15
- Worker source: 15
- PR #168 structural shell is merged: Today / Loads / Evaluate / Trips / Money.
- Post-merge Tests run `34746260152` is green.
- Cloudflare production build/deploy for the merged runtime succeeded (version `9dfb5ad3-086b-4e11-b3eb-8c09b34eeb52`), but exact production byte/header parity still requires the canonical live verifier.

The earlier structural-pass request in `gpt-to-claude-modern-ui-structural-pass-2026-09-13.md` is therefore satisfied. Do not recreate it in core.

## GPT work now in flight

- PR #169 — post-structural certification/field-document sync. Documentation only; HOLD remains.
- Draft PR #170 — approved new FreightLogic brand source (white F + upward road/arrow) and PWA icon rollout contract.

## Claude/shared work still required

1. Deploy Worker v15 through the existing manual `Deploy Backup Worker` workflow using the required explicit `DEPLOY` confirmation, then run the prescribed health/CORS/auth + authenticated authority/backup/rotation smokes. Worker v14 remains the last confirmed live generation at this handoff.
2. For the approved icon refresh, coordinate the final PNG replacement with the next shared PWA/cache generation. Do not merge only a subset of icon sizes and do not leave new icon bytes behind the unchanged installed-client cache contract. The full raster family is prepared for: favicon16/32 plus icon64/120/128/152/167/180/192/256/512/1024.
3. After the final release-bound shared changes land, run/enable exact production parity against the frozen candidate and return exact SHA/generation and results.

Do not alter canonical freight-decision logic, duplicate the load queue/evaluator, or relax HOLD based only on source/preview/build evidence.
