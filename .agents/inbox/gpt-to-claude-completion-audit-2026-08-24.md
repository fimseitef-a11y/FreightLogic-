# GPT -> Claude: full FreightLogic completion audit + recommended finish plan

**Timestamp:** 2026-08-24  
**Owner request:** When Claude Code resumes, audit the entire current FreightLogic state and return a finite recommended plan to finish the product.

## Read this first

A new durable handoff is now on `main`:

`docs/CLAUDE_CODE_COMPLETION_AUDIT_HANDOFF_2026-08-24.md`

The handoff was added in commit:

`96224bc04ede159ffd09bc57d574a7938e2e927e`

The application/code head immediately before that docs-only commit was:

`201cc450c6ecf4492d4ed715f5caa2a736bd89a5`

Do not rely on the older `/.agents/CLAUDE_PROMPT.md` snapshot as current re-entry truth. The CSS seam has already landed, current `styles.css` ownership is reflected in `LANES.md`, new API/source decisions were made today, and open PR state has changed.

## Audit scope

Before broad implementation, inspect and reconcile:

1. current `main` and full suite baseline;
2. all open PRs/branches, especially PR #87 (v24.1 Confidence + Evidence) and PR #89 (v24.2 lifecycle contract);
3. existing audit triage and all residual revalidation gaps;
4. new clean Midwest Stack v11 + Freight Calculator Level X+ authority requirements;
5. known parity risks: Cincinnati/Toledo tiering, exact F20 $0.90 floor, UNKNOWN-vs-zero mileage/deadhead handling, mileage provenance/status;
6. external source policy:
   - Warp = preferred real/bookable cargo-van **shipper-side** quote signal, not carrier payout;
   - 123Loadboard free account exists, API access is separate and requires current terms/eligibility review;
   - Direct Freight free account exists, API/partner terms remain unresolved;
   - DAT RateView is **not cargo-van expedite authority**; `dat-rateview.js` is frozen/dormant unless owner explicitly re-authorizes it;
   - EIA/NWS/FMCSA/CBP existing source-health plumbing should be reused;
   - email/Gmail alert ingestion is a possible pre-API bridge but requires proper FreightLogic OAuth/forwarding/parser architecture and provider-term compliance;
7. operator-verified historical load/quote data and how it should enter v24.2/v24.3 without losing provenance;
8. live Cloudflare Pages/Worker parity and real auth/invite behavior;
9. real iPhone/offline/long-running field validation;
10. what can be deliberately deferred so FreightLogic reaches a stable completion release instead of continuously expanding.

## Required output before broad code work

Return a source-backed report with:

- exact current SHA / test / deployment / PR state;
- what is already finished and should be left alone;
- confirmed defects/drift ranked by severity;
- Midwest Stack v11 + Level X+ parity matrix;
- API/source matrix with price semantics and access status;
- finite completion milestones with dependencies, owners/locks, tests, migrations, deploy checks, rollback points, and definition of done;
- explicit defer list;
- recommended owner approval checkpoint.

**Do not create a second decision engine or a new parallel architecture. Do not begin a broad implementation round until the owner approves the proposed completion plan.**