# GPT → Claude — Driver/Glance CSS contract ready for next-generation integration

Operator directive remains: finish the installable FreightLogic PWA as soon as possible.

## GPT-owned presentation work completed

Branch: `agent/gpt/driver-glance-css`
Commit: `b24f64fc4698aa9f2546dd7ee8958f14752a1e3a`

Only `styles.css` changes (206 additive lines). No app/core/Worker/release-marker path was touched.

The contract defines:

- `html[data-text-size="normal"|"large"|"xlarge"]`
- `html[data-driver-mode="glance"]`
- semantic helpers `.fl-road-primary`, `.fl-road-number`, `.fl-road-secondary`, `.fl-road-caption`, `.fl-road-action`
- text-size scaling for common trip/load/Today/evaluator surfaces
- a 16px minimum form-control floor for iPhone focus safety
- Glance-mode 52px common controls and enlarged primary route/pay/RPM/next-move hierarchy
- no hiding of secondary data, no economics, no persistence, no router/evaluator logic

Static sanity check on the exact commit:
- balanced braces
- no release-version literal in styles.css (CG-11 remains satisfiable)
- all 3 text-size states present
- Glance state present
- semantic road-use classes present
- 16px form floor present
- 52px Glance touch target present

## Integration requirement

Do NOT merge this CSS commit by itself into live 24.0.21: `styles.css` is a governed runtime asset and RG-01/RG-03 correctly require a new app generation.

Integrate/cherry-pick this GPT-authored commit into your next-generation branch that carries:
1. the PR #255 compact result repair;
2. Driver/Glance runtime state + persisted text-size preference;
3. the required v24.0.22 app/SW/cache/release-marker bump.

Runtime wiring should set/remove the two root attributes only; do not duplicate presentation sizes inside app.js.

For the compact evaluator result, use the `.fl-road-*` helpers instead of hard-coded inline 10/11/13px sizes so text-size/Glance mode can govern it.

Also preserve the provenance correction already recorded: static Tier-1/Tier-2 classification may describe anchor/density/reload *potential*, not claim live “strong/workable reloads” without live/recent evidence.

After integration: full exact-head suite, CodeQL/Lanes, deploy, then fresh exact-main live parity + production SW. DB stays 16 and Worker stays v21 unless Worker source actually changes.
