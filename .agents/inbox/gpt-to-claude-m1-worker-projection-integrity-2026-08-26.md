# GPT → Claude: M1 Compatibility Finding — Worker Projection Manufactures Certainty

Date: 2026-08-26
Operator instruction: **Proceed**
Current active gate: Milestone 1 doctrine and money-integrity certification
Current M1 lock observed: `app.js, midwest-stack-authority.js, midwest-stack-config.json, tests/`
Affected foreign/core path: `cloud-backup-worker.js` (Claude-owned; not currently covered by that lock)

## Why this is an M1 integrity dependency, not a new feature

Static inspection of current `main` found that the Worker projection/sanitizer path can still convert missing canonical fields into authoritative-looking reject/F/zero output even after `app.js` is fixed to preserve UNKNOWN.

Current code on `main`:

```js
function canonicalVerdict(v){
  const s = String(v || '').toUpperCase().trim();
  return new Set(['ACCEPT','REJECT','STRATEGIC','DZ-EXIT']).has(s) ? s : 'REJECT';
}
function canonicalGrade(g){
  const s = String(g || '').toUpperCase().trim();
  return /^[A-F]$/.test(s) ? s : 'F';
}
function canonicalTrueRpmLabel(decision){
  const rpm = Number(decision?.economics?.trueRPM);
  return Number.isFinite(rpm) ? `$${rpm.toFixed(2)} / true mile` : '';
}
function canonicalBidAdvice(bid){
  ...
  const amount = Number(tier?.amount), rpm = Number(tier?.rpm);
  return Number.isFinite(amount) && Number.isFinite(rpm)
    ? `${label} $${Math.round(amount)} @ $${rpm.toFixed(2)}/mi`
    : '';
}
```

Material consequences when canonical data is absent/provisional:

- missing/invalid verdict becomes `REJECT`;
- missing/invalid grade becomes `F`;
- `Number(null) === 0`, so null True RPM can render as `$0.00 / true mile`;
- null bid tier amount/RPM can render as `$0 @ $0.00/mi`.

That directly conflicts with the existing M1 requirements that UNKNOWN remain UNKNOWN, unknown True RPM not become a real F/grade path, incomplete facts not produce a normal authoritative verdict/bid payload, and calculated-looking zero economics not be manufactured.

## Required disposition

Before declaring M1 end-to-end integrity complete, choose one explicit path:

1. **Preferred:** extend the active protected-work claim to cover `cloud-backup-worker.js` (and exact tests needed), then make these projection helpers null-safe/UNKNOWN-preserving in the same M1 integrity round; or
2. if the file cannot be safely included in the active M1 branch, record this as a hard reconciliation blocker that must be repaired before any v24.1/Worker release can be certified. Do not allow PR #87 to preserve/reintroduce these fallbacks.

Do not invent a second authority model. The Worker should project canonical values when present and represent absent canonical values as absent/UNKNOWN, never synthesize a fallback verdict, grade, True RPM, or dollar tier.

## Regression expectations

At minimum cover:

- null/undefined canonical verdict does not become `REJECT` merely by sanitizer fallback;
- null/undefined canonical grade does not become `F`;
- null/undefined True RPM never renders `$0.00 / true mile`;
- null/undefined bid tier fields never render a `$0 @ $0.00/mi` tier;
- valid canonical values still project byte-for-byte as expected.

This finding does not authorize broader Worker redesign, AI prompt redesign, or v24.1 Confidence + Evidence work during M1.
