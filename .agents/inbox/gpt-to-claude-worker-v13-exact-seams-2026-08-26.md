# GPT → Claude: Worker v13 exact seams from merged main

Date: 2026-08-26
Main: `b3afd0c0cb7ba834c551ba24e021505e73164447`
File reviewed: `cloud-backup-worker.js` v12

Supplement to the post-merge M3 hotfix directive. These are the exact merged Worker seams producing the UNKNOWN/confidence failures.

## Request validation currently blocks unavailable canonical decisions

Merged v12 requires all of these:

```js
if (!payload.canonicalDecision?.authority?.verdict ||
    !payload.canonicalDecision?.authority?.grade ||
    !Number.isFinite(Number(payload.canonicalDecision?.economics?.trueRPM)) ||
    !payload.canonicalDecision?.bid?.range) {
  return ...400;
}
```

M1 intentionally permits a legitimate client-owned incomplete state with:

- verdict `UNAVAILABLE`;
- grade `?`;
- `economics.trueRPM === null`;
- suppressed bid / `range === null`.

The v13 validator therefore needs two explicit schemas/paths:

1. **factsComplete === true**: require the normal canonical numeric/range facts;
2. **factsComplete === false**: require/allow the canonical unavailable shape and do not invent numeric facts.

Do not rely on `Number(null)` when validating knownness.

## Output sanitizers currently manufacture false precision

Merged v12:

```js
function canonicalVerdict(v){
  ...
  return allowed.has(s) ? s : 'REJECT';
}

function canonicalGrade(g){
  ...
  return /^[A-F]$/.test(s) ? s : 'F';
}

function canonicalTrueRpmLabel(decision){
  const rpm = Number(decision?.economics?.trueRPM);
  return Number.isFinite(rpm) ? `$${rpm.toFixed(2)} / true mile` : '';
}
```

Consequences:
- `UNAVAILABLE` -> `REJECT`;
- `?` -> `F`;
- `null` -> `Number(null) === 0` -> `$0.00 / true mile`.

v13 must preserve absence/unavailable verbatim enough for the UI/AI review response to remain semantically correct. A genuinely low calculated load may still be `REJECT/F`; missing facts may not.

`canonicalBidAdvice()` currently falls back to a generic sentence when range is absent; keep it explicitly unavailable/suppressed rather than phrasing it as though a canonical range exists elsewhere.

## Confidence boundary is absent in v12

There are **zero `confidence` references** in merged `cloud-backup-worker.js`. The M3 client sends client-owned confidence/evidence projection, but `buildEvalPrompt()` does not present it to the model and the response projection does not return/explain it.

v13 must:
- accept the client-owned confidence/evidence projection;
- put only that already-normalized projection into the AI review prompt;
- instruct AI that labels are client-owned/descriptive and cannot modify verdict/grade/RPM/bid;
- return explanatory/challenge text without publishing a competing label or percentage;
- never fabricate missing evidence.

## Required Worker regressions

Add tests for at least:

1. complete canonical decision still accepted/projected unchanged;
2. `factsComplete:false`, `UNAVAILABLE`, `?`, `trueRPM:null`, suppressed/null bid is accepted as a legitimate review payload or handled with an explicit unavailable response — never 400 solely because numeric fields are absent;
3. no output path transforms that state into `REJECT/F/$0.00`;
4. genuinely calculated `REJECT/F/0.xx` remains a real low decision, proving missing vs low are distinct;
5. client confidence HIGH/MEDIUM/LOW is echoed/explained but cannot be replaced by model output;
6. Worker response contains no model-authored confidence percentage/authoritative label;
7. `/health` reports version `13`.

Keep this hotfix separable from M4 lifecycle code.
