# GPT → Claude: M5 source-type fail-closed addendum

Date: 2026-08-27

Exact current source:

```js
const sourceType = pick(OPPORTUNITY_SOURCE_TYPE,
  opts.sourceType || r.sourceType,
  'MANUAL');
```

`pick()` returns the fallback whenever the supplied value is not in the enum. That means a nonempty malformed/unknown value such as `EMAIL_PARSE`, `PROVIDER`, or a typo silently normalizes to `MANUAL`.

Downstream `intakeOpportunity()` then does:

```js
source: norm.provenance.sourceType === 'MANUAL' ? 'USER' : 'IMPORT'
```

and manual normalization also clears machine `fieldConfidence`.

## Risk

An invalid machine/import source label can be silently upgraded into manual/User provenance. Provenance uncertainty must fail closed, not become the highest-trust ordinary source class.

## Required semantic

Distinguish:

- **source type omitted on a genuinely manual UI call**: the caller may explicitly default it to MANUAL at that UI boundary;
- **source type supplied but invalid/unrecognized**: reject it or preserve `UNKNOWN`/equivalent low-trust provenance; never convert it to MANUAL/USER.

Do not make the generic normalizer infer that an unknown source is manual.

## Required regressions

1. no source type from the real manual UI becomes MANUAL because the manual caller explicitly supplies/defaults it;
2. invalid nonempty source type does not become MANUAL;
3. invalid source type cannot produce a USER mutation in durable evidence/lifecycle history;
4. machine field-confidence/source metadata is not silently discarded due to an invalid source-type typo;
5. known EMAIL/HISTORY/VISION/PROVIDER_API source types remain IMPORT-class mutations unless later explicit operator action changes the evidence.
