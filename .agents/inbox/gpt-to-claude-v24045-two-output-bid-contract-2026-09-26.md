# GPT → Claude: v24.0.45 two-output bid contract

## Why this note
Your active `app-js.lock` task now includes the operator-approved two-output bid feature in addition to the v24.0.45 generation markers. Preserve the existing contract exactly rather than reconstructing it from older bid doctrine.

## Output 1 — BASELINE / COST-PROTECTED BID
```
baselineBid = loadedMiles * 1.25
            + deadheadMiles * marginalDeadheadCostPerMile
```

Current operator-authoritative marginal deadhead cost: **$0.296/mi**.

Important:
- This is the marginal/variable deadhead cost.
- **Do not substitute the $0.405/mi all-in accounting cost** for this formula.
- Unknown deadhead stays **UNKNOWN**. Never coerce missing/unknown deadhead to 0.
- If the operator-authoritative cost profile changes later, consume that authority rather than pinning a stale constant in a second pricing engine.

## Output 2 — RECOMMENDED MARKET BID
Keep this distinct from the baseline. It is the market/positioning/risk-adjusted bid and may consider:
- destination / next-load quality,
- deadhead burden,
- timing / appointment constraints,
- lane and reload strength,
- current FreightLogic freight doctrine / market context.

It must not silently redefine Output 1 or collapse the two numbers into a single unexplained bid.

## Release integration constraints
- Coherent next app generation: **24.0.45**.
- Keep **DB_VERSION 16** unchanged.
- Keep **Worker generation 30** unchanged unless independent evidence requires otherwise.
- Do not broaden this slice into unrelated economics/storage/Worker changes.
- Exact-head Tests + Lanes + CodeQL must be green before merge.
- Physical iPhone certification remains separate.

## Current evidence
- Clean main `5e16709badae16bd564c2f8fb0c13133b1fb6ad8`: local PC **893/893** across 87 specs.
- PR #384 exact head `85daac745430ddbab912c3842ad7bda51696c8d6`: local PC **892/893**, sole RG-03 because `styles.css` changed while generation remained 24.0.44.
