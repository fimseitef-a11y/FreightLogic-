# Next Move Layer — v1 Specification

Status: **APPROVED TO START** by the operator on 2026-09-24 (reply "Both" to the proposed
intelligence layer). This document is the contract for the first slices. It is additive:
it keeps the current engine and UI, and it never changes canonical verdict, grade,
economics or bid range.

## 1. What it answers

Grading one load answers "is this load worth it?". Next Move answers **"what should I do
next from where I am?"**, one of:

| Move | Meaning | May only appear when |
|---|---|---|
| `TAKE` | Take the load being evaluated | A candidate load has a canonical decision of `ACCEPT` or `STRATEGIC` (never `REJECT`, `DZ-EXIT` without its gate, or `UNAVAILABLE`) |
| `WAIT` | Stay and work this market | The position resolves to a market, and reload evidence for it is good (see 4) |
| `REPOSITION` | Move toward a named better market | Position resolves, the market is evidenced as slow/trap, and a nearby anchor/support market exists |
| `UNKNOWN` | Not enough evidence to direct | Anything else. It names what is missing |

`UNKNOWN` is a real answer, not an error. It replaces today's F24 default of `HUNT`
("Unknown market. No history yet — watch boards"), which issues a directive from missing
data. That is the blank-deadhead / Toronto-for-blank class this repository has fixed
repeatedly (v24.0.1, v24.0.4, #216).

## 2. One directive surface, not two

The Today "Next Move" card is already `getPositioningBrief()` / `renderPositioningCard()`
(F24, restructured in v24.0.20). Next Move **evolves that command**; it does not add a
second card or a second directive. Mapping from the current F24 vocabulary:

| F24 today | Next Move v1 |
|---|---|
| `HOLD` (reload grade A/B, or anchor/support market) | `WAIT` |
| `REPOSITION` (dead zone with no outbound lanes, or trap market) | `REPOSITION` |
| `HUNT` with outbound lane options | `WAIT`, listing the evidenced lanes |
| `HUNT` with no evidence ("Unknown market") | `UNKNOWN` |

Position identity keeps coming from `resolveDriverPosition()` (#216), and an **ambiguous**
position yields `UNKNOWN`, the same stand-down the banner already applies (v24.0.20).

## 3. Authority

- **Advisory only.** Next Move reads the canonical decision; it never recomputes
  economics, grade or bid. `TAKE` is derived from `buildUnifiedDecisionContract()` output,
  not from a second calculation. This is the v24.0 authority rule applied to a new consumer.
- It can never soften a hard gate: a `REJECT` load is never `TAKE`, whatever the market says.
- Emergency pricing (~$0.89–0.90 True RPM) stays tactical escape pricing only, per operator
  doctrine. Next Move never treats it as a floor.

## 4. Evidence rules (strict)

Evidence states stay separate and never imply each other:
BOARD OBSERVATION → QUOTE → BID → WON/LOST → BOOKED → PICKED UP → COMPLETED → PAID.

- **Trips** count toward lane/market evidence only if `tripHasKnownDeadhead()` and not
  `needsReview`. An unknown deadhead is never summed as zero.
- **Bid outcomes** count only when adjudicated (`WON` / `LOST`). `EXPIRED` is a lost bid for
  win-rate purposes only where the existing rules already say so; `DEACTIVATED` is censored
  and excluded (v24.0.30).
- **Reload outcomes** count only with a recorded, non-negative `hoursToReload`.
- **Sample thresholds** reuse the v24.1 confidence contract
  (`docs/V24_1_CONFIDENCE_EVIDENCE_SPEC.md`): HIGH ≥ 10, MEDIUM 3–9, LOW ≤ 2. A LOW-evidence
  market cannot produce `WAIT` or `REPOSITION` on its own history; static market
  classification (Tier 1/2, anchor/support/trap) may still inform, labelled as static.
- **Distances** to a reposition target are `ESTIMATED` (straight-line), never presented as
  verified deadhead.
- Conflicting source records stay separate; DispatchLand quotes are never deduplicated by
  route alone.

## 5. Output shape

```js
{
  move: 'TAKE' | 'WAIT' | 'REPOSITION' | 'UNKNOWN',
  reason: string,               // one driver-readable sentence
  missing: string[],            // for UNKNOWN: which facts would unlock a move
  target: { city, distanceMi, distanceProvenance: 'ESTIMATED' } | null,
  confidence: 'HIGH' | 'MEDIUM' | 'LOW',
  evidence: [{ kind, count, provenance }]   // what the move rests on
}
```

## 6. Slices

1. **S1 — evidence integrity of the positioning brief (prerequisite).** Three existing
   defects in `getPositioningBrief()` that Next Move would inherit:
   - Outbound lane RPM and day-of-week patterns sum `Number(t.emptyMiles || 0)`, so a trip
     with an unstated deadhead reports a loaded-only RPM as a lane average ("Target: X at
     $1.80 avg"), and `needsReview` trips are not excluded. Same class fixed in `tripRow`
     (v24.0.15) and CSV export (v24.0.11).
   - Day-of-week patterns parse `new Date('YYYY-MM-DD')`, which is **UTC midnight**, so in
     any US timezone `getDay()` returns the previous day and "best day" is off by one.
   - Reload averages read `hoursToReload || 0`, so a missing value counts as an instant
     reload ("Hot market").
2. **S2 — Next Move derivation.** A pure `deriveNextMove(brief, position, decision)`
   implementing sections 1–5, wired into the existing card's command badge. `UNKNOWN`
   replaces the no-evidence `HUNT`.
3. **S3 — TAKE linkage.** The evaluator result offers the Next Move line for the load just
   scored, read from the canonical decision.

Later, and **not** in v1: Day Value / opportunity cost, the per-market operating clock, and
reload latency modelling. Each gets its own spec before code.

## 7. Acceptance

- No canonical verdict, grade, True RPM or bid range changes on any existing test fixture.
- A market with no evidence renders `UNKNOWN` and names what is missing; it never renders a
  directive.
- An ambiguous position renders `UNKNOWN`.
- A `REJECT` or `UNAVAILABLE` load never renders `TAKE`.
- A trip with an unstated deadhead never contributes to a lane average.
- Every slice ships with red-first regressions and a negative control, per repository
  convention.
