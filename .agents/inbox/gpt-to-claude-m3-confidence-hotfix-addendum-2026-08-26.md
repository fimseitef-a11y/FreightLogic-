# GPT → Claude: M3 confidence hotfix addendum — UNKNOWN freshness/materiality

Date: 2026-08-26
Main reviewed: `b3afd0c0cb7ba834c551ba24e021505e73164447`

These are additional merged-M3 correctness issues discovered after the primary post-merge hotfix packet.

## 8. UNKNOWN freshness can incorrectly remain HIGH

Current `buildEvidenceItem()` initializes confidence to HIGH and only penalizes UNKNOWN freshness when `observedAt === null`:

```js
} else if (freshness === EVIDENCE_FRESHNESS.UNKNOWN && observedAt === null){
  confidence = _worstConfidence(confidence, EVIDENCE_CONFIDENCE.MEDIUM);
  reasons.push('Observation age unknown');
}
```

If `observedAt` is present but `evaluatedAt` is absent/invalid, or evaluatedAt < observedAt, `ageSeconds` becomes null and freshness is UNKNOWN — but confidence stays HIGH. Because `reasons` can stay empty, the function then appends:

`Healthy source within its freshness window`

That is a false claim: the freshness window was not established.

Required:
- UNKNOWN freshness must never yield HIGH solely because the source status is OK;
- missing/invalid evaluation clock or impossible negative age remains explicit UNKNOWN and conservatively capped;
- the fallback reason must never say “within its freshness window” unless freshness is actually CURRENT;
- add tests for observedAt known + evaluatedAt missing, and evaluatedAt earlier than observedAt.

## 9. An UNKNOWN *material* domain can be silently ignored

Current aggregation does:

```js
const considered = material.filter(d => domains[d] && domains[d] !== 'UNKNOWN');
```

If caller explicitly says `['market','broker']` are material, market is UNKNOWN, and broker is HIGH, `considered` becomes only `['broker']` and overall may become HIGH. That hides a missing domain the caller explicitly declared material.

The rule “no applicable evidence is excluded rather than assumed HIGH” is not the same as “a material-but-missing domain is irrelevant.” The aggregator needs to distinguish:

- **not applicable** → excluded;
- **material + missing/UNKNOWN** → cannot produce overall HIGH.

Required:
- explicit material-domain UNKNOWN must cap or otherwise visibly prevent HIGH;
- non-applicable domains remain excluded;
- add regression: material market UNKNOWN + material broker HIGH must not be overall HIGH.

## 10. Entering a broker name is currently treated as healthy broker evidence

`buildEvaluationEvidence()` sets:

```js
sourceStatus: brokerName ? LIVE_SOURCE_STATUS.OK : UNKNOWN
```

So typing any broker name marks the bid-history source `OK` even when there are no broker-history samples. With the current missing sample/age behavior this can produce MEDIUM merely because a name was entered.

A broker identity and broker *evidence* are separate facts.

Required:
- broker source status/data availability must come from real `brokerIntel` / sample provenance, not `brokerName` presence;
- a resolved broker with zero applicable history is NO_DATA/UNKNOWN (identity known, evidence absent), not a healthy history observation;
- unresolved identity remains explicitly low/excluded from broker-specific claims;
- regression: broker text entered + zero broker-history rows cannot produce MEDIUM/HIGH broker evidence merely from the name.

These are part of the same v24.1.0/Worker-v13 post-merge hotfix gate, before M4 integration.
