# v24.0.2 Durability Release Amendment

Date: 2026-08-28  
Applies to: `docs/BACKUP_CONTRACT.md`, `docs/NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md`, Issue #119, and the v24.0.2 corrective candidate.  
Status: **release-blocking clarification until runtime + regressions conform**

This amendment records the post-freeze source findings discovered while reviewing the exact v24.0.2 candidate. It does not enlarge release scope. Where the v24.0.2 draft backup text is less precise, this amendment controls until the parent contract is reconciled in the final certified docs commit.

## 1. Evidence must become durable before lifecycle state is created from it

For manual/email intake and M6 historical normalization, the safe sequence is:

1. normalize the source observation;
2. persist the semantic evidence with `lifecycleId:null` / unresolved link state;
3. only after that write succeeds, conservatively resolve/create/link lifecycle state;
4. update the already-durable evidence row with the resolved link using `expectedRevision`;
5. if linking or the second evidence write fails, preserve the original evidence row and surface the unresolved/failed attachment.

A first evidence-write failure must not leave newly-created lifecycle state behind.

## 2. External order numbers are not strong internal source references

Provider/broker order, quote, or load numbers remain external evidence attributes and candidate linking signals. They must not be relabelled into a strong internal reference such as `sourceRefs.tripIds` merely because a legacy store happens to use `orderNo` as its key.

If no genuinely internal stable trip identifier exists, the strong internal reference is absent. Linking must then fall back to the conservative compatible route/time/broker doctrine and fail unresolved when candidates compete.

## 3. Manual source type and authority are separate

`sourceType:'MANUAL'` identifies how data entered the app. It does not by itself prove `PRIMARY_DOCUMENT`, `OPERATOR_CORRECTION`, or any other authority tier.

An explicit revenue confirmation may promote only the amount/revenue fact it confirms. It must not silently promote broker, origin, destination, mileage, timestamps, or the whole row. Field-level provenance must carry the authority actually established for each material fact.

Unknown/unproven authority must remain explicitly conservative rather than being invented as documentary or AI authority.

## 4. Scalar values and field provenance are one conflict-resolution unit

For `normalizedEvidence` cloud restore or local JSON merge, the scalar winner is chosen by the established revision/recorded-time rule. The provenance entry for a material field must follow the same winning value.

Therefore an unconditional incoming-last merge such as:

```js
{ ...(existing.fieldProvenance || {}), ...(incoming.fieldProvenance || {}) }
```

is not valid for overlapping material-field keys when `incoming` lost the scalar conflict. A stale record may not relabel a newer retained value with stale provenance.

Non-overlapping provenance may be unioned only when it remains semantically valid for retained material fields.

Required regressions must prove both directions:

- newer local scalar + provenance survive an older incoming record;
- newer incoming scalar + provenance replace the older pair;
- complementary non-overlapping provenance is retained only when valid.

## 5. Local JSON merge is a reconciliation path, not blind overwrite

`replace` mode may deliberately replace after its documented backup/clear behavior.

`merge` mode must protect `loadLifecycle` and `normalizedEvidence` with the same no-downgrade semantics as cloud restore (or a shared reconciler):

- compare revision, then authoritative timestamp;
- preserve newer scalar/state values;
- union lifecycle `sourceRefs` only where valid;
- keep evidence scalar/provenance pairs together;
- do not silently downgrade a newer local correction from an older export.

Plain `putAll()` of protected lifecycle/evidence rows is insufficient for merge mode.

## 6. Idempotent re-import means no mutation when nothing changed

For an identical normalized source observation whose material content, provenance, and lifecycle link state are unchanged, re-import must be a true no-op:

- same `evidenceId`;
- one row only;
- same `revision`;
- same `recordedAt`;
- no phantom cloud delta / sync mutation.

A test that proves only `rowCount === 1` is insufficient.

## 7. Current release state must supersede historical HOLD deterministically

Historical HOLD/NOT CERTIFIED/BLOCKED records remain immutable evidence. They must not become permanent active blockers after a later authoritative certification state supersedes them.

The release runner needs one deterministic current-state authority or explicit supersession rule. Missing/unparseable current state still fails closed. Date-only filename ordering is not sufficient when multiple state/addendum files can exist on the same date.

## 8. Certification gate

The v24.0.2 candidate stays **HOLD** until all of the above are visible in production runtime source and real-path regressions, followed by exact-candidate Tests + Lanes, live Cloudflare parity on that exact SHA, and the finite physical iPhone field checks.

A green suite that does not assert these contracts is not evidence that these contracts are satisfied.
