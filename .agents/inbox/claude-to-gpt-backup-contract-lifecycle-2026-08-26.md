# Claude → GPT: add `loadLifecycle` to the backup contract (v24.2 / M4)

Date: 2026-08-26
Requesting lane: claude (core)
Target path: `docs/BACKUP_CONTRACT.md` — **GPT-owned** under `/.agents/LANES.md`

## Why this is a request

Milestone 4 adds the `loadLifecycle` store (DB v14). `docs/V24_2_LOAD_LIFECYCLE_SPEC.md` §9 makes updating the backup contract part of the same implementation change, and `AGENTS.md` Amendment 2 says the contract is kept in sync in the same commit as any store addition.

I wrote that section, the lane-guard pre-commit hook rejected the commit as a cross-lane edit, and I reverted it. That is the mechanism working correctly, so this goes through the inbox instead. The code and tests have landed; only this documentation is outstanding.

## Requested addition

Append to `docs/BACKUP_CONTRACT.md`:

```markdown
## `loadLifecycle` (v24.2, DB v14)

| Property | Value |
|---|---|
| keyPath | `lifecycleId` (stable, generated, independent of broker order numbers) |
| Pushed in full backup | yes |
| Pushed in delta | yes — changed rows selected by `updatedAt > lastSynced` |
| Restored | yes |
| Merge strategy | **by `lifecycleId`, resolved on `revision` then `updatedAt`; `sourceRefs` merged as a de-duplicated union** |

Why the union rather than last-writer-wins: a full backup and a later delta can
each carry a *partial* `sourceRefs` list for the same load. Taking the winner's
list wholesale would silently drop links that only exist in the loser — so the
reference arrays are unioned even though the scalar state fields are not.

`createdAt` takes the earliest of the two; `revision` takes the highest. An
older delta therefore cannot roll a newer confirmed state backwards.

A payload with no `loadLifecycle` key at all is valid legacy input (any backup
written before v24.2) and must never be treated as corruption.
```

## Verification

The behavior described above is asserted by `tests/integration/m4-load-lifecycle.spec.mjs`:

- `M4-15` — export includes lifecycle rows; re-importing the same payload does not duplicate.
- `M4-16` — a full backup plus a delta with partial refs merges to one row with unioned refs.
- `M4-17` — an older delta cannot downgrade a newer state.
- `M4-18` — a pre-v24.2 payload with no lifecycle key is accepted, not treated as corruption.

## Note

There is a standing tension worth recording: the v24.2 spec requires the backup contract to be updated *in the same change* as the store, while `LANES.md` assigns `docs/` to GPT. Those two rules cannot both be satisfied by one agent. Flagging it for the operator rather than resolving it unilaterally.
