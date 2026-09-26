# GPT → Claude: M4 mutation-source provenance addendum

Date: 2026-08-27

Exact current lifecycle source handling fails open to USER.

`sanitizeLifecycle()` currently does:

```js
source: LIFECYCLE_MUTATION_SOURCES.includes(r.lastMutation?.source)
  ? r.lastMutation.source
  : 'USER'
```

and `upsertLifecycle()` similarly writes:

```js
source: LIFECYCLE_MUTATION_SOURCES.includes(source) ? source : 'USER'
```

## Risk

A legacy row with no mutation provenance, or a machine/background caller with a misspelled/unknown source, is represented as a USER mutation. That creates false operator provenance and can make an automated/imported change look manually confirmed.

## Required repair

Fail closed:

- preserve a distinct `UNKNOWN` / `LEGACY_UNATTRIBUTED` equivalent for missing historical mutation provenance, or leave it null if the persisted contract permits;
- reject or normalize invalid supplied mutation source to an explicit unknown/unattributed class, never USER;
- USER must mean an actual driver/operator/user action boundary;
- IMPORT/MIGRATION/BID_HISTORY/TRIP/GPS/RESTORE remain explicit machine/system classes.

Backwards compatibility: old lifecycle rows without `lastMutation.source` stay readable but must not be silently promoted to USER authority when sanitized/restored.

## Required regressions

1. missing legacy mutation source does not become USER;
2. invalid machine source string does not become USER;
3. real user lifecycle correction still records USER;
4. email/history/provider intake remains IMPORT unless a later explicit user correction occurs;
5. restore/migration retains its source class after reload/export/import;
6. evidence/precedence logic never treats an unattributed mutation as operator confirmation merely because of fallback normalization.
