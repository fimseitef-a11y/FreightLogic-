# FreightLogic Test Ledger

Live execution ledger. This file lives on `agent-coordination` and is never merged to `main`. Log observed runs only; never infer a result from history.

BASELINE: PENDING — requires Claude Code execution

## Required baseline command

`node tests/run-all.mjs`

## Required run fields

- UTC timestamp
- exact tested SHA
- command / relevant environment
- result: pass/fail totals and spec count
- every failing suite/test when red
- duration if observed
- rerun trigger/reason when a rerun occurs

Historical note only, **not a current baseline**: v24.0.0 release commit `5dddefbc9dbef0a586bd60d9d1bd787ec5aaf8f5` recorded 119 passed / 0 failed across 19 spec files on its final PR head.
