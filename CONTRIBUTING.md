# Contributing to FreightLogic

FreightLogic is a governed, multi-agent repository. Read `AGENTS.md` and `.agents/LANES.md` before changing anything.

## Workflow

1. Work only in paths owned by your lane. `SHARED` paths require the lock protocol in `AGENTS.md`.
2. Use an approved branch namespace: GPT uses `agent/gpt/<task>` or `chatgpt/<task>`; Claude uses `agent/claude/<task>` or `claude/<task>`.
3. Prefix commits with the matching agent prefix (`[gpt]` or `[claude]`). Do not force-push.
4. Preserve existing behavior unless the task explicitly changes it. Never convert unknown freight data to zero or weaken tests to obtain a green run.
5. Run the required regression gates. Any `app.js`, service-worker, storage/IndexedDB, or integrated behavior change requires the full suite.
6. Open a focused PR. Merge only after required Tests, Lanes, and CodeQL checks are green and any release-specific evidence is complete.

## Coordination

Live locks, status, test ledger, and cross-lane requests live on the `agent-coordination` branch and are never merged to `main`. Use `/.agents/inbox/` when another lane owns a required change.

Repository documentation is not a substitute for physical-device certification. Hardware-only iPhone checks must remain explicitly separate from automated browser and CI evidence.
