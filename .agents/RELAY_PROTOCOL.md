# Agent relay protocol — ChatGPT-primary coordination

**Standing instruction from the repository owner, updated 2026-09-27.**

ChatGPT/GPT is the primary coordinator and implementation lane for FreightLogic. The former automatic Claude ↔ ChatGPT usage-limit relay is superseded. Work must not wait for Claude, route to Claude automatically, or treat Claude availability as a prerequisite.

## Continuation order

When continuing work:

1. Refresh current GitHub `main` and the newest relevant Airtable/FreightLogic coordination checkpoint.
2. Read only the minimum current governance and task state needed to avoid collision.
3. Continue the latest verified unfinished task instead of restarting completed work.
4. Use the `gpt` lane for repository writes unless the operator explicitly authorizes a different bounded writer.
5. Keep SHARED-path locking, exact-head CI, testing, privacy, security, and approval gates unchanged.

## Specialists

Grok or another specialist may be used for bounded read-only review, research, or coordination when useful, but specialist output is advisory until ChatGPT reconciles it against primary evidence. A specialist is not a blocking dependency.

Claude has no active role by default. A future Claude session may participate only when the operator explicitly reauthorizes a bounded task and current governance records that authority. Historical Claude commits, notes, branches, and inbox records remain valid provenance; they are not current ownership.

## Handoff discipline

Before ending substantive work, the active writer should leave recoverable state:

- commit and push safe repository work;
- record what is verified, what remains, and the exact next action in the appropriate coordination system;
- release any live lock it owns;
- never report a test, deployment, payment, approval, or certification as complete without evidence.

Usage limits are not a reason to hand work to Claude automatically. If ChatGPT cannot continue a step, record the specific blocker and preserve state for the next authorized ChatGPT session.

## What does not change

- `/.agents/LANES.md` remains the path-ownership source of truth.
- SHARED paths require the lock protocol in `/AGENTS.md`.
- Commit prefixes must identify the actual writer.
- Tests and release/certification gates remain evidence-driven and fail closed.
- Production deployments, credential/security changes, external sends, binding freight actions, and shared/family-PC access remain separately approval-gated.
