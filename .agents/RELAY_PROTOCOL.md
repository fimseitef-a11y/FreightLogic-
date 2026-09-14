# Agent relay protocol — handing work over at a usage limit

**Standing instruction from the repository owner (2026-09-14).** This is not a
one-off request in an inbox; it applies to every session from now on, and both
lanes are expected to read it before picking work up.

## The rule

Work on this repository alternates between two agents whenever one runs out of
usage:

1. **Claude** works until its usage limit is reached and it stops coding.
2. **ChatGPT (the `gpt` lane) takes over at that point** and continues the work
   in progress, until *its* own limit is reached.
3. **Claude takes over again**, and so on.

Neither agent waits to be asked each time. A limit being reached IS the handoff
signal. The owner should not have to relay it by hand.

## What "take over" means

Take over the work that was actually in flight, not a fresh idea:

- Read `CLAUDE.md` first — it is the running architecture/decision record and
  the top section describes the current release state.
- Read the most recent release/certification documents under `docs/` for what
  is open. `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md` is the canonical
  roadmap; the newest `COMPLETION_RELEASE_CERTIFICATION_*` file is the current
  certification state.
- Check `/.agents/inbox/` on the `agent-coordination` branch for cross-lane
  requests that are still open, and check the branch the other agent was last
  pushing to (`git log --oneline -20`) for work that stopped mid-stream.
- Finish what is unfinished before starting anything new. If the previous agent
  left a spec failing, a control unverified, or a commit unpushed, that is the
  first item — not a clean-slate task.

## What does NOT change at a handover

The relay changes **who is typing**. It changes nothing else:

- **Path ownership still applies.** `/.agents/LANES.md` is the single source of
  truth and is enforced by `.githooks/pre-commit` and
  `.github/workflows/lanes.yml`. Taking over Claude's work does not grant the
  gpt lane Claude-owned paths, or the reverse. If the work in flight needs a
  foreign path, file a request under `/.agents/inbox/` and do the rest.
- **`app.js`, `index.html`, `service-worker.js`, `manifest.json`,
  `modern-shell.js`, `sw-bridge.js` stay SHARED** and still require the lock
  protocol in `/AGENTS.md`. A handover is not a lock.
- **Commit prefixes stay honest.** `[claude]` or `[gpt]` reflects who actually
  wrote the commit, so the history still shows which lane did what.
- **The full test suite still gates everything**: `node tests/run-all.mjs`, and
  a negative control for every new assertion. An agent picking up mid-task must
  re-run the suite rather than trusting the previous agent's last reported
  total.
- **Release-marker discipline is unchanged** — the version-bump checklist in
  `CLAUDE.md` applies to whoever ships the release, and a handover mid-release
  is exactly when a marker gets missed.

## Leaving the baton where it can be picked up

Before stopping — whether at a limit or not — the outgoing agent should leave
the work recoverable:

1. **Commit and push.** Uncommitted work in a container that gets reclaimed is
   gone, and the next agent cannot continue what it cannot see.
2. **Say what is done and what is next**, in the commit message or in a short
   note under `/.agents/inbox/`. "Finished X; Y is written but its negative
   control has not been run" is what makes a handover cheap.
3. **Do not leave a green claim you did not verify.** If the suite was not run,
   say it was not run. The next agent will build on whatever the last one
   asserted, so an unverified "all green" costs more than an honest "unknown".

## Note for the gpt lane specifically

The owner has asked for this relay to be automatic. If you are reading this
because Claude stopped at a limit: pick up the in-flight work described above,
keep to your lane, and push. When your own limit is reached, leave the same kind
of note, and Claude will pick it back up.
