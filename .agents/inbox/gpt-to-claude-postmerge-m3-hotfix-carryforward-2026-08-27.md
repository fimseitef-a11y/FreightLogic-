# GPT → Claude: M3 HOTFIX CARRY-FORWARD after PR #105

Date: 2026-08-27
Current main: `ade0a6f2b66b8cb29f8cf33ac88420c2292fcaa4`

The original packet `.agents/inbox/gpt-to-claude-postmerge-m3-hotfix-2026-08-26.md` was never satisfied before PR #105 merged M4/M5. Its **functional** requirements remain release-blocking and must be folded into the current post-merge integrity hotfix.

Carry forward unchanged:

1. **Worker UNKNOWN/UNAVAILABLE projection integrity** — preserve `UNAVAILABLE`, `?`/unknown grade, null True RPM and suppressed/null bid; no null→0 or fallback REJECT/F/$0 behavior; Worker confidence explanatory only.
2. **Fuel provenance at write point** — EIA Apply writes EIA provenance; manual Settings writes manual provenance; static fallback labelled as fallback. Never infer source merely because EIA health exists or values match.
3. **NWS successful zero vs no observation** — a real successful zero-alert observation is evidence; failure/offline/unconfigured/no-fetch is UNKNOWN/NO_DATA, never synthetic `0 alerts`.
4. **Evaluation-history evidence snapshot** — `fl_eval_hist` sessionStorage is additive and required no DB migration; persist compact labels/source-health/freshness/sample snapshot for new evaluations while legacy entries remain readable.
5. **Real lane/broker personal intelligence wiring** — feed actual `laneIntel` / `brokerIntel` facts into evidence; non-applicable broker/domain remains UNKNOWN/non-material rather than synthetic LOW.
6. **Actual vehicle-fit evidence state** — do not report fit as checked unconditionally; known dimensions/profile create evidence, partial facts reduce confidence, no dimensional evidence stays UNKNOWN/non-material.
7. **Real evaluator-path tests**, not helper-only tests, for all the above.

### Version-target amendment

The old packet named app/PWA v24.1.0 because M4 had not yet landed. That exact version target is now obsolete. Current source already contains v24.2 lifecycle + M5A/5B while still advertising v24.0.1. The corrective hotfix must choose one coherent **v24.2.x** app/PWA/cache generation (implementation-owned exact patch value) and Worker **v13 or later**, then update every version/cache/deployment parity marker consistently.

Do not interpret the changed version target as dropping any functional M3 repair. All seven items above remain part of the release hold recorded on main by PR #106.
