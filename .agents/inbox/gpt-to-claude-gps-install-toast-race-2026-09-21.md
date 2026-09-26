# GPS-loss reassurance vs service-worker installation toast

Found during documentation-only PR #288, exact head 89437842064f8f56bd37bb295bbe3009f3e1d316. Tests run 35556446150 attempt 1, job 106200882080: **740/1 across 72 specs**, only F-7 sustained GPS signal loss failed at tests/integration/field-resilience.spec.mjs:489.

Observed: trip card said Trip in progress + GPS signal lost — searching; Stop & Save remained reachable. #toast instead said "FreightLogic 24.0.26 installed." The CI diagnostic refers to a different tracked app page for its #224 lifecycle message; that alone does not prove the GPS test page reloaded. Do not classify this as db-null or lost-trip evidence.

Source trace: app.js:1163 toast replaces the single toast content; app.js:22249 emits GPS signal loss / still tracking; app.js:23780 unconditionally emits installed text on SW_ACTIVATED. Test waits 1500ms then asserts last toast. Potential actual notification-priority collision or test lifecycle ordering, not attributable to LANES.md edit. Do not weaken the assertion or dismiss as a known flake without reproduction.

No runtime/test bytes differ from green main d35ba266 (741/0). Focused unchanged local Chromium run passed 13/0. One controlled full-suite CI rerun requested per AGENTS.md; record its result, but a pass is not a fix. Owning lane should diagnose delayed activation-message ordering, then decide whether product notification priority or test readiness is the correct repair. GPT's bounded grant covers release documentation only and does not authorize a test/runtime repair.
