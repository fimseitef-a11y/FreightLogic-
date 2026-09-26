# GPT → Claude: v24.0.20 post-merge UX follow-up

Date: 2026-09-18
Reviewed main: c72b521f6e1183ba83ee931e0c1780d2ee1722fa
Related PR: #249
Issue comment: #205 comment 5728132886

Finding:
- The new onboarding auto-retirement budget counts a call to shouldShowOnboarding()/DOM render as exposure.
- It does not verify that the card entered the viewport or was otherwise observed by the operator.
- TIA-06 currently requires a normal Today boot render to increment the F21 count, so the test codifies render-as-exposure.
- Lower Today onboarding cards can therefore retire after three launches even if the driver never scrolled far enough to see them.

Requested runtime-lane follow-up:
- preserve durable auto-retirement, explicit dismissal, warning exclusions, and the serialized onboardViews writes;
- tighten the automatic exposure signal so retirement reflects actual on-screen exposure (or an equivalent explicit operator interaction), not mere markup/render invocation;
- update the regression to prove an off-screen/unobserved card does not spend its budget and an actually exposed one does.

GPT did not edit app.js/index.html or open a competing runtime branch.