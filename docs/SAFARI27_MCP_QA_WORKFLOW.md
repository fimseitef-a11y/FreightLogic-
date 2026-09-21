# Safari 27 MCP — developer QA workflow on macOS

Date: 2026-09-21
Issue: #204
Status: **Runbook only; Safari execution NOT RUN.** The continuation environment is Linux.

This continues the runbook in Claude draft PR #282. It complements the existing Chromium
suite with actual macOS Safari DOM, network, console and rendering observations. It cannot
certify the installed iPhone PWA, software keyboard, safe areas, background GPS, permissions,
or Safari-to-Home-Screen storage behavior. Physical A1-A13 stays separate and deferred.

## First-party setup, verified against WebKit on 2026-09-21

WebKit documents the server for Safari 27 beta and Safari Technology Preview 247. Record
the actual installed Safari/macOS versions and verify that build supports the server.

1. In Safari Settings, enable developer features under Advanced, then enable remote
   automation/external agents under Developer.
2. Configure the MCP client to launch `/usr/bin/safaridriver` with argument `--mcp`.
   For Technology Preview, use its bundled driver instead:
   `/Applications/Safari Technology Preview.app/Contents/MacOS/safaridriver`.
3. Reconnect the client, open an isolated test session and inspect the target tab.

Example for Claude Code:

```sh
claude mcp add safari-mcp -- /usr/bin/safaridriver --mcp
```

The original draft's `sudo safaridriver --enable` step is removed: WebKit's MCP instructions
do not require it. Follow the installed build's official instructions if setup differs.

Source: [WebKit's Safari MCP setup](https://webkit.org/blog/18136/introducing-the-safari-mcp-server-for-web-developers/).
Apple also maintains [Connecting an AI agent to Safari](https://developer.apple.com/documentation/safari-developer-tools/connecting-an-ai-agent-to-safari);
that page's body was not available to this continuation, so the concrete steps above are
verified from WebKit. No third-party npm server is needed.

## Safe test setup and evidence

Use a clean test profile and synthetic fixtures. Do not load operator trip history or expose
credentials in screenshots, console output or reports. Run against
`https://freightlogic-v2.fimseitef.workers.dev`, after confirming the source and live generation.
Record the exact app/SW/Worker versions, source SHA, Safari/macOS versions, launch context,
fixture and steps with each result. A connection or setup failure is BLOCKED, not a test pass.

## App-specific checks

1. **SVG rendering.** Inspect the F31 Earnings Trends chart and the five navigation icons.
   Capture Safari screenshots with fixed synthetic data and compare with Chromium. Record
   actual rendering differences; do not assume each difference is necessarily a defect.
2. **Form sizing.** Expand every disclosure, including evaluator More Details and advanced
   Settings. Check computed font sizes and layout for dynamically created controls too.
   A macOS measurement can find sizing defects, but cannot prove iPhone zoom-on-focus behavior.
3. **Customizable select controls.** Check both static and app.js-created controls, including
   option text, keyboard selection, VoiceOver names and fallback when base-select is unavailable.
   Their dynamic creation does not exclude them from CSS selectors.
4. **Accessibility and targets.** Check header status semantics, GPS target dimensions,
   accessible names and keyboard/state semantics on disclosures. Record real macOS VoiceOver
   observations separately from the physical iPhone's VoiceOver result.
5. **Navigation.** Exercise Today, Loads, Evaluate, Trips and Money, then the header More
   button. Check visible content and actual controls, not only the URL hash or active tab.
6. **Network.** Derive the asset list from `scripts/lib/deploy-assets.mjs`; every declared
   runtime asset must load with the expected content type. An HTTP 200 HTML fallback for a
   script is a failure even if a shallow status check would accept it.
7. **Persistence.** Read persistent-storage state in Diagnostics and record the observed
   result. A desktop grant does not establish the installed iPhone PWA's storage behavior.
8. **Cloud-backup paused banner.** With synthetic state, confirm the warning remains visible
   until its underlying condition changes; informational onboarding dismissal must not hide it.
9. **Driver IA and screenshot intake.** Check all More destinations, display settings and
   screenshot/paste/type entry points. An absent deadhead must remain UNKNOWN and require
   review; explicit zero and user corrections must survive. Report live-provider availability
   separately from browser UI behavior and from real-image extraction accuracy.

## Recording and closure

Save findings with reproducible steps and the environment identity. A Safari-only defect may
need a Safari regression; it does not automatically mean a Chromium assertion is missing.
Repairs follow AGENTS.md, ownership/locks, existing regression and release-generation gates.

These results may support a dated Safari QA evidence record when actually observed, but may
never auto-pass physical A1-A13. Keep #204's Safari-workflow item unchecked until the workflow
has run successfully and its evidence is recorded. This document alone does not close it.
