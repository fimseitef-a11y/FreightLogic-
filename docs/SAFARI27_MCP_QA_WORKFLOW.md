# Safari 27 MCP — developer QA workflow (macOS)

Date: 2026-09-20
Issue: #204, the unchecked item *"Add Safari 27 MCP as a developer QA workflow on macOS
Safari 27 for real Safari DOM/network/console/screenshot inspection."*
Status: **runbook only.** Nothing here was executed. This repository's session environment is
Linux and has no Safari to drive, which is the same blocker recorded on #204 on 2026-09-17.

## What this is for, and the one thing it is not for

FreightLogic's automated gates run **headless Chromium**. Safari 27 shipped **525 fixes, 30 of
them SVG**, and WebKit characterises the release as existing features *behaving differently —
more correctly — than before* (`docs/IOS27_SAFARI27_ASSESSMENT_2026-09-15.md`). So there is a
whole class of defect — real WebKit rendering and real WebKit DOM behaviour — that **no gate in
this repository can currently see**. That is the gap this workflow addresses.

> **It cannot clear a single A-row.** Safari on macOS is not Safari on an iPhone: different
> engine build, no touch input, no installed-PWA storage partition, no safe-area insets, no
> software keyboard, no background GPS, no iOS permission revocation. `FIELD_TEST_CHECKLIST.md`
> **A1-A13** remains the operator's, on a physical device, and issue #204's own guardrail says
> not to infer PASS from desktop emulation. This workflow **finds** bugs; it **discharges**
> nothing.

Its value is ordering: a defect found here costs a Mac session, and the same defect found on the
device costs a device session the operator has deferred to the final post-v24.5 candidate.

## Provenance of the setup steps — read this before following them

This repository marks facts **PRIMARY** (stated by WebKit/Apple) or **SECONDARY**, because it was
burned once by secondary coverage: the widely-repeated claim that "iOS 27 adds background sync"
is false, and it is the one API that would have fixed FreightLogic's most-documented failure.

- **PRIMARY, confirmed:** Apple ships a first-party **Safari MCP server**, introduced in Safari 27
  beta / Safari Technology Preview 247. It connects an agent to a Safari window and exposes the
  **DOM, network requests, console output and screenshots**.
  Sources: [Introducing the Safari MCP server for web developers](https://webkit.org/blog/18136/introducing-the-safari-mcp-server-for-web-developers/),
  [Connecting an AI agent to Safari](https://developer.apple.com/documentation/safari-developer-tools/connecting-an-ai-agent-to-safari).
- **SECONDARY, unverified from here:** the exact enablement steps below. `webkit.org` is blocked
  by this environment's egress proxy and Apple's documentation page did not return a body, so the
  exact invocation could not be read from the primary source. **Confirm the three steps against
  the two links above before relying on them.** They are recorded as a starting point, not as
  verified fact.

### Setup (SECONDARY — verify against Apple's docs)

1. Safari → Settings → **Advanced** → enable *"Show features for web developers"*.
2. Safari → Settings → **Developer** → enable *"Allow remote automation and external agents"*.
3. Authorize the driver once: `sudo safaridriver --enable`, then register Apple's first-party
   server with your agent using **`safaridriver` with the `--mcp` flag**.

### Do NOT use a third-party Safari MCP package

Search results surface npm packages such as `safari-devtools-mcp`, commonly installed with
`npx -y …@latest`. **Do not use them for this workflow.** `npx -y …@latest` executes unpinned
third-party code that would then be driving a browser session against FreightLogic. This
repository removed the jsDelivr Tesseract fallback in v24.0.17 (#220) for exactly that reason —
unpinned third-party JavaScript sharing an origin with the operator's entire trip history,
expenses, receipts and stored cloud credential — and `script-src` is now `'self'` alone. Adopting
an unpinned third-party agent package to QA that same app would walk straight around the decision.
Apple's `safaridriver` is already on the machine and is first-party.

If this workflow is ever run against a **logged-in** profile rather than a clean one, treat the
session as touching real financial data and use a throwaway profile instead.

## What to check, and why each one is here

Run against the deployed origin `https://freightlogic-v2.fimseitef.workers.dev` at the current
generation. Every item below exists because a real defect in this repository's history is in that
class — not because it is a generic browser checklist.

### 1. SVG rendering — the reason A11 exists
FreightLogic draws hand-built SVG in two surfaces the driver looks at constantly: the **F31
Earnings Trends chart** (`<rect>` bars, `<polyline>` net overlay, `<text>` labels, explicitly "no
canvas") and the **driver tab-bar icons**. 30 SVG fixes landed in Safari 27. Screenshot both in
real Safari and compare against Chromium. *No existing gate asserts a pixel.*

### 2. Form controls do not zoom on focus
iOS Safari zooms when a focused control computes under 16px. v24.0.10 exists because two
evaluator controls carried inline `font-size:13px` and were invisible to every prior pass — they
sit behind **More Details**, so the three always-visible fields were fine while 33 others were
never measured. **Expand every disclosure before checking**, including More Details, the Settings
form, and the v24.0.25 More categories.

### 3. Customizable `<select>`
The `@supports (appearance: base-select)` enhancement must preserve option text, keyboard
navigation and VoiceOver semantics. There are **29 selects — 16 in `index.html` and 13 built
inside `app.js` via `innerHTML`**. The latter are not reachable from `styles.css` by id, so an
enhancement can look correctly applied while being half-applied. Exercise the app.js-built ones.

### 4. Accessible names and touch targets — v24.0.24 / #268
Header status elements must carry non-interactive status semantics (`#syncIndicator`,
`#cloudIndicator` were `aria-prohibited-attr` at *serious* impact on the live origin), the GPS
button `#mwGpsBtn` must be ≥44×44, and disclosure controls must expose keyboard semantics **and
state**. Real Safari + real VoiceOver is the check no headless run makes.

### 5. Console is clean across all five tabs
Today / Loads / Evaluate / Trips / Money, plus More. v24.0.8 shipped a **dead Loads tab** green
because the hash and the highlighted tab were both correct while the surface rendered nothing.
Assert rendered content, not the hash.

### 6. Network — no asset served as HTML
All **22** declared runtime assets load, and none is answered with `text/html`. That SPA-fallback
shape is the one where the browser silently refuses to execute a script: no 404, no console error,
the script just vanishes. The live parity gate checks this too; here you see it in WebKit.

### 7. Persisted storage grant
`requestPersistentStorage()` runs at boot. The open question the assessment records is whether
the grant is actually *given*. Read it from the Diagnostics panel.

### 8. Cloud-backup paused banner has not regressed
It must not auto-dismiss. An informational notice may vanish; *"you are not being backed up"* may
not (v24.0.6). CBP-07/08 assert the shape in Chromium; confirm it renders and behaves in WebKit.

### 9. v24.0.25 IA
More groups into named categories with all destinations reachable, Text Size and Glance Mode are
immediately reachable, and screenshot/paste/type intake are all visible.

## Recording results

Findings are **defect reports**, not certification evidence, and must not be written into a
certification-state document as observations. If something here fails:

1. it is a real bug — file it, with the Safari version and a screenshot;
2. the corresponding Chromium gate is *also* missing an assertion, and that gap is the more
   valuable finding. v24.0.24 exists because no gate in this repository had ever asserted a pixel
   or an accessible name;
3. a fix follows ordinary release discipline — lock, full suite, exact-head CI, generation bump if
   deployed bytes change, then re-dispatched live parity and production service-worker gates.

## Status of issue #204's item

This runbook is the repository-side half. The item stays **unchecked** until the workflow is
actually run on macOS with Safari 27, because an unexecuted runbook is not a QA workflow — the
same standard this repository applies to an unobserved gate, which is never recorded as passing.
