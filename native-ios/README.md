# FreightLogic Apple Native Track

This directory is the bounded native Apple seam approved under GitHub issues #204 and #205. It is additive to the existing FreightLogic PWA; it is **not** a Swift rewrite and it does not own freight economics.

## Current status

The first native deliverable is a typed, fail-closed JS ↔ Swift bridge package that can be embedded by a future iOS host app. The package is deliberately useful before an Xcode app target exists:

- `FreightLogicNativeCore` defines separate native→web freight actions and web→native capability envelopes.
- `FreightLogicAppleBridge` provides a narrow WebKit capability handler plus a fixed native→web FreightLogic action dispatcher when WebKit is available.
- `FreightLogicNativeHost` builds the persistent `WKWebView` host boundary and exact-origin navigation policy.
- Swift tests pin the action set, UNKNOWN/null preservation, credential-key rejection, request size/depth limits, contract versioning, and exact-origin matching.
- `.github/workflows/native-ios.yml` runs the package on a macOS runner so the real WebKit code path is compiled, while ordinary non-Apple hosts can still test the core contract.

This scaffold does **not** claim an App Store app, signed build, entitlement, real Safari session, Siri execution, Live Activity, push notification, or physical-iPhone certification.

## Authority boundary

FreightLogic's existing web/core remains authoritative for:

- loaded/deadhead/total miles and UNKNOWN semantics;
- True RPM, operating cost, profit, grade, verdict, and bid guidance;
- trip/payment lifecycle truth;
- persistence, sync, and the canonical Load Evaluator.

Native code may collect input, expose Apple system surfaces, and request a canonical FreightLogic action. It must not independently reproduce or override the deterministic freight engine.

## Bridge security contract

The bridge is intentionally narrow:

1. Freight actions (`evaluateLoad`, `addTrip`, `markPaid`, and the rest of the canonical catalog) travel **native → web/core** only; the native layer never evaluates them itself.
2. The **web → native** message handler currently accepts only the `capabilities` handshake. Native capabilities expand deliberately as Apple-only features land; freight decisions never move into that channel.
3. Requests are versioned, bounded to 64 KiB, and limited in nesting depth.
4. Credential-shaped payload keys (`token`, `adminToken`, `driverToken`, `bearerToken`, `authorizationHeader`, `password`, `passphrase`, `appLockPin`, `adminPin`, `secret`, `apiKey`, etc.) are rejected recursively.
5. The WebKit capability adapter accepts only the main frame and an exact injected origin allowlist.
6. The native host injects environment-specific allowed origins; no production credential or host secret is compiled into the package.
7. Missing values remain missing/null. In particular, unknown deadhead must never become zero in the native layer.
8. Native→web dispatch calls one fixed page contract, `window.FreightLogicNativeActions.handle(request)`. If that canonical PWA handler is absent, dispatch fails closed with `notReady`; it does not guess a result or execute caller-supplied JavaScript.

## Native → FreightLogic web action catalog — contract v1

Read / decision requests:

- `evaluateLoad` — route input to the existing canonical evaluator; native code does not compute the verdict.
- `accountsReceivable`
- `trueRPM`
- `bestMove`

Mutations that must ultimately execute through FreightLogic's canonical state path:

- `addTrip`
- `addExpense`
- `addFuel`
- `markPaid`
- `startTrip`
- `pickup`
- `delivered`

The future App Intents layer should map Siri/Shortcuts language to this small catalog rather than inventing a second action model. The current PWA does **not yet** expose the fixed `FreightLogicNativeActions.handle` page contract, so native freight-action dispatch is intentionally `notReady` until a separately locked/tested web-core integration lands.

## Apple capability sequence

### Phase 0 — landed by this package

- typed directional bridge envelopes and origin policy;
- WebKit capability reply-handler adapter;
- fixed native→web action dispatcher that fails closed until the PWA handler exists;
- persistent WebKit host + exact-origin main-frame navigation gate;
- macOS SwiftPM CI;
- Safari MCP real-browser runbook.

### Phase 1 — requires a Mac with current Xcode / iOS 27 SDK

Create the thin host app and validate the bridge inside a `WKWebView`. Add App Intents for the action catalog and use App Intents Testing to exercise them through system pathways. Mutating intents must preserve confirmation/foreground requirements appropriate to the action.

### Phase 2 — native intake assistance

Use Vision/Foundation Models image tooling for screenshot, rate-confirmation, BOL/POD, and receipt extraction only. Native extraction returns reviewable observational fields; the canonical web evaluator still decides economics. Keep the existing Worker vision path as a supported cross-platform option.

### Phase 3 — glanceable Apple surfaces

Add Core Spotlight indexing for safe entities, then ActivityKit/Live Activities and push/notification actions for active-trip state where useful. Avoid indexing broker-sensitive or financial detail that is not needed for discovery.

### Phase 4 — real Apple certification

- Safari 27 MCP QA on macOS Safari 27;
- Xcode build/sign/entitlement verification;
- real Siri/App Intents/Spotlight/Live Activity tests;
- physical iPhone A1–A13 through the existing field-certification runner.

None of those gates can be promoted to PASS from Chromium, Linux SwiftPM, or source inspection.

## Validation

Non-Apple contract validation:

```sh
swift test --package-path native-ios
```

The GitHub macOS workflow runs the same package while compiling the WebKit branch. A future Xcode application target should add App Intents Testing and device/UI tests rather than weakening these package tests.
