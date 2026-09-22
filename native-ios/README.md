# FreightLogic Apple Native Track

This directory is the bounded native Apple seam approved under GitHub issues #204 and #205. It is additive to the existing FreightLogic PWA; it is **not** a Swift rewrite and it does not own freight economics.

## Current status

The first native deliverable is a typed, fail-closed JS ↔ Swift bridge package that can be embedded by a future iOS host app. The package is deliberately useful before an Xcode app target exists:

- `FreightLogicNativeCore` defines the only native bridge action allowlist and JSON envelope types.
- `FreightLogicAppleBridge` provides a WebKit `WKScriptMessageHandlerWithReply` adapter when WebKit is available.
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

1. Only the exact `BridgeAction` enum may cross JS → Swift.
2. Requests are versioned, bounded to 64 KiB, and limited in nesting depth.
3. Credential-shaped payload keys (`token`, `adminToken`, `driverToken`, `bearerToken`, `authorizationHeader`, `password`, `passphrase`, `appLockPin`, `adminPin`, `secret`, `apiKey`, etc.) are rejected recursively.
4. The WebKit adapter accepts only the main frame and an exact injected origin allowlist.
5. The native host injects environment-specific allowed origins; no production credential or host secret is compiled into the package.
6. Missing values remain missing/null. In particular, unknown deadhead must never become zero in the native layer.
7. No arbitrary native method invocation and no arbitrary JavaScript evaluation API is exposed by this package.

## Native action catalog — contract v1

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

The future App Intents layer should map Siri/Shortcuts language to this small catalog rather than inventing a second action model.

## Apple capability sequence

### Phase 0 — landed by this package

- typed bridge envelope and origin policy;
- WebKit reply-handler adapter;
- macOS SwiftPM CI;
- Safari MCP real-browser runbook.

### Phase 1 — requires a Mac with current Xcode / iOS 27 SDK

**Current CI gate:** PR #321's macOS runner reported Xcode 26.6 / Swift 6.3.3. Apple now deprecates `openAppWhenRun` in favor of iOS 27 `supportedModes`, so the real App Intents conformances are intentionally not authored against the older SDK. The framework-independent action/execution policy is implemented first; App Intents code waits for an Xcode 27-capable compiler so the current API is compiled rather than guessed.

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
