# Apple SDK / hardware gates

This file separates source work that can be validated today from Apple-only evidence that must not be inferred.

## Observed CI toolchain

PR #321's `macos-latest` native job reported:

- Xcode 26.6
- Swift 6.3.3

That runner is sufficient to compile the current SwiftPM bridge and WebKit adapter, but it is not an iOS 27 SDK authority.

## Xcode 27 gate

The following work must be compiled and tested with Xcode 27 before it is treated as implemented:

- App Intents using `supportedModes` rather than deprecated `openAppWhenRun`;
- iOS 27 App Intents execution-mode/system-context behavior;
- Foundation Models image input and Vision OCR tool calling introduced/updated for iOS 27;
- any new iOS 27-only App Intents schemas or Apple Intelligence integration;
- final native host target, signing, entitlements, and device deployment.

Do not bypass this gate by writing against deprecated compatibility APIs merely because the current CI image is older.

## Real macOS Safari 27 gate

Safari MCP requires a real Mac with Safari 27 and `/usr/bin/safaridriver --mcp`. See `SAFARI_MCP_RUNBOOK.md`.

GitHub's SwiftPM compile job is not Safari MCP evidence.

## Physical iPhone gate

The existing field certification issue #226 remains the authority for A1-A13. Native work does not auto-pass any row.

## Current safe work

Until the Xcode 27 runner is available, the repo may continue to build and test:

- typed bridge envelopes;
- exact action allowlists;
- native execution/privacy policies;
- WebKit origin/frame restrictions that compile under the available SDK;
- framework-independent data contracts;
- documentation/runbooks for later Apple-only validation.

This keeps progress real without treating uncompiled Apple APIs as complete.
