# Safari 27 MCP QA Runbook

Safari 27 ships a local MCP server through `safaridriver`. This is the correct real-Safari QA path for FreightLogic when a macOS Safari 27 machine is available. It complements, but does not replace, the physical Home Screen PWA A1–A13 run.

## One-time Mac setup

1. Update the Mac to Safari 27.
2. In Safari Settings → Advanced, enable the developer features pane if it is hidden.
3. In Safari Settings → Developer, enable **Allow remote automation and external agents**.
4. Register Safari MCP with the coding agent by launching `/usr/bin/safaridriver --mcp` through that agent's MCP configuration.

The Safari MCP server is local to the Mac. Do not copy FreightLogic credentials into MCP configuration or test prompts.

## FreightLogic QA matrix

Use a disposable test identity/data set unless the check explicitly requires the operator's production state.

For both dark and light themes, inspect at least:

- Today
- Loads / intake
- Evaluate / review / decision card
- Trips
- Money
- More / Settings

Record DOM, computed layout, console, network, and screenshots at representative iPhone widths (320, 390/393, and 430/440 CSS px). Confirm Safari's form focus behavior does not zoom controls and that touch targets/layout remain usable.

## Safari 27-specific checks

- Customizable select: verify real `<select>` behavior remains keyboard/VoiceOver/form compatible with `appearance: base-select` enhancement.
- Scroll anchoring: inject/load content above the current viewport and confirm the user's reading position remains stable; FreightLogic should not globally opt out with `overflow-anchor: none`.
- Storage/IndexedDB: exercise reload/relaunch-sensitive paths and watch for console/storage errors, especially around database upgrade/abort behavior.
- SVG/chart/icon rendering: visually compare earnings chart and driver navigation icons after Safari 27's large SVG-quality update.
- CSP/network: verify no unexpected executable origins or HTML-for-script fallback; compare against production parity expectations.
- Accessibility: inspect labels, roles, contrast, focus order, and keyboard activation on all interactive surfaces.

## Evidence boundary

Safari MCP can prove real Safari DOM/network/rendering behavior on the Mac. It **cannot** certify:

- installed iPhone Home Screen PWA safe areas or software keyboard behavior;
- real iPhone GPS/background/location permissions;
- Safari ↔ Home Screen storage partition behavior;
- iOS camera/Photos/Files controls;
- A1–A13 physical-device rows.

Keep those as explicit physical-iPhone observations in issue #226.
