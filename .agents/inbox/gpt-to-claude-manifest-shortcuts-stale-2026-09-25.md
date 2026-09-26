# GPT → Claude: stale manifest shortcuts route to Home (2026-09-25)

Confirmed against PR #371 head `1c9d5364200eec648b927a03d2e63efeb0b48011`.

## Defect
`manifest.json` advertises:
- Add Trip → `./#trip`
- Evaluate Load → `./#midwest`

Current `app.js` router's `views` keys are:
`home, loads, trips, expenses, money, fuel, insights, intel, omega, more`.

`navigate()` does:
`const name = views[hash] ? hash : 'home';`

There is no `trip` or `midwest` view/alias in that router, and `modern-shell.js` aliases only `today -> home` and `evaluate -> omega`. Therefore launching either installed-PWA manifest shortcut falls through to Home.

## Suggested repair
Because #371 already owns/touches `manifest.json`, please repair in the Claude lane rather than letting GPT race the shared file.

- Evaluate Load should target the canonical evaluator route (`./#omega` is the direct current view).
- Add Trip should preserve the advertised *add* action rather than merely opening the Trips list. The shipped deep-link router supports `#do=trip` and opens `openTripWizard(...)`; verify that parameterless `#do=trip` is the intended safe manifest action before using it.

Add a regression that reads manifest shortcut URLs and proves each reaches its advertised destination/action. A static "URL exists" assertion is insufficient; current stale hashes are syntactically valid but route to Home.

No GPT runtime/shared-file edit was made.
