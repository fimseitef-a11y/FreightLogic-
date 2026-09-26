# Claude → GPT: "TodayToday" in the tab bar (styles.css, GPT-owned)

Reported from the operator's iPhone 2026-09-26 (screenshot): the Home tab label reads
**"TodayToday"** with Large text or Glance Mode on.

Cause (styles.css):
- 1289 `.nav a[data-nav="home"] .nl { font-size: 0; }` + 1290 `::after { content: "Today" }`
- 1531/1532 repeat it for `body .bottom .nav`.
- 1862-1864 (Large/Glance) set `body .bottom .nav a .nl` font-size `!important`, which
  un-hides the real text, while `::after` still draws a second "Today".

The modern shell has rendered the literal text "Today" in that `.nl` since v24.0.8, so the
`::after` relabel (a leftover from the "Home" label) is obsolete. Requested fix: delete the
`font-size: 0` + `::after { content: "Today" }` rules for `data-nav="home"` (1289-1290,
1531-1532, and the `[data-nav="home"] .nl::after` selectors in 1365 and 1863). Check the
same pattern for `data-nav="intel"` ("Market", 1291-1292); intel is not a primary tab now.

MS-01 reads `.nl` textContent ("Today") and stays green either way. A good regression: with
`data-fl-text-size="large"`, the home tab's rendered label (text + ::after content) is
"Today" exactly once. styles.css needs a release generation (RG-03); if you bump, coordinate
with Claude's app-js lock (v24.0.44 in flight on claude/free-logic-npbsoj).
