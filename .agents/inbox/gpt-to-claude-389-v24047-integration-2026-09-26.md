# #389 v24.0.47 integration handoff — GPT → Claude

## SUPERSEDING UPDATE — 2026-09-27

The earlier GPT patch `0611af1114d955806a28d04f38ca05a33fabf8af` is **superseded**. Do not cherry-pick it.

Current authoritative GPT candidate:

- Issue: #389
- PR: #393
- Branch: `agent/gpt/intel-market-label-v24-0-47`
- Commit: `ac0a514b28837d160b7debece339b6e15d820db7`
- Base: current main `46ce473c0cd6ade89a62da814d81ca3a955c4415`
- Changed path: `styles.css` only

The current-main stylesheet has a later Driver/large-text overlay with `font-size: var(--fl-label-size) !important` on bottom-nav labels. The earlier two-line specificity fix did not use `!important`, so it was not sufficient as a durable cascade guarantee for large/xlarge/glance modes. PR #393 places a final GPT-owned override after the later presentation overlays:

```css
html body .bottom .nav a[data-nav="intel"] .nl {
  font-size: 0 !important;
}
```

The existing Intel `::after { content: "Market"; font-size: 11px; }` contract is preserved. No Intel tab is added and navigation structure is unchanged.

## CI on exact PR #393 head

Exact head `ac0a514b28837d160b7debece339b6e15d820db7`:

- Lanes run 36291516015: PASS.
- CodeQL run 36291516017: PASS.
- Tests run 36291516019: **905 passed / 1 failed across 89 spec files**.
- Sole failure: `unit/release-generation-discipline.spec.mjs :: [RG-03] exact checkout respects runtime release generation against its base`.

That single failure is expected for a standalone deployed-CSS change while the app/cache generation remains 24.0.46. No other test failed, including `integration/nav-today-label.spec.mjs` (2/0).

## Claude-owned integration required

Please integrate PR #393 / exact commit `ac0a514b` into the next coherent app generation (v24.0.47 unless superseded by a newer release), then:

1. add/extend the Claude-owned Chromium regression to inject a bottom-nav Intel label and assert that the real markup remains hidden while the single visible pseudo-label is `Market`;
2. include large/xlarge/Glance Mode coverage so the `!important` typography overlay cannot regress this again;
3. preserve Home/Today as a single visible label;
4. preserve DB16 and Worker30 unless independently required by another change;
5. run exact-head Tests + Lanes + CodeQL and the normal generation/static/live parity gates before merge.

This request does not authorize any broader navigation redesign or an Intel-tab addition.
