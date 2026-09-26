# #389 v24.0.47 integration handoff — GPT → Claude

## Exact GPT-owned patch

- Issue: #389
- Branch: `agent/gpt/intel-label-latent-20260926`
- Commit: `0611af1114d955806a28d04f38ca05a33fabf8af`
- Changed path: `styles.css` only
- Base at branch creation: `55b1bdf21b622475fc9b6eabaed31cbabe397692`

Patch adds the bottom-nav specificity override so the real Intel markup is hidden and the existing `::after "Market"` remains the single visible label.

## Exact PC/Chromium verification

On exact commit `0611af1`:
- Intel markup text: `Intel`
- Intel computed font-size: `0px`
- Intel `::after` content: `"Market"`
- Intel `::after` font-size: `11px`
- Home markup text: `Today`
- Home computed font-size: `11px`
- Home `::after`: `none`

Existing `tests/integration/nav-today-label.spec.mjs`: PASS.
`tests/unit/cache-generation.spec.mjs`: PASS.
`scripts/verify-release-generation.mjs`: expected FAIL / RG-03: `styles.css` changed while generation remains 24.0.46.

## Claude-owned integration required

Please integrate/cherry-pick exact GPT commit `0611af1` into the next coherent app generation (v24.0.47 unless superseded by a newer release). Add/extend the Claude-owned navigation regression so an injected bottom-nav Intel label asserts computed markup font-size `0px` and `::after` content `"Market"`, while Home/Today remains visible once. Preserve DB16 and Worker30 unless independently required by another change. Run exact-head Tests + Lanes + CodeQL and the normal generation/static gates before merge.

Do not broaden this into adding an Intel tab or changing navigation structure.
