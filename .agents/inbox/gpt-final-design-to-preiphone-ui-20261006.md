# Final pre-iPhone design reconciliation — 2026-10-06

Target: current holder of `.agents/locks/preiphone-final.lock`.

This is a refinement to the existing pre-iPhone UI handoff, based on the
operator's earlier approved driver-UI brief. Preserve current functionality and
do not add another primary navigation destination.

## Already present — do not rebuild

- Five driver surfaces: Today / Loads / Evaluate / Trips / Money.
- Today position / market context / NWS-backed weather evidence and sync/cloud
  status.
- Scan Load as the freight-intake action.
- Evaluate Offer when a rate exists vs Build My Bid when rate is absent.
- 2.6s nonblocking/reduced-motion-safe launch animation.
- Contextual Document Vault / trip document attachment path.

## Final design requirements to preserve/finish

1. **Do not put general document scanning on Today or replace Scan Load.**
   Load screenshots/text stay in Scan Load.

2. **Trip paperwork belongs contextually under History/Trips → trip →
   Attachments/Documents → Add Document → Review extracted details.**
   Review Import may also be reachable from an existing import/document surface,
   but must not become a sixth primary tab.

3. **Loads organization:** the current Decision Inbox has durable cards and
   Pursue / Pass / Awarded, but the approved organization target was
   **New / Saved / Won / Passed / Market**. Implement this as lightweight
   filtering/navigation over the existing evidence/lifecycle/disposition state;
   do not invent new status authority. Suggested mapping:
   - New = reviewed/unresolved decision cards with no operator disposition;
   - Saved = PURSUE (or another already-existing explicit saved disposition if
     current source defines one);
   - Won = explicit lifecycle WON / AWARDED only;
   - Passed = explicit PASS only (never Lost);
   - Market = existing Market Intel link.
   Preserve UNKNOWN semantics and existing evidence rows.

4. **Scanned-PDF fallback is real work.** Cloudflare Markdown Conversion's PDF
   path extracts PDF text/StructTree and does not document OCR for image-only
   pages. If `/document/extract` returns `needsOcrFallback:true`, Review
   Import must offer/use an actual OCR path rather than claim success. Prefer a
   lazy, self-hosted PDF page renderer (vendor lane is GPT-owned) that renders
   only on demand and sends bounded page images through the authenticated image
   OCR path. Do not add a CDN runtime dependency and do not increase app.js.

5. Keep the premium dark one-handed design: 44px+ targets, compact cards,
   amber/gold emphasis, no duplicated Settings/More controls, and no extra
   driver setup step.

Backend source-certified contract remains draft PR #468; refresh its head before
integration. Current exact-head green evidence is 1056/0 full suite + 10/0
completion gates on 50cdf917, plus Lanes/CodeQL/Performance/Native/Agent/ELI.
