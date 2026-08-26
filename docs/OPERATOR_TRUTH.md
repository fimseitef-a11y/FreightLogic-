# FreightLogic Operator Truth

Version: 1.0.0
Snapshot date: 2026-08-26
Owner lane: GPT (`docs/`)
Status: canonical operator/evidence truth snapshot; amend by versioned commit only

## Purpose

This file externalizes operator-specific freight facts that were previously carried in conversational context. It is intentionally conservative.

**Promotion rule:** a fact belongs here only when it is supported by an operator statement/correction or primary evidence such as a screenshot, rate confirmation, completed-order record, or directly observed board card. If the extraction cannot distinguish a user statement from an AI inference, the item belongs in `OPEN_QUESTIONS.md`, not here.

Secondary AI handoffs/summaries are not sufficient authority by themselves.

## Source-type vocabulary

- `OPERATOR_CORRECTION` — explicit user correction that supersedes prior interpretation.
- `OPERATOR_STATEMENT` — explicit user statement about operation, equipment, status, or experience.
- `SCREENSHOT` — value visibly present in a user-provided screenshot/load card.
- `RATE_CONFIRMATION` — contractual/dispatch confirmation evidence; does not by itself prove delivery or payment unless the evidence says so.
- `COMPLETION_RECORD` — source explicitly indicates the load was completed/delivered.
- `BOARD_OBSERVATION` — live/historical load-board card or board-state observation.
- `BROKER_CONVERSATION_RELAY` — operator relayed what a broker told them; useful market evidence, not a board-wide statistic.

## Authority and reconciliation rules

1. Current operator correction outranks older summaries.
2. Primary screenshots/order cards/rate confirmations/completion records outrank AI-generated handoffs.
3. Preserve source-displayed mileage separately from inferred or map-estimated mileage.
4. Preserve `loaded_miles`, `deadhead_miles`, and post-delivery reposition miles as separate quantities.
5. Quote/load IDs are **not guaranteed unique by themselves**. Never deduplicate a quote solely by ID. Use at minimum ID + origin + destination + pickup date/time, plus any other distinguishing facts.
6. Known reused quote IDs in operator history include `1005146`, `1005494`, `1005641`, `1005648`, and `1005661`.
7. A quote-board observation is not a completed load unless later awarded/completed evidence exists.
8. `EXPIRED` as a lifecycle state is not automatically `LOST`; however, for the specific 2026-08-24 screenshot batch, the operator explicitly stated that all cards they had bid on and showed as expired were bids they did not win.
9. Later operator-confirmed status corrections supersede earlier state labels without deleting the older observation.

## Operating identity and equipment

| Date | Source type | Confirmed fact |
|---|---|---|
| 2026-08-24 | OPERATOR_STATEMENT | Primary operating platform is DispatchLand/Dispatch Lane for cargo-van expedite work. |
| 2026-08-24 | OPERATOR_STATEMENT | FreightLogic is centered on a Ford Transit T250 cargo van and True RPM. |
| 2026-08-20 | OPERATOR_CORRECTION | Usable cargo-floor length is a **hard 121-inch limit** in the operator's actual van configuration. Freight measuring 176 in long was rejected on fit. |
| 2026-06-19 | OPERATOR_STATEMENT | Freight at 144 in long had already been rejected as too long, consistent with the later 121-in hard limit. |
| 2026-08-21 | OPERATOR_STATEMENT | The van does **not** carry a pallet jack. |
| 2026-08-19 | OPERATOR_STATEMENT | Operator normally fuels with 87-octane gasoline containing ethanol. |
| 2026-06-01 | OPERATOR_STATEMENT | Operator-reported loaded fuel-economy baseline is approximately 17.5 MPG. |
| 2026-08-24 | OPERATOR_STATEMENT | Cargo-van operation commonly handles 1–3 pieces; fit/weight must be checked against the actual van, not a generic cargo-van assumption. |

## Money and decision truth

| Date | Source type | Confirmed fact |
|---|---|---|
| 2026-08-19 | OPERATOR_CORRECTION | `True RPM = revenue / (loaded miles + deadhead/empty miles)`. Loaded RPM alone is informational and must not replace True RPM. |
| 2026-08-19 | OPERATOR_CORRECTION | Current Level X+ grading: A `>= 1.75`; B `1.60–1.74`; C `1.50–1.59`; D `1.40–1.49`; E `1.25–1.39`; ordinary reject `< 1.25` outside active Dead-Zone Exit. |
| 2026-08-19 | OPERATOR_CORRECTION | Normal floor is `$1.40` True RPM; preferred floor is `$1.50`; strategic floor is `$1.25`; explicit Dead-Zone Exit absolute floor is `$0.90`. |
| 2026-08-24 | OPERATOR_CORRECTION | DAT RateView is not authoritative cargo-van-expedite pricing for FreightLogic and is frozen/dormant unless explicitly re-authorized later. |
| 2026-08-20 | OPERATOR_OBSERVATION | Operator described that day's market as very weak after losing the Cheyenne → Denver bid sequence. |
| 2026-08-23 | OPERATOR_STATEMENT | Weekend behavior may justify accepting a lower all-in RPM when it improves Sunday/Monday positioning and covers repositioning; this is strategic positioning logic, not a new normal-market floor. |

## DispatchLand behavior confirmed by the operator

| Date | Source type | Confirmed behavior |
|---|---|---|
| 2026-06-27 | OPERATOR_CORRECTION | Notification text equivalent to **“You have just received the Quote”** means the quote is pending/received; it does not mean the load was won. |
| 2026-06-27 | OPERATOR_CORRECTION | Operator language equivalent to **“hasn't won”** means historical/not awarded. |
| 2026-08-24 | OPERATOR_CORRECTION | The expired cards supplied that day were all loads the operator bid on and did **not** win; treat those specific observations as historical lost bids, not pending or awarded loads. |
| 2026-08-24 | OPERATOR_CORRECTION | Quote IDs can be reused for different lanes; identity must not be based on quote ID alone. |
| 2026-08-20 | OPERATOR_REQUIREMENT | For a new quote analysis, FreightLogic should surface the same-day winning range, recommended bid, and strategic minimum when evidence is sufficient. |
| 2026-08-22 | OPERATOR_OBSERVATION | Operator stated that weekends usually produce very few or no loads for their operation. |

## Operator-verified historical dataset rules

| Date | Source type | Confirmed fact |
|---|---|---|
| 2026-08-24 | OPERATOR_CORRECTION | Historical master covering approximately Nov 2025 through May 27, 2026 contained 91 unique orders across 45 screenshots; operator re-audited and confirmed zero duplicate order numbers in that set. |
| 2026-08-24 | OPERATOR_CORRECTION | June–Aug 2026 extension contained 34 orders plus 1 quote; records previously marked `DRY RUN` were completed, and records marked `WAITING FOR DRIVER'S CONFIRMATION` for #42401, #89029, and #15272 were later confirmed completed. |
| 2026-08-24 | OPERATOR_CORRECTION | Consolidated master contained **125 rows: 124 unique orders + 1 auction quote** after duplicate DispatchLand #354310 was removed. Operator instructed that supplied master values are correct and should not be re-audited unless the operator later corrects them. |
| 2026-08-24 | OPERATOR_CORRECTION | When merging historical batches, deduplicate completed/order history by Order ID where appropriate, but preserve later status corrections and do not apply that rule to quote-board IDs that may be reused. |
| 2026-08-24 | OPERATOR_CORRECTION | A verified quote-board batch contains 56 unique quote IDs observed roughly 15:07–18:04; 37 had fully visible origin→destination text and 19 were partial/cut off. Partial route text must be preserved rather than guessed. |

**Important extraction limitation:** the conversation context confirms the existence and operator-verification status of the 125-row master, but this snapshot does not contain every row's full primary fields. This file therefore does not manufacture missing rows. The row-level master must be imported from the operator-verified CSV/source evidence when available.

## Accepted / completed / rate-confirmed loads present in the current context

Status meanings in this table are deliberately narrow: `COMPLETED` requires completion evidence; `WON/ACCEPTED` means award/rate-confirmation evidence exists but completion is not asserted here.

| Date | Status | Order / source | Lane | Known economics / freight facts | Source type |
|---|---|---|---|---|---|
| 2026-08-23 | WON/ACCEPTED | Travel Order #27990 | Warren, MI → Louisville, KY | Pay not asserted in this snapshot; completion not asserted | RATE_CONFIRMATION |
| 2026-08-21 | WON/ACCEPTED | Order #27973 | Lake Zurich, IL → Toledo, OH | Operator explicitly said **“I got this for 450”**; delivery was scheduled 6:00 AM; completion not asserted here | OPERATOR_STATEMENT + RATE_CONFIRMATION |
| 2026-08-20 | COMPLETED | Order #313190 | Oklahoma City, OK → Cheyenne, WY | Master status later operator-confirmed completed | OPERATOR_CORRECTION / COMPLETION_RECORD |
| 2026-08-14 | COMPLETED | Order #106299 | Glendale, OH → Detroit, MI | Completion evidence present; pay not asserted here | COMPLETION_RECORD |
| 2026-08-14 | COMPLETED | Order #106238 | Crossville, TN → Ludlow Falls, OH | Completion evidence present; pay not asserted here | COMPLETION_RECORD |
| 2026-08-13 | COMPLETED | Order #2070 | Clinton, IA → Athens, TN | Completion evidence present; pay not asserted here | COMPLETION_RECORD |
| 2026-08-11 | COMPLETED | Travel Order #29083 | Chicago, IL → Lincoln, NE | Completion evidence present; pay not asserted here | COMPLETION_RECORD |
| 2026-08-07 | COMPLETED | Travel Order #714393 | Twinsburg, OH → Sterling Heights, MI | Completion evidence present; pay not asserted here | COMPLETION_RECORD |
| 2026-08-07 | COMPLETED | Travel Order #20711 | Camden, NJ → Aliquippa, PA | Completion evidence present; pay not asserted here | COMPLETION_RECORD |
| 2026-08-05 | COMPLETED | Travel Order #347173 | Milwaukee, WI → Bethel, CT | Completion evidence present; pay not asserted here | COMPLETION_RECORD |
| 2026-07-31 | COMPLETED | Travel Order #89423 | Northbrook, IL → Dahlgren, IL | Completion evidence present; pay not asserted here | COMPLETION_RECORD |
| 2026-07-30 | WON/ACCEPTED | rate confirmation | West Allis, WI → Le Roy, NY | Completion not asserted here | RATE_CONFIRMATION |
| 2026-07-29 | COMPLETED | source record | Groveport, OH → Nashville, TN | Completion evidence present | COMPLETION_RECORD |
| 2026-07-27 | COMPLETED | Select Logistics record | Dexter, MI → East Liberty, OH | Completion evidence present | COMPLETION_RECORD |
| 2026-07-26 | COMPLETED | Alliance Cargo record | South Bend, IN → Romulus, MI | Completion evidence present | COMPLETION_RECORD |
| 2026-07-24 | COMPLETED | Sound Transportation record | Altoona, PA → Enola, PA | Completion evidence present | COMPLETION_RECORD |
| 2026-07-23 to 2026-07-24 | COMPLETED | source record | Plainfield, IN → McConnellsburg, PA | Completion evidence present | COMPLETION_RECORD |
| 2026-07-22 | COMPLETED | source record | Trevor, WI → Greenfield, IN | Completion evidence present | COMPLETION_RECORD |
| 2026-07-17 | COMPLETED | source record | Columbia, KY → Middleton, TN | Completion evidence present | COMPLETION_RECORD |
| 2026-07-16 to 2026-07-17 | COMPLETED | source record | Amory, MS → Louisville, KY | Completion evidence present | COMPLETION_RECORD |
| 2026-07-08 | COMPLETED | #89029 / NFL | Grand Rapids, MI → Menomonie, WI | 459 displayed/loaded mi; 2,000 lb; `$673`; displayed loaded RPM about 1.47. Deadhead is not asserted here, so this row does **not** assert a True RPM. | OPERATOR_RECORD + COMPLETION_RECORD |
| 2026-07-07 | COMPLETED | Travel Order #345680 | Milwaukee, WI → Belleville, MI | Completion evidence present | COMPLETION_RECORD |
| 2026-07-04 | COMPLETED | Travel Order #39414 | El Paso, TX → Hamtramck, MI | Completion evidence present | COMPLETION_RECORD |
| 2026-07-02 | COMPLETED | Travel Order #498637 | Southaven, MS → El Paso, TX | Completion evidence present | COMPLETION_RECORD |
| 2026-06-27 | COMPLETED | Travel Order #498291 | Tulsa, OK → Merrillville, IN | Completion evidence present | COMPLETION_RECORD |
| 2026-06-24 | WON/ACCEPTED | #632684 | Adrian, MI → Tulsa, OK | 851 loaded + 97 empty = 948 total displayed context miles; 504 lb. Award is confirmed; final pay is intentionally not asserted in this file because the carried wording about `$1,050` is ambiguous. | OPERATOR_RECORD |
| 2026-06-23 | COMPLETED | #15272 | Des Plaines, IL → Sterling Heights, MI | 375 mi; 415 lb; `$525` | OPERATOR_RECORD + COMPLETION_RECORD |
| 2026-06-20 to 2026-06-21 | COMPLETED | #147138 | Des Plaines, IL → Columbus, OH | 398 mi; 1 lb; `$500` | OPERATOR_RECORD + COMPLETION_RECORD |
| 2026-06-16 | COMPLETED | #40005 | Nashville, TN → Kingsport, TN | 288 mi; 20 lb; `$500` | OPERATOR_RECORD + COMPLETION_RECORD |
| 2026-06-12 to 2026-06-15 | COMPLETED | #93189 | Watertown, WI → Fenton, MO | 439 mi; 200 lb; `$675` | OPERATOR_RECORD + COMPLETION_RECORD |
| 2026-06-05 | COMPLETED | source record | Winchester, KY → Raton, NM | 1,292 loaded mi; 250 lb; `$1,850`; loaded RPM ≈ 1.43. No deadhead value is asserted here, so no True RPM is asserted. | OPERATOR_RECORD + COMPLETION_RECORD |

Additional completed lanes present in primary completion evidence from July 8–16, 2026 include Boyceville, WI → Holts Summit, MO; Sturtevant, WI → Lima, OH; Lima, OH → Dayton, OH; and Dayton, OH → Corinth, MS. Exact order IDs/pay are not promoted here because they are not present in the extracted context.

## Lost bids explicitly present in the current context

| Date | Quote | Lane | Bid / board facts | Outcome | Source type |
|---|---|---|---|---|---|
| 2026-08-24 | 998232 | Louisville, KY 40219 → Michigan City, IN 46360 | 295 loaded + 17 empty; operator bid `$400`; 84 lb; 2 pcs; pickup 08/24 ASAP by 7:00 PM EDT; delivery 08/25 direct by 4:00 AM CDT | Operator confirmed not won | SCREENSHOT + OPERATOR_CORRECTION |
| 2026-08-24 | 998088 | Louisville, KY 40228 → Cleveland, OH 44109 | 352 loaded + 14 empty; operator bid `$450`; board target `$400`; 450 lb; 3 pcs; pickup 08/24 ASAP by 7:00 PM EDT; delivery 08/25 8:00 AM EDT | Operator confirmed not won | SCREENSHOT + OPERATOR_CORRECTION |
| 2026-08-24 | 997892 | Franklin, IN 46131 → Cedar Park, TX 78613 | 1,068 loaded + 106 empty; operator bid `$1,600`; pickup shown for 08/25; remaining timing details are not reproduced because the current extraction is incomplete | Operator confirmed not won | SCREENSHOT + OPERATOR_CORRECTION |
| 2026-08-20 | not preserved here | Cheyenne, WY → Denver, CO | Operator bid `$750`, then `$650` | Lost | OPERATOR_STATEMENT |

## Quote-board observations explicitly present in the current context

| Date | Quote | Lane | Visible facts | Source type |
|---|---|---|---|---|
| 2026-08-24 | 995504 | Mason, OH 45040 → Winston-Salem, NC | `HOT`; 411 loaded + 119 empty; 180 lb; 1 pc; pickup ASAP by 4:00 PM EDT; delivery 08/25 8:00 AM EDT | SCREENSHOT / BOARD_OBSERVATION |
| 2026-08-24 | 995526 | New Albany, IN 47150 → Winston-Salem, NC | `HOT`; 439 loaded + 22 empty; 1,240 lb; 2 pcs; pickup window shown through 3:30 PM EDT; delivery 08/25 direct by 8:00 AM EDT | SCREENSHOT / BOARD_OBSERVATION |
| 2026-08-24 | ID not visible | New Albany, IN 47150 → Atlanta, GA 30301 | 395 loaded + 22 empty; 1,240 lb; 1 pc; pickup 08/24 3:30 PM EDT; delivery 08/25 8:00 AM–3:00 PM EDT | SCREENSHOT / BOARD_OBSERVATION |

The operator explicitly instructed that a missing/obscured quote ID must remain missing; do not invent one.

## Broker-relayed market observations

| Date | Source type | Observation |
|---|---|---|
| 2026-06-26 | BROKER_CONVERSATION_RELAY | Broker told operator OK/KS cargo-van market was averaging roughly `$0.90–$1.00`; Tulsa → Chicago/Indianapolis was roughly `$520–$650`; operator had previously taken `$700` once; westbound Tulsa → Seattle was described around `$1,900–$2,200`; US→Canada about `$1.30–$1.40`; Canada→US about `$1.16–$1.20`. These are broker-relayed observations, not guaranteed market averages. |

## Warp observations supplied for FreightLogic comparison

These values are external market evidence, not carrier payout. See `EVIDENCE_PROVENANCE.md` for semantics.

| Date | Lane | Warp quoted price | Transit | Source type |
|---|---|---:|---|---|
| 2026-08-24 | Milwaukee area → Detroit | `$575.67` | 1 day | WARP_QUOTE_EVIDENCE |
| 2026-08-24 | Detroit → Columbus | `$364.38` | 1 day | WARP_QUOTE_EVIDENCE |
| 2026-08-24 | Columbus → Chicago | `$519.47` | 1 day | WARP_QUOTE_EVIDENCE |
| 2026-08-24 | Chicago → Grand Rapids | `$335.14` | 1 day | WARP_QUOTE_EVIDENCE |
| 2026-08-24 | Indianapolis → Detroit | `$468.41` | 1 day | WARP_QUOTE_EVIDENCE |

## 123Loadboard and Direct Freight account status

| Date | Source type | Confirmed fact |
|---|---|---|
| 2026-08-24 | OPERATOR_STATEMENT | Operator created a free 123Loadboard account. |
| 2026-08-24 | OPERATOR_STATEMENT | Operator created a free Direct Freight account. |
| 2026-08-24 | OPERATOR_CORRECTION | Free load-board account access must be kept separate from API/partner authorization. FreightLogic must not treat a website login as API approval. |

Exact API eligibility, token status, commercial terms, and any `$200` 123Loadboard integration/key offer are tracked in `OPEN_QUESTIONS.md` unless independently verified.

## Change control

- Never silently overwrite a conflicting fact. Add the newer fact with its date/source and mark the superseded entry explicitly.
- Any future AI importing this file must preserve the distinction between observed, bid, won, completed, invoiced, and paid.
- Any fact that cannot be sourced under the rules above must move to `OPEN_QUESTIONS.md` until the operator confirms or rejects it.
