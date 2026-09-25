# DispatchLand Sanitized Screenshot Samples

Purpose: regression corpus for `parseLabelledLoadFields()` and the `/extract-image` benchmark.

These are sanitized transcriptions from real operator-supplied DispatchLand screenshots/posts from 2026-09-23 through 2026-09-24. Broker contacts, phone numbers and email addresses are excluded. Freight facts remain intact. **UNKNOWN means the source evidence did not preserve/show the field; it must never be converted to zero.**

The `Expected` columns are parser truth. Timing text is preserved as observed where available; relative words such as “today” and “tomorrow” are source text, not a new scheduling assertion.

| Load ID | Pickup | Pickup Time | Delivery | Delivery Time | Loaded Miles | Empty Miles | Weight | Pieces | Rate / Bid | Expected origin | Expected destination |
|---|---|---|---|---|---:|---:|---:|---:|---|---|---|
| 1201521 | Alpharetta, GA 30005, US | 09/23 ASAP by 06:00 PM EDT (today) | Alpha, NJ 08865, US | 09/24 08:00 AM EDT (tomorrow) - 09/24 03:00 PM EDT (tomorrow) | 789 | 40 | 300 lb | 1 | Target $700 | Alpharetta, GA | Alpha, NJ |
| 1201423 | Alpharetta, GA 30005, US | 09/23 ASAP by 06:00 PM EDT (today) | Alpha, NJ 08865, US | 09/24 08:00 AM EDT (tomorrow) - 09/24 [end time not preserved] | 789 | 40 | 300 lb | 1 | Target $700 | Alpharetta, GA | Alpha, NJ |
| 1211571 | Murfreesboro, TN 37127, US | 09/24 ASAP by 04:00 PM CDT (today) | Noblesville, IN 46060, US | 09/25 APPT at 08:00 AM EDT (tomorrow) | 339 | 89 | 474 lb | UNKNOWN | UNKNOWN | Murfreesboro, TN | Noblesville, IN |
| 1210427 | Birmingham, AL 35210, US | 09/24 ASAP by 02:00 PM CDT (today) | Flat Rock, IN 47234, US | 09/24 DIRECT by 11:55 PM EDT (today) | 455 | 95 | 220 lb | UNKNOWN | UNKNOWN | Birmingham, AL | Flat Rock, IN |
| 1208397 | Rome, GA 30165, US | 09/25 ASAP by 08:00 AM EDT (tomorrow) | Rochester, MN 55901, US | 09/28 DIRECT by 08:00 AM CDT (Mon) | 958 | 125 | 800 lb | UNKNOWN | UNKNOWN | Rome, GA | Rochester, MN |
| 1209027 | Lavonia, GA 30553, US | 09/24 ASAP by 02:00 PM EDT (today) | Marietta, GA 30066, US | 09/24 DIRECT by 04:00 PM EDT (today) | 104 | 272 | 3000 lb | 3 | Target $300 | Lavonia, GA | Marietta, GA |
| 1209295 | Gallatin, TN 37066, US | 09/24 ASAP by 03:00 PM CDT (today) | Casa Grande, AZ 85130, US | 09/28 APPT at 08:00 AM MST (Mon) | 1711 | 150 | 3500 lb | 2 | UNKNOWN | Gallatin, TN | Casa Grande, AZ |
| 1191660 | College Park, GA | 09/23 08:00 AM EDT | Carrollton, OH | 09/24 03:00 PM EDT | 700 | 8 | 2070 lb | 2 | Target $700 | College Park, GA | Carrollton, OH |
| 1201355 | Chattanooga, TN | 09/23 08:00 AM EDT | Gurnee, IL | 09/24 08:00 AM CDT | 610 | 126 | 700 lb | 1 | $600 offer | Chattanooga, TN | Gurnee, IL |
| 1201454 | Chattanooga, TN | 09/23 04:30 PM EDT | Richfield, OH | 09/24 06:00 AM EDT | 589 | 126 | 110 lb | 1 | $589 offer | Chattanooga, TN | Richfield, OH |
| 1202323 | Cumming, GA | ASAP by 05:20 PM [date/time-zone not preserved] | Youngstown, OH | 09/25 12:00 PM [time-zone not preserved] | 699 | 49 | 450 lb | 15 | Operator bid $620; not broker offer | Cumming, GA | Youngstown, OH |

## Labelled-text fixtures

Use this shape when testing the labelled parser. Do not add a missing line merely to make a fixture complete.

```text
Load ID: 1201521
Pickup: Alpharetta, GA, 30005, US
Pickup Time: 09/23 ASAP by 06:00 PM EDT (today)
Delivery: Alpha, NJ, 08865, US
Delivery Time: 09/24 08:00 AM EDT (tomorrow) - 09/24 03:00 PM EDT (tomorrow)
Loaded Miles: 789
Empty Miles: 40
Weight: 300 lb
Pieces: 1
Target Rate: $700
```

```text
Load ID: 1211571
Pickup: Murfreesboro, TN, 37127, US
Pickup Time: 09/24 ASAP by 04:00 PM CDT (today)
Delivery: Noblesville, IN, 46060, US
Delivery Time: 09/25 APPT at 08:00 AM EDT (tomorrow)
Loaded Miles: 339
Empty Miles: 89
Weight: 474 lb
```

```text
Load ID: 1209027
Pickup: Lavonia, GA, 30553, US
Pickup Time: 09/24 ASAP by 02:00 PM EDT (today)
Delivery: Marietta, GA, 30066, US
Delivery Time: 09/24 DIRECT by 04:00 PM EDT (today)
Loaded Miles: 104
Empty Miles: 272
Weight: 3000 lb
Pieces: 3
Target Rate: $300
```

## Regression invariants

- Parse `Load ID` as the order/load identifier; never turn the words “Load, ID” into an origin.
- `Loaded Miles` and `Empty Miles` are distinct fields. Never copy loaded miles into deadhead.
- Missing `Empty Miles` remains UNKNOWN, never `0`.
- A displayed operator bid is not a broker target/offer. Sample 1202323 is explicitly an operator bid.
- Preserve distinct Load IDs even when route, mileage or timing is similar.
- Do not infer awarded, booked, completed or paid status from a board screenshot.
