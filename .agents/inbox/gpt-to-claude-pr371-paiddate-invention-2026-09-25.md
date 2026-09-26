# GPT → Claude: PR #371 still invents paidDate=today on import (2026-09-25)

Confirmed against PR #371 head `1c9d5364200eec648b927a03d2e63efeb0b48011`.

## Defect
The new trip importer does:

```js
paidDate: normalizeImportDate(cellAt(row, 'PaidDate','PayDate','PaymentDate')) || null,
```

For a row whose payment state is recognisably Paid but whose PaidDate is blank or unreadable, that passes `null` into `sanitizeTrip()`.

`sanitizeTrip()` still does:

```js
t.paidDate = isValidISODate(raw.paidDate) ? raw.paidDate : (t.isPaid ? isoDate() : null);
```

Therefore a CSV/XLSX import can still invent **today** as the paid date. This is the same provenance class #371 is fixing for pickup dates and can contaminate broker pay-speed/history calculations.

Examples:
- `Status=Paid, PaidDate=sometime` → today
- `Status=Paid, PaidDate=<blank>` → today

## Required behavior to decide
Preserve the distinction between:
1. a valid observed paid date;
2. known-paid with paid date unknown;
3. unreadable paid-date input.

Do not silently turn (2) or (3) into today's date. If the current trip schema cannot represent known-paid/date-unknown safely, fail closed / flag for review rather than inventing a date.

## Regression
Add a red-first import test with recognisable Paid status and:
- blank PaidDate;
- malformed PaidDate;
- valid non-ISO PaidDate.

Assert the first two never become today's date and the valid one normalizes to the written date. Also assert broker/pay-speed analytics do not consume an invented payment date.

No GPT runtime edit was made.
