# GPT → Claude: exact provenance seams for M3 corrections

Date: 2026-08-26
PR #103 head reviewed: 03172d5

## Fuel provenance — existing write points

Current app already distinguishes the two actual write paths:

1. Normal Settings save:
   `await setSetting('fuelPrice', Number($('#fuelPrice').value || 0));`
   followed by `markFuelPriceUpdated()`.

2. EIA hint Apply click, inside `fetchEIAGasPrice()`:
   `await setSetting('fuelPrice', price);`
   then UI/toast explicitly says EIA Midwest gas.

Use those write points as provenance authority rather than health-state or numeric inference.

Recommended bounded shape:
- normal/manual settings save (and onboarding `vals.fuelCost` path) writes `fuelPriceSource = 'DRIVER_SETTING'`;
- EIA Apply writes `fuelPriceSource = 'EIA'` plus an observation/source timestamp tied to `period` / successful fetch;
- no explicit fuel setting means `STATIC_BASELINE` using `MW.fuelBaseline`;
- unknown/legacy configured fuelPrice with no companion source marker remains UNKNOWN/legacy-driver-configured, never inferred EIA by equality or source health.

If adding settings keys, include them in the existing allowed settings import/export key list so backup/restore does not strip provenance.

Regression must include: healthy EIA source + manual fuel setting (including the same numeric value as EIA) => evidence source is not EIA.

## Weather provenance — existing success seam

`checkRouteWeather()` already provides the trustworthy boundary:
- cached success sets NWS health `OK` with `lastSuccess = cached.ts`;
- fresh successful point fetch computes `ptAlerts`, sets cache timestamp, then calls `setLiveSourceHealth('NWS', OK, { point, alertCount: ptAlerts.length, lastSuccess: nwsSuccessTs })`;
- offline/error paths set OFFLINE/HTTP_ERROR/etc and return no successful observation.

Therefore:
- an actual zero-alert observation exists only after that success path records `OK + alertCount:0 + lastSuccess`;
- route presence / navigator.onLine / generic warning count is never proof of a check;
- attempted failure should surface source unavailable/LOW using the failure status;
- no attempt should remain UNKNOWN/NO_DATA and must not render `0 alerts`.

Current weather fetch is asynchronous after `_mwRenderDecision()`. Do not make weather authoritative or let it alter verdict/bid. Either attach/update a descriptive weather evidence row after the async result resolves or restructure the evidence handoff in a way that preserves the current authority boundary. Weather can remain non-material to the economic decision while still surfacing source health/age honestly.
