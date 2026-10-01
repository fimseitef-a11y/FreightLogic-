// Load One / Load1 live-source seam.
//
// Public research proves that current bid opportunities/recent-shipment maps
// exist behind Load One-authenticated systems, but it did not identify a
// public, documented load feed that ELI is authorized to collect. This module
// therefore registers the desired cadence and market-hours policy while
// remaining fail-closed until a documented authorized feed adapter exists.

export const LOADONE_CRON = '*/20 * * * *';

export const LOADONE_LIVE_SOURCE = Object.freeze({
  sourceId: 'loadone-live',
  sourceClass: 'LICENSED_LIVE_OPTIONAL',
  adapterVersion: 'loadone-live-v1',
  desiredCadenceMinutes: 20,
  timeZone: 'America/New_York',
  activeWindow: Object.freeze({ startHourInclusive: 6, endHourExclusive: 22 }),
  authorizationRequired: true,
  allowedCollectionMethod: 'DOCUMENTED_AUTHORIZED_FEED_ONLY',
  requiredForServiceLiveness: false,
  completenessCapability: 'UNKNOWN_UNTIL_AUTHORIZED_FEED_DOCUMENTED',
});

const EASTERN_HOUR = new Intl.DateTimeFormat('en-US', {
  timeZone: LOADONE_LIVE_SOURCE.timeZone,
  hour: '2-digit',
  hour12: false,
  hourCycle: 'h23',
});

export function isLoadOneActiveWindow(instant) {
  const date = instant instanceof Date ? instant : new Date(instant);
  if (!Number.isFinite(date.getTime())) return false;
  const hourPart = EASTERN_HOUR.formatToParts(date).find((part) => part.type === 'hour');
  const hour = Number(hourPart?.value);
  return Number.isInteger(hour)
    && hour >= LOADONE_LIVE_SOURCE.activeWindow.startHourInclusive
    && hour < LOADONE_LIVE_SOURCE.activeWindow.endHourExclusive;
}

export async function runLoadOneCollection(env, deps = {}) {
  const now = (deps.now ?? (() => new Date().toISOString()))();

  if (env?.ELI_ENABLED !== 'true') {
    return { status: 'SKIPPED', reason: 'ELI_DISABLED' };
  }

  // Check the active window before any provider/access work. Cloudflare cron is
  // UTC, so this DST-aware gate preserves the operator-observed Eastern window
  // while allowing one stable */20 schedule all year.
  if (!isLoadOneActiveWindow(now)) {
    return { status: 'SKIPPED', reason: 'LOADONE_OUTSIDE_ACTIVE_WINDOW' };
  }

  if (env?.LOADONE_COLLECTION_AUTHORIZED !== 'true') {
    return { status: 'SKIPPED', reason: 'LOADONE_UNAUTHORIZED' };
  }

  // Deliberately no fetch here. A future implementation must be based on a
  // documented, authorized Load One feed and its exact schema/terms; guessing
  // an app/private endpoint would violate ELI's source-access contract.
  return { status: 'SKIPPED', reason: 'LOADONE_DOCUMENTED_FEED_NOT_CONFIGURED' };
}
