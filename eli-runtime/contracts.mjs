export const LIFECYCLE_STATES = Object.freeze([
  'SHOWN',
  'BID',
  'WON',
  'LOST',
  'EXPIRED',
  'REJECTED',
  'DRY_RUN',
  'DEACTIVATED',
  'IN_PROGRESS',
  'COMPLETED',
  'PAID',
]);

export const SOURCE_CLASSES = Object.freeze([
  'STRUCTURAL_PUBLIC',
  'OPERATOR_PRIVATE',
  'LICENSED_LIVE_OPTIONAL',
]);

const OUTCOME_ALLOWED_FIELDS = new Set([
  'correlationToken',
  'status',
  'observedAt',
  'source',
  'sourceRecordId',
  'originMarket',
  'destinationMarket',
  'pickupAt',
  'equipmentClass',
  'lineage',
]);

const OUTCOME_FORBIDDEN_FIELDS = new Set([
  'rate',
  'rpm',
  'bidAmount',
  'revenue',
  'payout',
  'settlement',
  'fuel',
  'costPerMile',
  'paymentAccount',
  'paymentIdentifier',
  'cardNumber',
  'accountNumber',
  'secret',
]);

export function validateOutcomeEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    throw new TypeError('outcome event must be an object');
  }

  for (const key of Object.keys(event)) {
    if (OUTCOME_FORBIDDEN_FIELDS.has(key)) {
      throw new Error(`forbidden outcome field: ${key}`);
    }
    if (!OUTCOME_ALLOWED_FIELDS.has(key)) {
      throw new Error(`outcome field is not allowlisted: ${key}`);
    }
  }

  if (!LIFECYCLE_STATES.includes(event.status)) {
    throw new Error(`invalid lifecycle status: ${String(event.status)}`);
  }

  return { ...event };
}
