export const LOAD_HISTORY_TABLE_ID = 'tbl6Wof9SlTVotCEa';

export const LOAD_HISTORY_FIELD_IDS = Object.freeze({
  loadId: 'fldcn3ICJoHqh4cul',
  source: 'fldOLL5VAvhn4aij6',
  statusLayer: 'fldr421BJuQAedLrO',
  origin: 'fldN33xbzUlNNmRE1',
  destination: 'fld60hboskYKlnq1P',
  loadedMiles: 'fldVznCz7rFq4ggWW',
  emptyMiles: 'fldHj8pfXD6ixiNdw',
  pickup: 'fldBtvJkAaTqmqM2y',
  delivery: 'fldoHpqhBU1VQ8YyI',
  weightLb: 'fldC4kvfowRLhh4ts',
  pieces: 'fldmRqT3o2dH8tQHJ',
  duplicateRepost: 'fldNuXG7snnZjyxcD',
  relatedLoadIds: 'fldrNpmORWv0TBdIR',
  evidenceDate: 'fld8rWQILiis5rnxl',
});

export function getLoadHistoryReadFieldIds() {
  return Object.values(LOAD_HISTORY_FIELD_IDS);
}

function unwrap(value) {
  if (value && typeof value === 'object' && !Array.isArray(value) && typeof value.name === 'string') {
    return value.name;
  }
  return value ?? null;
}

function nullableText(value) {
  const unwrapped = unwrap(value);
  if (unwrapped == null) return null;
  const text = String(unwrapped).trim();
  return text || null;
}

function nullableNumber(value) {
  return Number.isFinite(value) ? value : null;
}

export function projectLoadHistoryRecord(record = {}) {
  const cells = record.cellValuesByFieldId && typeof record.cellValuesByFieldId === 'object'
    ? record.cellValuesByFieldId
    : {};

  return {
    airtableRecordId: record.id ?? null,
    loadId: nullableText(cells[LOAD_HISTORY_FIELD_IDS.loadId]),
    source: nullableText(cells[LOAD_HISTORY_FIELD_IDS.source]),
    statusLayer: nullableText(cells[LOAD_HISTORY_FIELD_IDS.statusLayer]),
    origin: nullableText(cells[LOAD_HISTORY_FIELD_IDS.origin]),
    destination: nullableText(cells[LOAD_HISTORY_FIELD_IDS.destination]),
    loadedMiles: nullableNumber(cells[LOAD_HISTORY_FIELD_IDS.loadedMiles]),
    emptyMiles: nullableNumber(cells[LOAD_HISTORY_FIELD_IDS.emptyMiles]),
    pickup: nullableText(cells[LOAD_HISTORY_FIELD_IDS.pickup]),
    delivery: nullableText(cells[LOAD_HISTORY_FIELD_IDS.delivery]),
    weightLb: nullableNumber(cells[LOAD_HISTORY_FIELD_IDS.weightLb]),
    pieces: nullableText(cells[LOAD_HISTORY_FIELD_IDS.pieces]),
    duplicateRepost: nullableText(cells[LOAD_HISTORY_FIELD_IDS.duplicateRepost]),
    relatedLoadIds: nullableText(cells[LOAD_HISTORY_FIELD_IDS.relatedLoadIds]),
    evidenceDate: nullableText(cells[LOAD_HISTORY_FIELD_IDS.evidenceDate]),
  };
}
