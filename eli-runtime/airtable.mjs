// airtable.mjs — read-only Airtable REST client for ELI ingestion.
// The token is sent only in the Authorization header and never appears in
// errors, logs, D1 or returned values.

const API = 'https://api.airtable.com/v0';
const MAX_PAGES = 60; // 6,000 records per table per run; a bound, not a target.
const TIMEOUT_MS = 15000;

export class AirtableError extends Error {
  constructor(message, status = null) {
    super(message);
    this.name = 'AirtableError';
    this.status = status;
  }
}

export async function fetchAirtableRecords({
  token,
  baseId,
  tableId,
  fieldIds = [],
  filterByFormula = null,
  fetchImpl = fetch,
  maxPages = MAX_PAGES,
}) {
  if (!token || typeof token !== 'string') throw new AirtableError('AIRTABLE_TOKEN_MISSING');
  if (!/^app[A-Za-z0-9]{14}$/.test(baseId ?? '')) throw new AirtableError('AIRTABLE_BASE_INVALID');
  if (!/^tbl[A-Za-z0-9]{14}$/.test(tableId ?? '')) throw new AirtableError('AIRTABLE_TABLE_INVALID');

  const records = [];
  let offset = null;
  for (let page = 0; page < maxPages; page += 1) {
    const url = new URL(`${API}/${baseId}/${tableId}`);
    url.searchParams.set('returnFieldsByFieldId', 'true');
    url.searchParams.set('pageSize', '100');
    for (const id of fieldIds) url.searchParams.append('fields[]', id);
    if (filterByFormula) url.searchParams.set('filterByFormula', filterByFormula);
    if (offset) url.searchParams.set('offset', offset);

    let response;
    try {
      response = await fetchImpl(url.toString(), {
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch {
      throw new AirtableError(`AIRTABLE_REQUEST_FAILED:${tableId}`);
    }
    if (!response.ok) throw new AirtableError(`AIRTABLE_HTTP_${response.status}:${tableId}`, response.status);

    let body;
    try {
      body = await response.json();
    } catch {
      throw new AirtableError(`AIRTABLE_INVALID_JSON:${tableId}`);
    }
    if (!Array.isArray(body?.records)) throw new AirtableError(`AIRTABLE_INVALID_RESPONSE:${tableId}`);
    records.push(...body.records);
    offset = typeof body.offset === 'string' && body.offset ? body.offset : null;
    if (!offset) return records;
  }
  throw new AirtableError(`AIRTABLE_PAGE_LIMIT:${tableId}`);
}
