// v24.0.1 bank-expense import foundation — pure parser/dedupe contracts.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('unit/bank-expense-import.spec.mjs');
let app;

async function call(name, ...args){
  return await app.page.evaluate(({ name, args }) => window.__FL_TESTS[name](...args), { name, args });
}

test('[BANK-01] recognizes common bank statement headers without hijacking explicit FreightLogic expense CSVs', async () => {
  eq(await call('isLikelyBankCSV', ['Date','Description','Amount','Running Balance']), true,
    'checking-account Date/Description/Amount/Balance export should enter bank review mode');
  eq(await call('isLikelyBankCSV', ['Details','Posting Date','Description','Amount','Type','Balance']), true,
    'posting-date/type/balance export should enter bank review mode');
  eq(await call('isLikelyBankCSV', ['Date','Description','Amount','Category']), false,
    'generic categorized expense CSV should stay on the existing expense importer');
  eq(await call('isLikelyBankCSV', ['Order','Pickup Date','Loaded Miles','Amount']), false,
    'freight/load CSV must never be mistaken for a bank statement');
});

test('[BANK-02] negative signed amount becomes a positive debit expense candidate', async () => {
  const r = await call('buildBankExpenseCandidates', ['Date','Description','Amount','Running Balance'], [
    ['08/20/2026','PILOT #1234','-64.25','1200.00'],
  ]);
  eq(r.length, 1, 'one transaction should parse');
  eq(r[0].date, '2026-08-20', 'US bank date should normalize to ISO');
  eq(r[0].direction, 'debit', 'negative checking amount is a debit');
  eq(r[0].amount, 64.25, 'expense amount is stored positive');
  eq(r[0].category, 'Fuel', 'Pilot merchant should infer Fuel');
  eq(r[0].defaultSelected, true, 'ordinary debit should be selected for review by default');
});

test('[BANK-03] separate Debit/Credit columns classify direction deterministically', async () => {
  const r = await call('buildBankExpenseCandidates', ['Posted Date','Payee','Debit','Credit'], [
    ['2026-08-20','VALVOLINE','111.17',''],
    ['2026-08-21','BROKER REFUND','','75.00'],
  ]);
  eq(r[0].direction, 'debit', 'Debit column must win');
  eq(r[0].category, 'Maintenance', 'Valvoline should infer Maintenance');
  eq(r[1].direction, 'credit', 'Credit column must be excluded from expenses by default');
  eq(r[1].defaultSelected, false, 'credits must never auto-select as expenses');
});

test('[BANK-04] ambiguous positive Amount-only rows require manual review instead of importing income as expense', async () => {
  const r = await call('buildBankExpenseCandidates', ['Date','Description','Amount','Balance'], [
    ['08/20/2026','UNKNOWN TRANSACTION','125.00','900.00'],
  ]);
  eq(r[0].direction, 'unknown', 'positive amount-only semantics are bank-dependent');
  eq(r[0].defaultSelected, false, 'ambiguous positive row must be unchecked by default');
  ok(r[0].reviewReason.includes('direction'), 'candidate should explain why review is required');
});

test('[BANK-05] transaction-type Purchase can safely classify a positive credit-card amount as debit', async () => {
  const r = await call('buildBankExpenseCandidates', ['Transaction Date','Description','Amount','Transaction Type'], [
    ['08/20/2026','SHELL OIL 123','52.40','Purchase'],
  ]);
  eq(r[0].direction, 'debit', 'Purchase type resolves positive amount semantics');
  eq(r[0].defaultSelected, true, 'resolved purchase should be selected by default');
});

test('[BANK-06] transfers and card payments are review-only to prevent double-counting', async () => {
  const r = await call('buildBankExpenseCandidates', ['Posting Date','Description','Debit','Balance'], [
    ['08/20/2026','ONLINE TRANSFER TO CREDIT CARD','500.00','700.00'],
  ]);
  eq(r[0].direction, 'debit', 'money left the account');
  eq(r[0].transferLike, true, 'transfer/payment pattern must be flagged');
  eq(r[0].category, 'Transfer / Review', 'transfer must never be silently categorized as deductible expense');
  eq(r[0].defaultSelected, false, 'transfer/payment must be unchecked by default');
});

test('[BANK-07] fingerprints are stable across re-imports but preserve legitimate repeated same-day charges', async () => {
  const headers = ['Date','Description','Amount','Balance'];
  const rows = [
    ['08/20/2026','KWIK TRIP','-25.00','1000.00'],
    ['08/20/2026','KWIK TRIP','-25.00','975.00'],
  ];
  const a = await call('buildBankExpenseCandidates', headers, rows);
  const b = await call('buildBankExpenseCandidates', headers, rows);
  eq(a[0].fingerprint, b[0].fingerprint, 'same export should create stable first fingerprint');
  eq(a[1].fingerprint, b[1].fingerprint, 'same export should create stable second fingerprint');
  ok(a[0].fingerprint !== a[1].fingerprint, 'two legitimate identical charges in one file must not collapse into one duplicate');
});

test('[BANK-08] conservative merchant inference covers operating categories without guessing unknown merchants', async () => {
  const r = await call('inferBankExpenseCategory', 'I-PASS AUTOREPLENISH');
  eq(r, 'Tolls', 'I-PASS should map to Tolls');
  eq(await call('inferBankExpenseCategory', 'MYSTERY MERCHANT 8492'), 'Other', 'unknown merchant stays Other');
});

test('[BANK-09] sanitizeExpense preserves bank provenance fields through the real storage sanitizer', async () => {
  const r = await app.page.evaluate(() => window.__FL_TESTS.sanitizeExpense({
    date:'2026-08-20', amount:64.25, category:'Fuel', notes:'Pilot',
    importSource:'bank_csv', bankFingerprint:'bank_deadbeef_1',
    bankDescription:'PILOT #1234', bankDirection:'debit', bankFileName:'checking.csv', bankReference:'ABC123',
  }));
  eq(r.importSource, 'bank_csv', 'import source must survive sanitizer');
  eq(r.bankFingerprint, 'bank_deadbeef_1', 'dedupe fingerprint must survive sanitizer');
  eq(r.bankDirection, 'debit', 'direction provenance must survive sanitizer');
  eq(r.bankFileName, 'checking.csv', 'source filename must survive sanitizer');
  eq(r.bankReference, 'ABC123', 'bank transaction reference must survive sanitizer');
});

export async function runSpec(){
  app = await launchApp();
  try { return await run(); }
  finally { await app.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`){
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
