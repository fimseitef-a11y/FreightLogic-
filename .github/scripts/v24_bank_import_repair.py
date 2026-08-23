from pathlib import Path

APP = Path('app.js')
TEST = Path('tests/unit/bank-expense-import.spec.mjs')

source = APP.read_text()

old_money = "function parseBankMoney(value){\n  let s = sanitizeImportValue(value).trim();"
new_money = """function parseBankMoney(value){
  // Bank Amount columns use a leading '-' as transaction-direction data.
  // Do not use sanitizeImportValue() here: that generic text sanitizer
  // intentionally strips formula-leading characters, including '-'.
  // This parser never evaluates text; Number() below accepts only numeric
  // currency after formatting characters are removed and rejects formulas.
  let s = String(value ?? '').trim();"""
if old_money in source:
    source = source.replace(old_money, new_money, 1)
elif new_money not in source:
    raise SystemExit('Expected parseBankMoney pattern not found; refusing broad patch')

helper = """function bankTransferRequiresReclassification(candidate, category){
  return !!candidate?.transferLike && String(category || '') === 'Transfer / Review';
}

"""
if 'function bankTransferRequiresReclassification(' not in source:
    marker = 'function inferBankExpenseCategory(description){'
    if marker not in source:
        raise SystemExit('Expected bank category marker not found')
    source = source.replace(marker, helper + marker, 1)

old_help = 'Transfers/card payments and ambiguous positive Amount-only rows start unchecked. Credits and known duplicates cannot be selected.'
new_help = 'Transfers/card payments start unchecked and must be reclassified before import. Ambiguous positive Amount-only rows start unchecked. Credits and known duplicates cannot be selected.'
if old_help in source:
    source = source.replace(old_help, new_help, 1)
elif new_help not in source:
    raise SystemExit('Expected bank review help text not found')

pick_marker = """    const picks = [...body.querySelectorAll('.bankImportPick:checked:not(:disabled)')];
    if (!picks.length){ toast('Select at least one expense to import', true); return; }
"""
guard_block = """    const picks = [...body.querySelectorAll('.bankImportPick:checked:not(:disabled)')];
    if (!picks.length){ toast('Select at least one expense to import', true); return; }
    for (const pick of picks){
      const i = Number(pick.dataset.bankIndex);
      const c = candidates[i];
      const categoryEl = body.querySelector(`.bankImportCategory[data-bank-index="${i}"]`);
      const category = BANK_IMPORT_CATEGORY_OPTIONS.includes(categoryEl?.value) ? categoryEl.value : c?.category;
      if (bankTransferRequiresReclassification(c, category)){
        toast('Reclassify transfer/payment rows before importing', true);
        return;
      }
    }
"""
if 'Reclassify transfer/payment rows before importing' not in source:
    if pick_marker not in source:
        raise SystemExit('Expected bank commit prevalidation marker not found')
    source = source.replace(pick_marker, guard_block, 1)

old_export = 'isBankTransferLike, buildBankExpenseCandidates,'
new_export = 'isBankTransferLike, bankTransferRequiresReclassification, buildBankExpenseCandidates,'
if old_export in source:
    source = source.replace(old_export, new_export, 1)
elif new_export not in source:
    raise SystemExit('Expected __FL_TESTS bank export marker not found')

APP.write_text(source)

tests = TEST.read_text()
marker = '\nexport async function runSpec(){'
if marker not in tests:
    raise SystemExit('Expected bank test insertion marker not found')

if '[BANK-10]' not in tests:
    bank10 = r'''

test('[BANK-10] bank money parser preserves numeric signs without accepting formula payloads', async () => {
  eq(await call('parseBankMoney', '-64.25'), -64.25, 'leading minus must survive as bank direction data');
  eq(await call('parseBankMoney', '(64.25)'), -64.25, 'accounting parentheses must remain a negative amount');
  eq(await call('parseBankMoney', '$1,234.56'), 1234.56, 'formatted currency should parse normally');
  eq(await call('parseBankMoney', '=1+1'), 0, 'spreadsheet formula text must not parse as money');
  eq(await call('parseBankMoney', '@SUM(A1:A2)'), 0, 'formula-like command text must not parse as money');
  eq(await call('parseBankMoney', '-1+2'), 0, 'a leading minus does not make an expression valid numeric input');
});
'''
    tests = tests.replace(marker, bank10 + marker, 1)

if '[BANK-11]' not in tests:
    bank11 = r'''

test('[BANK-11] transfer review category requires explicit reclassification before import', async () => {
  eq(await call('bankTransferRequiresReclassification', { transferLike: true }, 'Transfer / Review'), true,
    'transfer/payment review rows must not import with the review category');
  eq(await call('bankTransferRequiresReclassification', { transferLike: true }, 'Fuel'), false,
    'explicit category override can clear a false-positive transfer flag');
  eq(await call('bankTransferRequiresReclassification', { transferLike: false }, 'Transfer / Review'), false,
    'non-transfer rows are not blocked solely by category text');
});
'''
    tests = tests.replace(marker, bank11 + marker, 1)

TEST.write_text(tests)
