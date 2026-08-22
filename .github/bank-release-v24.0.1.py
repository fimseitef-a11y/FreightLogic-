from pathlib import Path


def read(path):
    return Path(path).read_text()


def write(path, text):
    Path(path).write_text(text)


def replace_once(path, old, new):
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{path}: expected exactly one match for {old!r}, found {count}')
    write(path, text.replace(old, new, 1))


# app.js: bump the shipped app identity only. The canonical decision schema and
# hard-gate policy remain v24.0.0 because this patch does not alter that contract.
replace_once('app.js', '/** FreightLogic v24.0.0 USA ENGINE', '/** FreightLogic v24.0.1 USA ENGINE')
replace_once('app.js', "const APP_VERSION = '24.0.0';", "const APP_VERSION = '24.0.1';")
replace_once('app.js', '// FREIGHTLOGIC v24.0.0 USA ENGINE — Production Security Hardened', '// FREIGHTLOGIC v24.0.1 USA ENGINE — Production Security Hardened')
replace_once(
    'app.js',
    ' *  v24.0.0 "Trust & Recovery" (X-01..X-12, in progress — see CLAUDE.md for the',
    ' *  v24.0.1: Guarded bank-statement expense import with review-before-write, transfer/inflow protection, merchant categorization, and duplicate provenance.\n *  v24.0.0 "Trust & Recovery" (X-01..X-12, in progress — see CLAUDE.md for the'
)

app = read('app.js')
if "const UNIFIED_DECISION_SCHEMA_VERSION = '24.0.0';" not in app:
    raise SystemExit('app.js: v24.0.0 decision schema must remain unchanged in patch release')
if "version: '24.0.0-hard-gates-1'" not in app:
    raise SystemExit('app.js: hard-gate policy version unexpectedly changed')

# Shipped static/cache files: all 24.0.0 markers here identify the app build or
# cache-buster, not the immutable decision schema.
for path in [
    'index.html',
    'manifest.json',
    'service-worker.js',
    'midwest-stack-authority.js',
    'sw-bridge.js',
    'voice-load.js',
    'scripts/verify-cloudflare-parity.mjs',
]:
    text = read(path)
    count = text.count('24.0.0')
    if count < 1:
        raise SystemExit(f'{path}: no 24.0.0 release marker found')
    write(path, text.replace('24.0.0', '24.0.1'))

# Project instructions: only current release identity changes; v24.0 historical
# architecture references remain accurate.
replace_once('CLAUDE.md', '**FreightLogic v24.0.0**', '**FreightLogic v24.0.1**')
claude = read('CLAUDE.md')
anchor = '**v24.0 authority rule:** `app.js` is the sole deterministic owner of load verdict, grade, economics, and bid range. USA scoring and `midwest-stack-authority.js` are evidence/advisory layers. Cloud Worker `/evaluate` may explain or challenge assumptions, but it must project—not recalculate—the canonical decision.\n'
if anchor not in claude:
    raise SystemExit('CLAUDE.md: v24 authority anchor missing')
addition = anchor + '\n**v24.0.1 bank-import rule:** Bank CSV/XLSX data must enter the guarded expense-review candidate path. Credits/inflows, transfer-like payments, ambiguous direction, and known duplicates may not be silently imported as deductible expenses. Bank-link providers added later must feed this same provider-neutral candidate/review model rather than create a second bookkeeping path.\n'
write('CLAUDE.md', claude.replace(anchor, addition, 1))

# Roadmap note without consuming the reserved v24.1 Confidence + Evidence number.
roadmap = read('docs/V24_ROADMAP.md')
anchor = 'v24.0 implementation status: **release candidate** — code complete; merge remains gated on the full Playwright suite and release-parity checks.\n'
if anchor in roadmap:
    roadmap = roadmap.replace(anchor, 'v24.0 implementation status: **released** — Unified Decision Engine merged with the full Playwright gate green.\n', 1)
note_anchor = '## Delivery sequence\n\n'
if note_anchor not in roadmap:
    raise SystemExit('docs/V24_ROADMAP.md: delivery sequence anchor missing')
roadmap = roadmap.replace(note_anchor, note_anchor + '**Patch release v24.0.1:** guarded bank-statement expense ingestion foundation. This does not consume the reserved v24.1 Confidence + Evidence milestone.\n\n', 1)
write('docs/V24_ROADMAP.md', roadmap)
