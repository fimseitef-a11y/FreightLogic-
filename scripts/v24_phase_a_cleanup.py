from pathlib import Path


def replace_once(path, old, new, label):
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly 1 match, found {count}")
    p.write_text(text.replace(old, new, 1))

# Worker AI no longer owns business/tax thresholds. Its job is to review the
# client decision, so stale benchmark/tax constants should not compete with
# the canonical deterministic engine.
replace_once(
    'cloud-backup-worker.js',
    "FINANCIAL CONTEXT (2026 IRS / industry benchmarks for cargo van expedite):\n- Minimum viable true RPM for cargo van: $1.40/mi\n- Professional floor: $1.60/mi\n- Strong target: $1.75–$2.00/mi\n- IRS mileage deduction: $0.725/mi (2026)\n- Per diem: $80/day CONUS (50% deductible for non-DOT operators)\n- Fuel cost baseline: ~$0.28–$0.40/mi depending on MPG and local prices\n- Operating cost (all-in): typically $0.65–$0.90/mi for a cargo van\n\n",
    "REVIEW CONTEXT:\n- Treat the client-provided economics, floor, verdict, grade, and risk signals as authoritative inputs.\n- Do not inject independent tax rates, generic national RPM floors, or stale industry benchmarks into the review.\n- A CHALLENGE should identify missing/stale evidence or a questionable assumption, not replace the client's deterministic calculation.\n\n",
    'remove stale worker financial authority'
)

# These validators existed only for AI-owned verdict/grade output. Keeping them
# after v24 authority separation is misleading dead code.
replace_once(
    'cloud-backup-worker.js',
    "\nconst VALID_VERDICTS = new Set(['ACCEPT', 'NEGOTIATE', 'PASS', 'STRATEGIC_ONLY']);\nconst VALID_GRADES   = new Set(['A', 'B', 'C', 'D', 'E']);\n\nfunction validateVerdict(v) {\n  const s = String(v || '').toUpperCase().replace(/\\s+/g, '_');\n  return VALID_VERDICTS.has(s) ? s : 'PASS';\n}\n\nfunction validateGrade(g) {\n  const s = String(g || '').toUpperCase().trim();\n  return VALID_GRADES.has(s) ? s : 'C';\n}\n",
    "",
    'remove obsolete AI verdict validators'
)

# Strengthen v24 test so this authority leak cannot regress.
p = Path('tests/unit/v24-unified-decision.spec.mjs')
text = p.read_text()
needle = "  ok(!worker.includes('grade:         validateGrade(parsed.grade)'), 'AI-parsed grade must not remain authoritative');\n"
if text.count(needle) != 1:
    raise SystemExit('v24 worker regression anchor mismatch')
text = text.replace(needle, needle + "  ok(!worker.includes('Professional floor: $1.60/mi'), 'Worker must not inject a competing generic RPM floor');\n  ok(!worker.includes('IRS mileage deduction: $0.725/mi (2026)'), 'Worker review must not carry stale flat tax-rate context');\n", 1)
p.write_text(text)

# Self-remove after guarded transformation.
Path('scripts/v24_phase_a_cleanup.py').unlink()
