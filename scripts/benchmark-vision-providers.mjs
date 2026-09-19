#!/usr/bin/env node
// FreightLogic — vision provider benchmark (Issue #252's measurement half).
//
// #252 requires, for each provider candidate: field exact-match accuracy,
// critical-field error rate, latency, request size, cost/free-quota usage, and
// malformed JSON rate. This runs that measurement over a corpus of sanitized
// screenshots and prints one table, so the default provider is CHOSEN rather
// than assumed. `workers-ai` is currently the zero-cost candidate in
// `cloud-backup-worker.js`; nothing in this repository has yet measured it
// against the alternatives, and this script is what closes that.
//
// ── THE CORPUS LIVES OUTSIDE THIS REPOSITORY, ON PURPOSE ─────────────────────
// Real load screenshots are operator business data: broker names, rates, lanes,
// order numbers. They are not sanitized by being in a folder called sanitized,
// and a repository whose Worker publishes `assets.directory: "."` is the last
// place they belong — that is the #228 defect with a picture attached. So there
// is no default in-repo corpus path and no `.gitignore` rule pretending one is
// safe: `--corpus` is REQUIRED and should point somewhere outside the checkout,
// exactly as the M6 raw files were kept out.
//
// ── WHAT IS ACTUALLY UNDER TEST ──────────────────────────────────────────────
// The REAL exported fetch handler from `cloud-backup-worker.js`, driven through
// `POST /extract-image` with a driver credential minted through the REAL
// invite/claim path, against an IN-MEMORY KV. So the route, the auth gate, the
// 3MB ceiling, the tri-state normalizer and the observational allow-list are
// the shipped ones, and NO production KV, driver account or backup is touched.
// Only the transport to the provider differs, and only for `workers-ai`, which
// has no `AI` binding outside the Workers runtime — see the shim below.
//
// ── WHAT IT REFUSES TO REPORT ────────────────────────────────────────────────
// A dollar cost. Nothing here can observe a bill, and a figure derived from a
// price table nobody re-reads is the guessed-speed failure of v24.0.9. It
// reports the units that bill — calls, uploaded bytes, image pixels — and says
// so plainly.
//
// USAGE
//   node scripts/benchmark-vision-providers.mjs --corpus ~/fl-screenshots --init
//       → runs the cheapest configured provider once per image and writes a
//         `<image>.expected.json` next to each, pre-filled with what it read.
//         Correct the values, set "verified": true, and they become ground truth.
//
//   node scripts/benchmark-vision-providers.mjs --corpus ~/fl-screenshots \
//       --providers workers-ai,gemini --repeat 3 --out bench.json
//       → the actual benchmark.
//
// Provider credentials come from the environment and are never written to the
// report. Keep them in the environment or in `wrangler secret`; never in this
// repository.

import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  SCORED_FIELDS, CRITICAL_FIELDS, scoreCase, summarizeProvider, stability,
  truthIsUsable, workerFieldKeys,
} from './lib/vision-bench.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ADMIN_TOKEN = 'bench-admin-token-not-a-real-credential';
const IMAGE_EXT = new Set(['.jpg', '.jpeg', '.png', '.webp']);
const MIME_BY_EXT = { '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp' };

// ─── args ────────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const out = { providers: null, repeat: 1, init: false, corpus: null, outFile: null, only: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--corpus') out.corpus = argv[++i];
    else if (a === '--providers') out.providers = String(argv[++i] || '').split(',').map(s => s.trim()).filter(Boolean);
    else if (a === '--repeat') out.repeat = Math.max(1, parseInt(argv[++i], 10) || 1);
    else if (a === '--out') out.outFile = argv[++i];
    else if (a === '--case') out.only = argv[++i];
    else if (a === '--init') out.init = true;
    else if (a === '--help' || a === '-h') out.help = true;
    else if (a.startsWith('--')) { console.error('Unknown option: ' + a); process.exit(64); }
  }
  return out;
}

// ─── in-memory KV, so no production state is touched ─────────────────────────

function makeKV() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async put(k, v) { m.set(k, v); },
    async delete(k) { m.delete(k); },
    async list({ prefix = '' } = {}) {
      return { keys: [...m.keys()].filter(k => k.startsWith(prefix)).map(name => ({ name })) };
    },
  };
}

/**
 * Workers AI has no `AI` binding outside the Workers runtime, so the shim calls
 * the documented REST equivalent with the same model id and the same payload
 * the adapter builds. It is the shipped ADAPTER under test, not a reimplemented
 * one — but the transport is not in-colo, so its latency is an upper bound and
 * the report says so rather than quietly comparing it against hosted APIs as if
 * it were the number production will see.
 */
function makeWorkersAIShim(accountId, apiToken, record) {
  return {
    async run(model, input) {
      const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/ai/run/${model}`;
      const body = JSON.stringify(input);
      record.providerBytes = body.length;
      const res = await fetch(url, {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + apiToken, 'Content-Type': 'application/json' },
        body,
      });
      if (!res.ok) throw new Error('workers-ai REST ' + res.status + ' ' + (await res.text()).slice(0, 160));
      const j = await res.json();
      return j?.result ?? j;
    },
  };
}

function buildEnv(kv, providerName, record) {
  const env = {
    BACKUPS: kv,
    ADMIN_TOKEN,
    VISION_PROVIDER: providerName,
    ALLOWED_ORIGIN: 'https://freightlogic-v2.fimseitef.workers.dev',
  };
  if (process.env.FL_VISION_MODEL) env.VISION_MODEL = process.env.FL_VISION_MODEL;
  if (providerName === 'workers-ai') {
    const acct = process.env.CLOUDFLARE_ACCOUNT_ID;
    const tok = process.env.CLOUDFLARE_API_TOKEN;
    if (acct && tok) env.AI = makeWorkersAIShim(acct, tok, record);
  }
  if (process.env.GEMINI_API_KEY) env.GEMINI_API_KEY = process.env.GEMINI_API_KEY;
  if (process.env.OPENAI_API_KEY) env.OPENAI_API_KEY = process.env.OPENAI_API_KEY;
  if (process.env.DEEPSEEK_API_KEY) env.DEEPSEEK_API_KEY = process.env.DEEPSEEK_API_KEY;
  if (process.env.DEEPSEEK_BASE_URL) env.DEEPSEEK_BASE_URL = process.env.DEEPSEEK_BASE_URL;
  return env;
}

function providerCredentialHint(name) {
  switch (name) {
    case 'workers-ai': return 'CLOUDFLARE_ACCOUNT_ID + CLOUDFLARE_API_TOKEN';
    case 'gemini': return 'GEMINI_API_KEY';
    case 'openai': return 'OPENAI_API_KEY';
    case 'deepseek': return 'DEEPSEEK_API_KEY';
    default: return 'provider credentials';
  }
}

function providerIsConfigured(name) {
  switch (name) {
    case 'workers-ai': return Boolean(process.env.CLOUDFLARE_ACCOUNT_ID && process.env.CLOUDFLARE_API_TOKEN);
    case 'gemini': return Boolean(process.env.GEMINI_API_KEY);
    case 'openai': return Boolean(process.env.OPENAI_API_KEY);
    case 'deepseek': return Boolean(process.env.DEEPSEEK_API_KEY);
    default: return false;
  }
}

// ─── corpus ──────────────────────────────────────────────────────────────────

const sidecarPath = (imgPath) => imgPath.replace(/\.[^.]+$/, '') + '.expected.json';

async function loadCorpus(dir) {
  let entries;
  try { entries = await fsp.readdir(dir, { withFileTypes: true }); }
  catch (e) { throw new Error(`Corpus directory not readable: ${dir}\n  ${e.message}`); }

  const cases = [];
  for (const ent of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (!ent.isFile()) continue;
    const ext = path.extname(ent.name).toLowerCase();
    if (!IMAGE_EXT.has(ext)) continue;
    const imgPath = path.join(dir, ent.name);
    const bytes = await fsp.readFile(imgPath);
    let sidecar = null, sidecarError = null;
    const sp = sidecarPath(imgPath);
    if (fs.existsSync(sp)) {
      try { sidecar = JSON.parse(await fsp.readFile(sp, 'utf8')); }
      catch (e) { sidecarError = 'sidecar is not valid JSON: ' + e.message; }
    }
    cases.push({
      name: ent.name,
      imgPath,
      sidecarPath: sp,
      mime: MIME_BY_EXT[ext],
      base64: bytes.toString('base64'),
      imageBytes: bytes.length,
      sidecar,
      sidecarError,
    });
  }
  return cases;
}

// ─── one call ────────────────────────────────────────────────────────────────

/** Classify a non-success response into one of the failure modes #252 asks to be
 *  counted SEPARATELY. "Could not produce JSON", "read nothing", "the provider
 *  errored" and "it is not configured" are four different product outcomes, and
 *  one combined error rate hides whichever of them actually decides the choice. */
function classifyFailure(status, body) {
  const err = String(body?.error || '');
  if (status === 501) return 'notConfigured';
  if (status === 429) return 'rateLimited';
  if (status === 502) return 'providerError';
  if (status === 422) return /valid JSON|no output/i.test(err) ? 'malformedJson' : 'nothingReadable';
  return 'other';
}

async function runOne(worker, env, token, kase, record) {
  const body = JSON.stringify({ image: kase.base64, mime: kase.mime });
  const req = new Request('https://worker.test/extract-image', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': String(Buffer.byteLength(body)),
      'X-Backup-Token': token,
      'X-Device-Id': 'bench-device',
    },
    body,
  });
  const t0 = performance.now();
  let res, parsed = null;
  try {
    res = await worker.fetch(req, env);
    parsed = await res.json().catch(() => null);
  } catch (e) {
    return { requestBytes: Buffer.byteLength(body), latencyMs: performance.now() - t0, failure: 'providerError', detail: String(e).slice(0, 200) };
  }
  const latencyMs = performance.now() - t0;
  const out = { requestBytes: Buffer.byteLength(body), providerBytes: record.providerBytes || null, latencyMs, status: res.status };
  if (res.status === 200 && parsed?.ok) {
    out.extraction = { fields: parsed.fields, fieldMeta: parsed.fieldMeta, observedCount: parsed.observedCount };
    out.model = parsed.model;
  } else {
    out.failure = classifyFailure(res.status, parsed);
    out.detail = String(parsed?.error || '').slice(0, 200);
  }
  return out;
}

// ─── report ──────────────────────────────────────────────────────────────────

const pct = (n) => (n === null || n === undefined ? '  —  ' : (n * 100).toFixed(1).padStart(5) + '%');
const ms = (n) => (n === null || n === undefined ? '  —  ' : Math.round(n) + 'ms');

function printProviderTable(summaries) {
  const w = (s, n) => String(s).padEnd(n);
  console.log('');
  console.log('  ' + w('PROVIDER', 14) + w('EXACT', 8) + w('CRIT', 8) + w('SILENT', 8) + w('DH-0', 6) + w('BADJSON', 9) + w('p50', 9) + w('p95', 9) + w('REQ/call', 10));
  console.log('  ' + '─'.repeat(81));
  for (const [name, s] of Object.entries(summaries)) {
    console.log('  ' + w(name, 14)
      + w(pct(s.accuracyAll), 8)
      + w(pct(s.accuracyCritical), 8)
      + w(pct(s.silentCriticalErrorRate), 8)
      + w(s.fabricatedZeroDeadhead, 6)
      + w(pct(s.malformedJsonRate), 9)
      + w(ms(s.latencyMs.p50), 9)
      + w(ms(s.latencyMs.p95), 9)
      + w((s.requestBytes.mean / 1024).toFixed(0) + 'KB', 10));
  }
  console.log('');
  console.log('  EXACT   field exact-match accuracy over fields that HAD a value to read');
  console.log('  CRIT    the same, over pay / miles / deadhead / origin / destination / pickup clock');
  console.log('  SILENT  critical fields that arrived WRONG or INVENTED and were NOT flagged');
  console.log('          UNCERTAIN — the errors a driver would not be asked to check. Lower is');
  console.log('          better and this column, not EXACT, is the one that should pick a default.');
  console.log('  DH-0    times an unstated deadhead arrived as 0. Any number above zero');
  console.log('          disqualifies a provider outright: that is a verified zero the operator');
  console.log('          never supplied, and canonical economics is entitled to believe it.');
  console.log('  BADJSON share of CALLS whose output could not be parsed as JSON at all.');
  console.log('');
}

function printFailures(summaries) {
  let any = false;
  for (const [name, s] of Object.entries(summaries)) {
    const f = Object.entries(s.failures).filter(([, v]) => v > 0);
    if (!f.length) continue;
    if (!any) { console.log('  Failures by mode (counted separately — they are different outcomes):'); any = true; }
    console.log('    ' + name.padEnd(14) + f.map(([k, v]) => `${k}=${v}`).join('  '));
  }
  if (any) console.log('');
}

function printWorstFields(summaries, perProviderCases) {
  for (const [name, cases] of Object.entries(perProviderCases)) {
    const bad = [];
    for (const c of cases) {
      if (!c.score) continue;
      for (const key of CRITICAL_FIELDS) {
        const f = c.score.perField[key];
        if (f.outcome === 'wrong' || f.outcome === 'fabricated') {
          bad.push(`      ${c.name} · ${key}: expected ${JSON.stringify(f.expected)}, got ${JSON.stringify(f.got)} [${f.state}${f.silent ? ', UNFLAGGED' : ''}]`);
        }
      }
    }
    if (bad.length) {
      console.log(`  ${name} — critical-field errors (${bad.length}):`);
      console.log(bad.slice(0, 25).join('\n'));
      if (bad.length > 25) console.log(`      … and ${bad.length - 25} more (see --out JSON)`);
      console.log('');
    }
    void summaries;
  }
}

// ─── init mode ───────────────────────────────────────────────────────────────

/** Seed ground-truth sidecars from one provider's reading so the operator
 *  CORRECTS eighteen fields instead of typing them. The seeded file is marked
 *  `"verified": false` and records which model produced it; `truthIsUsable()`
 *  scores nothing until a human flips that flag, which is the mitigation for the
 *  obvious bias in seeding truth from a model. */
async function writeSidecar(kase, extraction, provider, model) {
  const fields = {};
  for (const key of SCORED_FIELDS) fields[key] = extraction?.fields?.[key] ?? null;
  const payload = {
    _README: [
      'Ground truth for one benchmark screenshot. Correct every value to what is',
      'ACTUALLY LEGIBLE in the image, then set "verified": true.',
      'A field that is NOT in the image must stay null — especially deadheadMiles.',
      'null means "the posting does not state one"; 0 means "the posting says zero".',
      'Those are different facts and the benchmark scores them differently.',
    ],
    image: kase.name,
    verified: false,
    seededBy: `${provider} / ${model || 'unknown model'}`,
    seededAt: new Date().toISOString(),
    fields,
  };
  await fsp.writeFile(kase.sidecarPath, JSON.stringify(payload, null, 2) + '\n');
}

// ─── main ────────────────────────────────────────────────────────────────────

function usage() {
  console.log(`
FreightLogic vision provider benchmark (Issue #252)

  --corpus <dir>        REQUIRED. Directory of screenshots. Keep it OUTSIDE this
                        repository — they are operator business data.
  --init                Seed a ground-truth sidecar per image from one provider's
                        reading, for you to correct. Scores nothing.
  --providers a,b,c     Providers to measure. Default: every configured one.
                        Known: workers-ai, gemini, openai, deepseek
  --repeat N            Run each image N times per provider to measure stability.
  --case <filename>     Limit to one image.
  --out <file.json>     Write the full per-field result. Credentials are never
                        included.

Credentials are read from the environment, never from this repository:
  workers-ai  CLOUDFLARE_ACCOUNT_ID + CLOUDFLARE_API_TOKEN
  gemini      GEMINI_API_KEY
  openai      OPENAI_API_KEY
  deepseek    DEEPSEEK_API_KEY  (optional DEEPSEEK_BASE_URL)
`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { usage(); return 0; }

  if (!args.corpus) {
    console.error('\n  --corpus <dir> is required.\n');
    console.error('  There is deliberately no default: real load screenshots carry broker');
    console.error('  names, rates and lanes, and this repository publishes its own root as a');
    console.error('  document origin. Keep the corpus outside the checkout.\n');
    usage();
    return 64;
  }

  // The scored field list claims to mirror the Worker's contract. Check it
  // against the Worker's actual source rather than trusting the claim — a
  // benchmark measuring a stale field list is measuring the wrong contract.
  const workerSrc = await fsp.readFile(path.join(ROOT, 'cloud-backup-worker.js'), 'utf8');
  const wk = workerFieldKeys(workerSrc);
  const drift = [...wk.filter(k => !SCORED_FIELDS.includes(k)).map(k => '+' + k),
                 ...SCORED_FIELDS.filter(k => !wk.includes(k)).map(k => '-' + k)];
  if (drift.length) {
    console.error('\n  FAIL — scripts/lib/vision-bench.mjs SCORED_FIELDS has drifted from the');
    console.error('  Worker\'s VISION_FIELD_SPEC: ' + drift.join(' ') + '\n');
    return 1;
  }

  let cases = await loadCorpus(args.corpus);
  if (args.only) cases = cases.filter(c => c.name === args.only);
  if (!cases.length) {
    console.error(`\n  No images found in ${args.corpus} (looking for .jpg/.jpeg/.png/.webp).\n`);
    return 1;
  }

  const known = ['workers-ai', 'gemini', 'openai', 'deepseek'];
  let providers = args.providers || known.filter(providerIsConfigured);
  const unknown = providers.filter(p => !known.includes(p));
  if (unknown.length) { console.error('  Unknown provider(s): ' + unknown.join(', ')); return 64; }
  if (!providers.length) {
    console.error('\n  No provider is configured. Set at least one credential set:\n');
    for (const p of known) console.error(`    ${p.padEnd(12)} ${providerCredentialHint(p)}`);
    console.error('');
    return 1;
  }
  const unconfigured = providers.filter(p => !providerIsConfigured(p));
  if (unconfigured.length) {
    // Named as not-configured rather than run and reported as a failure: a
    // provider that was never asked anything has no error rate, and recording
    // one would make a missing credential look like a bad model.
    console.error('\n  Not configured, skipping: ' + unconfigured.map(p => `${p} (needs ${providerCredentialHint(p)})`).join('; ') + '\n');
    providers = providers.filter(p => providerIsConfigured(p));
    if (!providers.length) return 1;
  }

  const workerMod = await import(pathToFileURL(path.join(ROOT, 'cloud-backup-worker.js')).href);
  const worker = workerMod.default;

  console.log(`\n  Corpus: ${args.corpus}`);
  console.log(`  Images: ${cases.length}    Providers: ${providers.join(', ')}    Repeats: ${args.repeat}`);
  if (args.init) console.log('  Mode:   INIT — seeding ground-truth sidecars, scoring nothing.');
  console.log('');

  const perProviderCases = {};
  const summaries = {};
  const rawResults = {};

  for (const providerName of providers) {
    const kv = makeKV();
    const record = {};
    const env = buildEnv(kv, providerName, record);

    // A REAL credential through the REAL invite/claim path, against in-memory
    // KV. Nothing in production is created, read or spent.
    const inv = await (await worker.fetch(new Request('https://worker.test/admin/invites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Admin-Token': ADMIN_TOKEN },
      body: JSON.stringify({ name: 'Benchmark' }),
    }), env)).json();
    const claimed = await (await worker.fetch(new Request('https://worker.test/claim', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.7' },
      body: JSON.stringify({ code: inv.code }),
    }), env)).json();
    const token = claimed.token;
    if (!token) { console.error(`  ${providerName}: could not mint a benchmark credential — ${JSON.stringify(claimed).slice(0, 160)}`); return 1; }

    const results = [];
    rawResults[providerName] = [];

    for (const kase of cases) {
      const runs = [];
      for (let r = 0; r < args.repeat; r++) {
        record.providerBytes = null;
        process.stdout.write(`  ${providerName} · ${kase.name}${args.repeat > 1 ? ` (${r + 1}/${args.repeat})` : ''} … `);
        const out = await runOne(worker, env, token, kase, record);
        console.log(out.failure ? `${out.failure}` : `${Math.round(out.latencyMs)}ms, ${out.extraction.observedCount} fields`);
        runs.push(out);
      }
      const best = runs.find(r => r.extraction) || runs[0];

      if (args.init) {
        if (best.extraction) await writeSidecar(kase, best.extraction, providerName, best.model);
        results.push({ name: kase.name, ...best, score: null });
        rawResults[providerName].push({ name: kase.name, runs });
        continue;
      }

      let score = null, skipped = null;
      if (best.extraction) {
        if (kase.sidecarError) skipped = kase.sidecarError;
        else {
          const usable = truthIsUsable(kase.sidecar);
          if (!usable.usable) skipped = usable.why;
          else score = scoreCase(kase.sidecar.fields, best.extraction);
        }
      }
      results.push({
        name: kase.name, imageBytes: kase.imageBytes,
        requestBytes: best.requestBytes, providerBytes: best.providerBytes,
        latencyMs: best.latencyMs, failure: best.failure, detail: best.detail,
        model: best.model, score, skipped,
        stability: args.repeat > 1 ? stability(runs) : null,
      });
      rawResults[providerName].push({ name: kase.name, runs, score, skipped });
    }

    perProviderCases[providerName] = results;
    summaries[providerName] = summarizeProvider(results);
    console.log('');
  }

  if (args.init) {
    const wrote = Object.values(perProviderCases)[0].filter(r => !r.failure).length;
    console.log(`  Wrote ${wrote} ground-truth sidecar(s) next to the images.`);
    console.log('');
    console.log('  NEXT: open each *.expected.json, fix every value to what the image');
    console.log('  actually shows, and set "verified": true. Until you do, that case is');
    console.log('  SKIPPED rather than scored — a benchmark graded against one model\'s own');
    console.log('  reading would score that model highest by construction.');
    console.log('');
    console.log('  Leave a field null if the screenshot does not state it. deadheadMiles');
    console.log('  especially: null is "not stated", 0 is "stated as zero", and the whole');
    console.log('  app treats those as different facts.');
    console.log('');
    return 0;
  }

  const skippedCases = Object.values(perProviderCases)[0].filter(r => r.skipped);
  if (skippedCases.length) {
    console.log(`  ${skippedCases.length} case(s) not scored (no usable ground truth):`);
    for (const s of skippedCases.slice(0, 12)) console.log(`    ${s.name}: ${s.skipped}`);
    if (skippedCases.length > 12) console.log(`    … and ${skippedCases.length - 12} more`);
    console.log('');
  }

  const anyScored = Object.values(summaries).some(s => s.scoredCases > 0);
  printProviderTable(summaries);
  printFailures(summaries);
  if (anyScored) printWorstFields(summaries, perProviderCases);

  if (args.repeat > 1) {
    console.log('  Stability across repeats (identical extraction / runs):');
    for (const [name, rs] of Object.entries(perProviderCases)) {
      const vals = rs.map(r => r.stability).filter(v => v !== null);
      const mean = vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : null;
      console.log(`    ${name.padEnd(14)} ${pct(mean)}   (a provider that reads a load differently on a re-run has not earned the default)`);
    }
    console.log('');
  }

  console.log('  Cost is NOT measured here, and is deliberately not estimated.');
  console.log('  What bills is recorded instead, per provider:');
  for (const [name, s] of Object.entries(summaries)) {
    console.log(`    ${name.padEnd(14)} ${s.calls} call(s), ${(s.requestBytes.total / 1024 / 1024).toFixed(2)}MB uploaded`);
  }
  console.log('    workers-ai bills neurons per call against a free daily allocation;');
  console.log('    gemini/openai/deepseek bill per token. Read the live figure from the');
  console.log('    provider dashboard after a run — this script cannot see a bill.');
  console.log('');
  if (providers.includes('workers-ai')) {
    console.log('  NOTE: workers-ai here goes through the Cloudflare REST API, because the');
    console.log('  `AI` binding does not exist outside the Workers runtime. The ADAPTER is the');
    console.log('  shipped one; the transport is not in-colo, so its latency is an upper bound');
    console.log('  and should not be compared against the hosted APIs as if it were what');
    console.log('  production will see.');
    console.log('');
  }

  if (!anyScored) {
    console.log('  No case was scored, so no accuracy figure above means anything yet.');
    console.log('  Run with --init first, correct the sidecars, then re-run.');
    console.log('');
  }

  if (args.outFile) {
    // Nothing from the environment is serialized. The report carries model ids,
    // timings and field values; no credential is ever in scope here, and this is
    // written down so a later "just include env for debugging" is a visible
    // change rather than a quiet one.
    const payload = {
      generatedAt: new Date().toISOString(),
      corpus: args.corpus,
      repeat: args.repeat,
      providers,
      summaries,
      cases: rawResults,
      note: 'Credentials are never recorded. Cost is not measured; see the calls/bytes counters.',
    };
    await fsp.writeFile(args.outFile, JSON.stringify(payload, null, 2) + '\n');
    console.log(`  Full per-field result written to ${args.outFile}`);
    console.log('');
  }

  // A provider that fabricated a deadhead zero fails the run outright, whatever
  // its accuracy. That value reaches canonical economics as a fact the operator
  // never supplied, which is the one error class this app has spent five
  // releases removing.
  const fabricators = Object.entries(summaries).filter(([, s]) => s.fabricatedZeroDeadhead > 0).map(([n]) => n);
  if (fabricators.length) {
    console.log(`  FAIL — fabricated an unstated deadhead as 0: ${fabricators.join(', ')}`);
    console.log('  That provider must not be the default at any accuracy.');
    console.log('');
    return 1;
  }
  return 0;
}

main().then(c => process.exit(c)).catch(e => { console.error(e); process.exit(1); });
