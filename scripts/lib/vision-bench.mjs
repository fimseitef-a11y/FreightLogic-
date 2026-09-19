// Vision-provider benchmark scoring — the pure half of Issue #252's
// "for each provider candidate measure ..." requirement.
//
// WHY THIS IS A SEPARATE MODULE. `scripts/benchmark-vision-providers.mjs` runs
// it against real providers over real screenshots; `tests/unit/vision-benchmark.spec.mjs`
// runs it against a fixture corpus with no network. Both import THIS file, for
// the same reason the gate and its regression both import
// `scripts/lib/deploy-assets.mjs`: a second copy of the scoring rules is a
// second thing to drift, which is the 2026-09-13 defect shape (two lists
// disagreeing while both gates read green).
//
// WHAT IT DELIBERATELY DOES NOT DO:
//
//  * It does not re-implement the normalizer. The runner drives the REAL
//    exported Worker fetch handler, so what is scored is what production
//    returns — route, auth gate, ceilings, tri-state normalizer and all. A
//    benchmark of a parallel implementation measures the parallel one.
//  * It does not print a dollar figure. Nothing here can observe a bill, and
//    a cost derived from a price table nobody re-reads is the guessed-speed
//    failure of v24.0.9 wearing a different hat. What it reports instead is
//    the units that actually bill — calls made, bytes uploaded, image
//    pixels — and says plainly that money is not measured.
//  * It does not treat every error as one number. "The model read it wrong",
//    "the model invented a value that is not in the image" and "the model
//    could not produce JSON" are three different product failures with three
//    different consequences, and averaging them hides the one that matters.

/** Fields that reach canonical economics or a blocking gate. An error here is
 *  materially different from an error in `notes`: pay/miles feed True RPM and
 *  the bid range, origin/destination feed market classification, and the pickup
 *  clock feeds the v24.0.9 feasibility gate. */
export const CRITICAL_FIELDS = Object.freeze([
  'pay', 'loadedMiles', 'deadheadMiles', 'origin', 'destination', 'pickupDate', 'pickupTime',
]);

/** The observational contract, mirrored from the Worker's VISION_FIELD_SPEC.
 *  Kept as a list rather than imported because the Worker exports only its
 *  fetch handler; `assertFieldListMatchesWorker()` below is what stops the two
 *  drifting, and it reads the Worker source rather than trusting this copy. */
export const SCORED_FIELDS = Object.freeze([
  'orderNo', 'broker', 'customer', 'origin', 'destination', 'pay',
  'loadedMiles', 'deadheadMiles', 'pickupDate', 'pickupTime',
  'deliveryDate', 'deliveryTime', 'timezone', 'weight', 'pieces',
  'dimensions', 'commodity', 'notes',
]);

/** US/CA state and province tokens, used ONLY to classify a place difference as
 *  "near" rather than to accept it as correct. Being explicit about the
 *  difference is the point: `Chicago` and `Chicago IL` are the same place read
 *  with less precision, while `Chicago` and `Chicago Heights IL` are not, and a
 *  fuzzy matcher that folded both into "correct" would flatter every provider. */
const STATE_TOKENS = new Set([
  'al','ak','az','ar','ca','co','ct','de','fl','ga','hi','id','il','in','ia','ks','ky','la',
  'me','md','ma','mi','mn','ms','mo','mt','ne','nv','nh','nj','nm','ny','nc','nd','oh','ok',
  'or','pa','ri','sc','sd','tn','tx','ut','vt','va','wa','wv','wi','wy','dc',
  'ab','bc','mb','nb','nl','ns','nt','nu','on','pe','qc','sk','yt',
]);

function placeTokens(s) {
  return String(s).toLowerCase().replace(/[.,]/g, ' ').split(/\s+/).filter(Boolean);
}

/** Token-sequence comparison, the v24.0.2 place rule: equal token sequences are
 *  equal, and exactly one extra trailing state token is a QUALIFICATION of a
 *  less specific value rather than a different place. Anything else differs. */
function compareStrings(gt, got) {
  const a = placeTokens(gt), b = placeTokens(got);
  if (a.join(' ') === b.join(' ')) return 'correct';
  const [shorter, longer] = a.length <= b.length ? [a, b] : [b, a];
  if (longer.length === shorter.length + 1 &&
      STATE_TOKENS.has(longer[longer.length - 1]) &&
      longer.slice(0, shorter.length).join(' ') === shorter.join(' ')) {
    return 'near';
  }
  return 'wrong';
}

function compareNumbers(gt, got) {
  // Money is normalized to cents by the Worker; miles/weight/pieces are integers.
  // No tolerance band: a benchmark that accepted "close enough" miles would be
  // accepting exactly the OCR-confusable digits (345/845, 1,500/150) #252 names
  // as a required corpus case.
  return Math.abs(Number(gt) - Number(got)) < 0.005 ? 'correct' : 'wrong';
}

/**
 * Classify one field against ground truth.
 *
 * Six outcomes, because they are six different things to a driver:
 *   correct     — matches
 *   near        — a place read at lower precision (`Chicago` for `Chicago IL`)
 *   wrong       — a value that is in the image, read as something else
 *   missed      — a value that is in the image, not read at all (costs typing)
 *   fabricated  — a value that is NOT in the image (costs trust)
 *   absentOk    — correctly left UNKNOWN
 */
export function classifyField(key, gtValue, gotValue, state) {
  const gtNull = gtValue === null || gtValue === undefined || gtValue === '';
  const gotNull = gotValue === null || gotValue === undefined || gotValue === '';

  if (gtNull && gotNull) return { outcome: 'absentOk', silent: false };
  if (gtNull && !gotNull) {
    return {
      outcome: 'fabricated',
      silent: state === 'OBSERVED',
      // The single worst output this endpoint can produce. An unstated deadhead
      // arriving as 0 is not an inaccuracy — it is a VERIFIED ZERO the operator
      // never supplied, and it is the defect class v24.0.1/.4/.5/.21 each fixed
      // one layer at a time. It gets its own counter so it can never be averaged
      // into a respectable-looking error rate.
      fabricatedZeroDeadhead: key === 'deadheadMiles' && Number(gotValue) === 0,
    };
  }
  if (!gtNull && gotNull) return { outcome: 'missed', silent: false };

  const verdict = (typeof gtValue === 'number' || typeof gotValue === 'number')
    ? compareNumbers(gtValue, gotValue)
    : compareStrings(gtValue, gotValue);

  // A wrong value the review step flags is recoverable; a wrong value presented
  // as OBSERVED is the one that reaches the evaluator unchallenged. Splitting
  // them is what makes this benchmark able to pick a provider: a model that is
  // less accurate but honest about which reads are shaky is the safer default.
  return { outcome: verdict, silent: verdict === 'wrong' && state === 'OBSERVED' };
}

const EMPTY_TALLY = () => ({
  correct: 0, near: 0, wrong: 0, missed: 0, fabricated: 0, absentOk: 0,
  silentWrong: 0, silentFabricated: 0, fabricatedZeroDeadhead: 0,
});

function addTally(into, cls) {
  into[cls.outcome] = (into[cls.outcome] || 0) + 1;
  if (cls.silent && cls.outcome === 'wrong') into.silentWrong++;
  if (cls.silent && cls.outcome === 'fabricated') into.silentFabricated++;
  if (cls.fabricatedZeroDeadhead) into.fabricatedZeroDeadhead++;
}

/**
 * Score one extraction against one case's ground truth.
 *
 * `extraction` is the Worker's own success payload (`{ fields, fieldMeta }`),
 * unmodified. `truth` is the operator-verified sidecar's `fields` object.
 */
export function scoreCase(truth, extraction) {
  const all = EMPTY_TALLY();
  const critical = EMPTY_TALLY();
  const perField = {};

  for (const key of SCORED_FIELDS) {
    const state = extraction?.fieldMeta?.[key]?.state || 'ABSENT';
    const cls = classifyField(key, truth ? truth[key] : null, extraction?.fields?.[key], state);
    perField[key] = { ...cls, state, expected: truth ? (truth[key] ?? null) : null, got: extraction?.fields?.[key] ?? null };
    addTally(all, cls);
    if (CRITICAL_FIELDS.includes(key)) addTally(critical, cls);
  }
  return { all, critical, perField };
}

/** Exact-match accuracy over the fields that HAD a value to read. Absences the
 *  model correctly left alone are excluded from the denominator on purpose:
 *  counting them would let a provider that reads nothing score well on a sparse
 *  corpus, which is the metric gaming this benchmark exists to avoid. */
export function accuracy(tally) {
  const denom = tally.correct + tally.near + tally.wrong + tally.missed;
  return denom === 0 ? null : tally.correct / denom;
}

/** The rate at which a critical field reached the app as a WRONG or INVENTED
 *  value the review step did not flag. This is #252's "critical-field error
 *  rate", narrowed to the errors a driver would not see. */
export function silentCriticalErrorRate(tally) {
  const denom = tally.correct + tally.near + tally.wrong + tally.missed + tally.fabricated + tally.absentOk;
  return denom === 0 ? null : (tally.silentWrong + tally.silentFabricated) / denom;
}

export function percentile(values, p) {
  if (!values.length) return null;
  const s = [...values].sort((a, b) => a - b);
  const i = Math.min(s.length - 1, Math.max(0, Math.ceil((p / 100) * s.length) - 1));
  return s[i];
}

/** Fold per-case results into one provider summary. */
export function summarizeProvider(caseResults) {
  const all = EMPTY_TALLY();
  const critical = EMPTY_TALLY();
  const latencies = [];
  let bytesSent = 0, calls = 0;
  const failures = { malformedJson: 0, nothingReadable: 0, providerError: 0, notConfigured: 0, rateLimited: 0, other: 0 };

  for (const r of caseResults) {
    calls++;
    bytesSent += r.requestBytes || 0;
    if (Number.isFinite(r.latencyMs)) latencies.push(r.latencyMs);
    if (r.failure) { failures[r.failure] = (failures[r.failure] || 0) + 1; continue; }
    if (!r.score) continue;
    for (const k of Object.keys(all)) { all[k] += r.score.all[k] || 0; critical[k] += r.score.critical[k] || 0; }
  }

  const scored = caseResults.filter(r => r.score).length;
  return {
    cases: caseResults.length,
    scoredCases: scored,
    calls,
    all,
    critical,
    accuracyAll: accuracy(all),
    accuracyCritical: accuracy(critical),
    silentCriticalErrorRate: silentCriticalErrorRate(critical),
    fabricatedZeroDeadhead: critical.fabricatedZeroDeadhead,
    failures,
    // #252 asks for "malformed JSON rate" by name. It is the share of CALLS, not
    // of scored cases: a provider that fails to produce JSON has no scored case,
    // so a denominator of scored cases would make a provider look better the
    // more often it failed.
    malformedJsonRate: calls ? failures.malformedJson / calls : null,
    latencyMs: { p50: percentile(latencies, 50), p95: percentile(latencies, 95), max: latencies.length ? Math.max(...latencies) : null },
    requestBytes: { total: bytesSent, mean: calls ? Math.round(bytesSent / calls) : 0 },
  };
}

/**
 * Stability across repeats: did the same image produce the same field values?
 *
 * A provider that reads a load correctly once and differently twice has not
 * earned the default. Measured over the normalized field object so that a
 * confidence score wobbling does not read as an unstable extraction.
 */
export function stability(runsForCase) {
  const usable = runsForCase.filter(r => r.extraction);
  if (usable.length < 2) return null;
  const first = JSON.stringify(usable[0].extraction.fields);
  return usable.filter(r => JSON.stringify(r.extraction.fields) === first).length / usable.length;
}

/**
 * Ground-truth sidecars are REFUSED unless the operator marked them verified.
 *
 * `--init` seeds a sidecar from a model's own reading so the operator corrects
 * values instead of typing eighteen fields per screenshot. That saves real work
 * and it biases the ground truth toward whichever model seeded it, so the gate
 * is the mitigation: a seeded sidecar scores nothing until a human has looked at
 * it and said so. `seededBy` stays in the file so a reader can always see which
 * model's reading the truth started from.
 */
export function truthIsUsable(sidecar) {
  if (!sidecar || typeof sidecar !== 'object') return { usable: false, why: 'missing or unreadable sidecar' };
  if (sidecar.verified !== true) {
    return { usable: false, why: sidecar.seededBy
      ? `seeded from "${sidecar.seededBy}" and not yet verified — review it and set "verified": true`
      : 'sidecar is not marked "verified": true' };
  }
  if (!sidecar.fields || typeof sidecar.fields !== 'object') return { usable: false, why: 'sidecar has no "fields" object' };
  return { usable: true, why: null };
}

/** Read the Worker's own VISION_FIELD_SPEC keys out of its source, so the field
 *  list above cannot silently fall behind the contract it claims to mirror. */
export function workerFieldKeys(workerSource) {
  const m = /const VISION_FIELD_SPEC = \{([\s\S]*?)\n\};/.exec(workerSource);
  if (!m) throw new Error('VISION_FIELD_SPEC not found in cloud-backup-worker.js');
  return m[1].split('\n')
    .map(l => /^\s*([A-Za-z0-9_]+)\s*:/.exec(l.replace(/\/\/.*$/, '')))
    .filter(Boolean).map(x => x[1]);
}
