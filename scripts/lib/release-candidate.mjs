/* Release-generation derivation — "which build is this release, and which
 * Worker generation does it declare?", read from the repository's own
 * authorities instead of from a literal somebody has to remember to update.
 *
 * Why this is one shared module and not logic inlined in the gate. On
 * 2026-09-14 the gpt lane found `scripts/verify-rollback.mjs` carrying
 * `PRODUCTION_CANDIDATE = '8d5b82b8…'` (an obsolete candidate) and
 * `if (srcWorkerVer === '14')` while the release had moved to v24.0.9 and
 * Worker v15. Neither literal was wrong when it was written; both went stale
 * silently, and the second one made the gate FAIL FOR THE WRONG REASON — a
 * release gate reporting a Worker-generation mismatch that was really its own
 * staleness. That is the one failure mode a gate may never have.
 *
 * Deriving fixes the specific instance. Putting the derivation HERE, where the
 * gate and its regression test both import it, is what stops the fix from
 * rotting the same way: a second copy inside the test could drift from the gate
 * and each would report green about the other's blind spot — exactly the shape
 * of the 2026-09-13 deploy-coverage defect that `deploy-assets.mjs` exists to
 * prevent, one level up.
 *
 * No npm dependencies — the release tooling is standalone.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '../..');

/* The living release authorities. Each is continuously reconciled to the
 * current candidate rather than being a dated snapshot.
 *
 * Dated CERTIFICATION_STATE / ADDENDUM files are deliberately NOT read: they
 * correctly name the candidate that was current when they were written, so
 * reading them would manufacture a disagreement out of documents that are doing
 * their job. That distinction — living authority vs. historical snapshot — is
 * the same one `scripts/m7-certify.mjs` makes with explicit supersession. */
export const CANDIDATE_AUTHORITIES = [
  'docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md',
  'FIELD_TEST_CHECKLIST.md',
  'docs/COMPLETION_RELEASE_PLAN_2026-08-25.md',
];

/* Matches the labelled forms those documents actually use — "exact runtime Git
 * candidate", "Current runtime candidate", "Runtime Git SHA", "runtime
 * synchronization point", "exact runtime merge SHA" — and requires the SHA to
 * sit within 60 characters of the label.
 *
 * The proximity bound is load-bearing, not tidiness. These are markdown files,
 * so one paragraph is one line, and the very same line in
 * COMPLETION_RELEASE_PLAN also names the repository `main` head ("advanced
 * repository `main` to `a1a5f7dc…`"), which is NOT the runtime candidate.
 * A line-wide match would read both and report a disagreement that does not
 * exist. */
const CANDIDATE_RE =
  /(?:exact\s+)?runtime\s+(?:git\s+)?(?:merge\s+)?(?:candidate|sha|synchronization\s+point)[^\n`]{0,60}`([0-9a-f]{40})`/gi;

/** Every distinct runtime-candidate SHA a document labels, in order of first
 *  appearance. Unlabelled SHAs elsewhere in the text are ignored by design. */
export function candidateShasInText(text) {
  const out = [];
  CANDIDATE_RE.lastIndex = 0;
  let m;
  while ((m = CANDIDATE_RE.exec(String(text))) !== null) {
    if (!out.includes(m[1])) out.push(m[1]);
  }
  return out;
}

/** Read every authority and report what each one names.
 *
 *  Returns `{ readings, agreed }` where `readings` is one entry per authority
 *  (`{ rel, missing, shas }`) and `agreed` is the set of distinct SHAs claimed
 *  across all of them. A caller may only treat the candidate as derived when
 *  `agreed.length === 1`: zero means nothing to stand on, and more than one
 *  means the release record contradicts itself, which is a governance defect to
 *  report rather than a tie to break. */
export function deriveCandidate({ root = REPO_ROOT, files = CANDIDATE_AUTHORITIES, read = null } = {}) {
  const readFile = read ?? ((rel) => readFileSync(path.join(root, rel), 'utf8'));
  const readings = [];
  const agreed = [];
  for (const rel of files) {
    let text;
    try { text = readFile(rel); }
    catch { readings.push({ rel, missing: true, shas: [] }); continue; }
    const shas = candidateShasInText(text);
    readings.push({ rel, missing: false, shas });
    for (const s of shas) if (!agreed.includes(s)) agreed.push(s);
  }
  return { readings, agreed };
}

/* The Worker generation has exactly ONE declared source of truth: the parity
 * verifier's EXPECTED block. `scripts/deploy-backup-worker.sh` already derives
 * from it, for a documented reason — the v15 deploy was refused by that very
 * script while source, parity verifier and workflow all agreed on 15, because
 * one remaining guard still grepped the literal `workerVersion: "14"`.
 * Converting three of four copies and leaving the fourth is not a partial fix;
 * the remaining literal is still the one that fails the release.
 *
 * Note the division of labour: deriving is right for anything whose job is
 * "describe whatever generation this checkout declares". It is WRONG in
 * tests/unit/cache-generation.spec.mjs CG-09, which pins the Worker version by
 * hand on purpose so an unintended Worker bump riding along with an app bump has
 * to be seen and justified by a human. Do not "fix" that one to match this. */
export function declaredWorkerVersion(parityText) {
  return String(parityText).match(/workerVersion:\s*"(\d+)"/)?.[1] ?? null;
}

/** The Worker generation the shipped Worker source actually answers with. */
export function sourceWorkerVersion(workerText) {
  return String(workerText).match(/version:\s*'(\d+)'/)?.[1] ?? null;
}
