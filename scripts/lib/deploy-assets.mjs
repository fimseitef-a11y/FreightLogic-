/* Deployment asset inventory — the single source of truth for "what does the
 * running app actually request, and can the deployment serve it?"
 *
 * Why this is one shared module and not two copies. On 2026-09-13, against main
 * c02ed36, `scripts/verify-cloudflare-parity.mjs` reported 24/24 checks PASS
 * while `admin-driver-ui.js` returned HTTP 404 from the deployed origin. The
 * cause was two lists that disagreed and nothing comparing them: the service
 * worker precached the file in CORE and injected a <script> tag for it into
 * every HTML response, while `.assetsignore` told the Cloudflare Workers assets
 * uploader never to publish it.
 *
 * Duplicating this logic between the release gate and its regression test would
 * reproduce exactly that failure mode one level up — two matchers that can drift
 * apart, each reporting green about the other's blind spot. Both
 * `scripts/verify-cloudflare-parity.mjs` (live gate) and
 * `tests/unit/deploy-asset-coverage.spec.mjs` (offline regression) import from
 * here, so they cannot disagree about what is declared or what is excluded.
 *
 * No npm dependencies — the parity verifier is a standalone deploy gate.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '../..');

const read = (rel) => readFileSync(path.join(REPO_ROOT, rel), 'utf8');

/** Strip the `?v=` generation and any `./` prefix — identity is the PATH.
 *  Mirrors `normalizeAssetPath()` in service-worker.js. */
function assetPath(ref) {
  return ref.split('?')[0].replace(/^\.?\//, '');
}

/**
 * Every same-origin asset the running app requests, as
 * `Map<path, { ref, requesters:Set<string> }>` where `ref` keeps the `?v=`
 * generation so a live fetch asks for exactly what the browser asks for.
 *
 * Collected from the real declarations rather than a maintained list: a curated
 * inventory is one more thing to keep in sync, and falling out of sync is the
 * defect this module exists to catch. The five sources are deliberately
 * exhaustive, because the two that no markup grep can see are the ones that
 * failed:
 *
 *   - the service worker's `CORE` precache list (also what `KNOWN_ASSET_PATHS`
 *     derives from, so anything here is a path the worker will serve);
 *   - its install-blocking `critical` array (a miss aborts install outright);
 *   - the `ADMIN_UI_TAG` / `MIDWEST_STACK_TAG` <script> tags it INJECTS into
 *     every HTML response — neither appears in index.html;
 *   - index.html's own same-origin src/href references;
 *   - sw-bridge.js's dynamic `import()`, requested by no markup at all, which
 *     is why CG-04/CG-05 could never see modern-shell.js.
 */
export function declaredRuntimeAssets() {
  const sw = read('service-worker.js');
  const index = read('index.html');
  const bridge = read('sw-bridge.js');
  const found = new Map();
  const problems = [];

  const addRef = (ref, requester) => {
    const p = assetPath(ref);
    if (!p || p === '/') return; // the origin root is index.html by another name
    if (!found.has(p)) found.set(p, { ref: ref.replace(/^\.?\//, ''), requesters: new Set() });
    if (ref.includes('?v=')) found.get(p).ref = ref.replace(/^\.?\//, '');
    found.get(p).requesters.add(requester);
  };

  // Both arrays mix quoted literals with bare const identifiers — `APP_SHELL`
  // stands for './index.html' in CORE and in the critical shell. Resolving them
  // matters: a literals-only scan silently drops the app shell itself, and a
  // silently shorter inventory is the failure shape this module exists to catch.
  const constRefs = new Map();
  for (const m of sw.matchAll(/^const ([A-Z_][A-Z0-9_]*) = '([^']+)';/gm)) constRefs.set(m[1], m[2]);

  const collectArray = (rawBody, requester) => {
    for (const m of rawBody.matchAll(/'([^']+)'/g)) addRef(m[1], requester);
    // Comments are stripped before the identifier scan: CORE's own X-10 note
    // contains the bare word "CDN", which would otherwise read as an
    // unresolvable entry and report a problem that is not one.
    const body = rawBody.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
    for (const m of body.matchAll(/(?:^|[,[\s])([A-Z_][A-Z0-9_]*)(?=[,\]\s]|$)/g)) {
      const resolved = constRefs.get(m[1]);
      if (resolved) addRef(resolved, requester);
      else problems.push(`${requester} references identifier ${m[1]}, which this module cannot resolve to a path`);
    }
  };

  const coreMatch = sw.match(/const CORE = \[([\s\S]*?)\n\];/);
  if (coreMatch) collectArray(coreMatch[1], 'service-worker.js CORE');
  else problems.push('could not locate the CORE array in service-worker.js');

  const criticalMatch = sw.match(/const critical = \[([^\]]*)\]/);
  if (criticalMatch) collectArray(criticalMatch[1], 'service-worker.js critical shell');
  else problems.push('could not locate the `const critical = [...]` array in service-worker.js');

  for (const constName of ['MIDWEST_STACK_TAG']) {
    const m = sw.match(new RegExp('const ' + constName + " = '<script src=\"([^\"]+)\""));
    if (m) addRef(m[1], `service-worker.js ${constName} (injected)`);
    else problems.push(`could not read ${constName} from service-worker.js`);
  }

  for (const m of index.matchAll(/(?:src|href)="([^"]+)"/g)) {
    const ref = m[1];
    if (/^(https?:)?\/\//.test(ref) || ref.startsWith('data:') || ref.startsWith('#')) continue;
    addRef(ref, 'index.html');
  }

  for (const m of bridge.matchAll(/import\('([^']+)'\)/g)) addRef(m[1], 'sw-bridge.js dynamic import');

  // A source this module cannot parse is reported, never silently dropped:
  // an empty inventory would otherwise read as "nothing is broken".
  return { assets: found, problems };
}

export function assetsIgnorePatterns() {
  try {
    return read('.assetsignore')
      .split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  } catch {
    return []; // no exclusion file: nothing is excluded
  }
}

/**
 * A deliberately small gitignore-subset matcher covering the syntax
 * `.assetsignore` actually uses: bare names, anchored paths, directory entries,
 * `*` / `**` globs, and `!` negation. `wrangler.jsonc` publishes
 * `assets.directory: "."` — the whole repository — minus whatever this excludes.
 *
 * It errs in one direction only: it may over-report a match, never under-report
 * one. A false "this asset is excluded" is a loud failure a human resolves in a
 * minute; a missed exclusion is the silent production 404 this module exists to
 * prevent.
 *
 * Returns `(filePath) => { excluded, by }`, where `by` names the pattern that
 * decided it — which is what turns an unexplained 404 into a one-line diagnosis.
 */
export function assetsIgnoreMatcher(patterns = assetsIgnorePatterns()) {
  const GLOBSTAR = '\u{1F7E1}'; // a character that cannot occur in a path pattern
  const compiled = patterns.map(pattern => {
    let pat = pattern;
    const negated = pat.startsWith('!'); if (negated) pat = pat.slice(1);
    const dirOnly = pat.endsWith('/'); if (dirOnly) pat = pat.slice(0, -1);
    const anchored = pat.startsWith('/'); if (anchored) pat = pat.slice(1);
    const rx = new RegExp('^' + pat
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, GLOBSTAR)
      .replace(/\*/g, '[^/]*')
      .split(GLOBSTAR).join('.*')
      .replace(/\?/g, '[^/]') + '$');
    return { pattern, rx, negated, dirOnly, anchored, hasSlash: pat.includes('/') };
  });

  return (filePath) => {
    let excluded = false, by = null;
    for (const c of compiled) {
      const segments = filePath.split('/');
      const candidates = [filePath];
      if (!c.anchored) {
        // An unanchored pattern matches at any depth.
        for (let i = 1; i < segments.length; i++) candidates.push(segments.slice(i).join('/'));
        // A bare name matches any single segment, gitignore-style.
        if (!c.hasSlash) candidates.push(...segments);
      }
      // A directory entry excludes everything beneath it.
      const dirHit = c.dirOnly && segments.slice(0, -1).some(s => c.rx.test(s));
      if (dirHit || candidates.some(x => c.rx.test(x))) { excluded = !c.negated; by = c.pattern; }
    }
    return { excluded, by };
  };
}

/** Assets whose content type the origin must not report as HTML. A 200 carrying
 *  text/html for a `.js` request is the SPA-fallback failure mode: the browser
 *  refuses to execute it, with no 404 and no console error, so the script
 *  silently vanishes — a delivery failure that looks like success to a
 *  status-code-only check. */
export function expectsNonHtml(assetFilePath) {
  return /\.(js|mjs|css|json|png|svg|ico|webmanifest|woff2?)$/i.test(assetFilePath);
}
