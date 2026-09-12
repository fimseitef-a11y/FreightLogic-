// Child entry point: runs exactly ONE spec file and exits with its result.
//
// Used by run-all.mjs to execute specs in parallel processes. A generic wrapper
// rather than per-spec `import.meta.url` branches, because five specs never had
// one and adding them would be churn that can drift; this works uniformly for
// every spec that exports `runSpec()`.
//
// Process isolation is the point: each child gets its own module registry, its
// own shared HTTP server and its own browser, so specs cannot contend over the
// singleton in harness.mjs. `sw-subresource-semantics` already ran its own
// server and kills it deliberately — in its own process that cannot affect a peer.
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { stopServer } from './harness.mjs';

const rel = process.argv[2];
if (!rel) {
  console.error('run-one.mjs: expected a spec path argument');
  process.exit(2);
}

try {
  const mod = await import(pathToFileURL(path.resolve(rel)).href);
  if (typeof mod.runSpec !== 'function') {
    // Fail loudly. A spec that cannot report is never silently a pass — the
    // X-06 rule: a skipped suite is a SKIP, not a PASS.
    console.error(`run-one.mjs: ${rel} exports no runSpec()`);
    process.exit(2);
  }
  const r = await mod.runSpec();
  await stopServer().catch(() => {});
  process.exit(r && r.fail > 0 ? 1 : 0);
} catch (err) {
  console.error(`run-one.mjs: ${rel} threw before reporting:\n${err && err.stack ? err.stack : String(err)}`);
  await stopServer().catch(() => {});
  process.exit(2);
}
