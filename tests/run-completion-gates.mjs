import { runSpec as launchIntro } from './unit/launch-intro.gate.mjs';
import { runSpec as hyperdriveBinding } from './unit/hyperdrive-binding.gate.mjs';
import { runSpec as st12RestoreTransaction } from './integration/st12-restore-transaction.gate.mjs';

const specs = [launchIntro, hyperdriveBinding, st12RestoreTransaction];
const results = [];

for (const runSpec of specs) {
  try {
    const result = await runSpec();
    const pass = Number.isSafeInteger(result?.pass) && result.pass >= 0 ? result.pass : 0;
    const fail = Number.isSafeInteger(result?.fail) && result.fail >= 0 ? result.fail : 1;
    results.push({ file: result?.file || runSpec.name || 'completion gate', pass, fail });
  } catch (error) {
    results.push({
      file: runSpec.name || 'completion gate',
      pass: 0,
      fail: 1,
      error: String(error?.stack || error?.message || error),
    });
  }
}

const totalPass = results.reduce((sum, result) => sum + result.pass, 0);
const totalFail = results.reduce((sum, result) => sum + result.fail, 0);

for (const result of results) {
  console.log(`${result.file}: ${result.pass} passed, ${result.fail} failed`);
  if (result.error) console.error(result.error);
}
console.log(`COMPLETION TOTAL: ${totalPass} passed, ${totalFail} failed across ${results.length} spec file(s)`);
process.exit(totalFail ? 1 : 0);
