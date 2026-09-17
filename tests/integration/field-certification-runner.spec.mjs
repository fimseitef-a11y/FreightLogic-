import { readFile } from 'node:fs/promises';
import { launchBlank, createSuite, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/field-certification-runner.spec.mjs');
const STORE_KEY = 'freightlogic_field_cert_v1';

async function openRunner(app, query = '') {
  const response = await app.page.goto(`${app.baseUrl}/field-certification.html${query}`, { waitUntil: 'load' });
  eq(response?.status(), 200, 'field certification companion must be served from the FreightLogic origin');
  return app.page;
}

async function requireControl(page, selector, message) {
  eq(await page.locator(selector).count(), 1, message);
}

async function waitEnvironment(page) {
  await requireControl(page, '#candidateExpected', 'candidate generation control must exist');
  await page.waitForFunction(() => document.body.dataset.environmentReady === 'true', { timeout: 8000 });
}

async function startCertification(page, { candidate = null, device = 'iPhone physical test device', ios = '27.0' } = {}) {
  await waitEnvironment(page);
  if (candidate !== null) await page.locator('#candidateExpected').fill(candidate);
  await page.locator('#deviceModel').fill(device);
  await page.locator('#iosVersion').fill(ios);
  await page.locator('[data-start-session]').click();
}

function gate(page, id) {
  return page.locator(`[data-gate="${id}"]`);
}

async function gateStatus(page, id) {
  return gate(page, id).getAttribute('data-status');
}

async function startGate(page, id) {
  await gate(page, id).locator('[data-action="start"]').click();
}

async function completeBaseEvidence(page, id, observation = 'Observed on the required physical iPhone with synthetic non-sensitive data.') {
  const row = gate(page, id);
  await row.locator('[data-operator-observation]').fill(observation);
  await row.locator('[data-attestation]').check();
  const checks = row.locator('[data-required-check]');
  const count = await checks.count();
  for (let i = 0; i < count; i++) await checks.nth(i).check();
}

test('[FIELD CERT / NEW] FC-01 runner loads and exposes exactly A1-A12 as NOT_RUN', async () => {
  const app = await launchBlank();
  try {
    const page = await openRunner(app);
    const gates = await page.locator('[data-gate]').evaluateAll(nodes => nodes.map(node => ({
      id: node.getAttribute('data-gate'),
      status: node.getAttribute('data-status'),
    })));
    eq(gates.length, 12, 'the companion must render exactly the twelve physical-device gates');
    eq(gates.map(g => g.id).join(','), 'A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12',
      'the companion must preserve the canonical A1-A12 identity and order');
    eq(gates.every(g => g.status === 'NOT_RUN'), true,
      'every physical-device gate must start in the canonical NOT_RUN state; nothing is pre-certified');
  } finally {
    await app.close();
  }
});

test('[FIELD CERT / NEW] FC-02 environment capture records the frozen candidate facts without pinning a release literal', async () => {
  const app = await launchBlank();
  try {
    const page = await openRunner(app);
    await waitEnvironment(page);
    const observed = await page.locator('body').getAttribute('data-observed-generation');
    eq(Boolean(observed), true, 'manifest-derived app generation must be observed at runtime');
    eq(await page.locator('#candidateExpected').inputValue(), observed,
      'candidate input should default to the runtime generation rather than a hard-coded version');

    const keys = await page.locator('[data-env-key]').evaluateAll(nodes => nodes.map(n => n.getAttribute('data-env-key')));
    for (const required of ['origin', 'appGeneration', 'indexedDbSchema', 'swScript', 'swScope', 'swCache', 'workerGeneration', 'gitSha', 'launchMode', 'browser', 'deviceModel', 'iosVersion', 'timestamp']) {
      eq(keys.includes(required), true, `environment capture must expose ${required}`);
    }
  } finally {
    await app.close();
  }
});

test('[FIELD CERT / NEGATIVE] FC-03 a wrong candidate generation fails closed before any physical row can start', async () => {
  const app = await launchBlank();
  try {
    const page = await openRunner(app, '?candidate=99.99.99');
    await startCertification(page);
    eq(await page.locator('body').getAttribute('data-session-state'), 'INVALID',
      'a runtime/candidate mismatch must invalidate the session');
    eq(await gateStatus(page, 'A1'), 'NOT_RUN', 'no row may advance under the wrong runtime generation');
    const banner = (await page.locator('[data-session-banner]').textContent()) || '';
    eq(/mismatch/i.test(banner), true, 'the mismatch must be visible to the operator');
  } finally {
    await app.close();
  }
});

test('[FIELD CERT / NEGATIVE] FC-04 automated presence or a bare click can never close a physical-device row', async () => {
  const app = await launchBlank();
  try {
    const page = await openRunner(app);
    await startCertification(page);
    eq(await page.locator('body').getAttribute('data-session-state'), 'ACTIVE', 'matching candidate should start');

    await startGate(page, 'A1');
    eq(await gateStatus(page, 'A1'), 'RUNNING', 'explicit start transitions NOT_RUN -> RUNNING');
    await gate(page, 'A1').locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A1'), 'RUNNING', 'a PASS click with no manual evidence must be rejected');

    const row = gate(page, 'A1');
    await row.locator('[data-operator-observation]').fill('Physical update path observed.');
    await row.locator('[data-attestation]').check();
    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A1'), 'RUNNING', 'attestation alone cannot replace required physical checkpoints');

    const checks = row.locator('[data-required-check]');
    const count = await checks.count();
    eq(count > 0, true, 'A1 must have explicit physical checkpoints');
    for (let i = 0; i < count; i++) await checks.nth(i).check();
    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A1'), 'PASS', 'the row may close only after explicit manual evidence is complete');
  } finally {
    await app.close();
  }
});

test('[FIELD CERT / NEGATIVE] FC-05 A6 requires real-device attestation and at least ten background minutes', async () => {
  const app = await launchBlank();
  try {
    const page = await openRunner(app);
    await startCertification(page);
    await startGate(page, 'A6');
    await completeBaseEvidence(page, 'A6');
    const row = gate(page, 'A6');

    await row.locator('[data-background-minutes]').fill('10');
    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A6'), 'RUNNING', 'ten typed minutes without real-device confirmation are insufficient');

    await row.locator('[data-real-device]').check();
    await row.locator('[data-background-minutes]').fill('9');
    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A6'), 'RUNNING', 'nine background minutes must fail the >=10 minute requirement');

    await row.locator('[data-background-minutes]').fill('10');
    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A6'), 'PASS', 'A6 may pass only with >=10 minutes plus real-device evidence');
  } finally {
    await app.close();
  }
});

test('[FIELD CERT / NEGATIVE] FC-06 A11 cannot pass below iOS 27 and cannot skip its visual checkpoints', async () => {
  const oldApp = await launchBlank();
  try {
    const page = await openRunner(oldApp);
    await startCertification(page, { ios: '26.9' });
    await startGate(page, 'A11');
    await completeBaseEvidence(page, 'A11');
    await gate(page, 'A11').locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A11'), 'RUNNING', 'an A11 PASS on iOS 26 would certify nothing about iOS 27');
    const error = (await gate(page, 'A11').locator('[data-gate-error]').textContent()) || '';
    eq(/iOS 27/i.test(error), true, 'the version floor failure must be explicit');
  } finally {
    await oldApp.close();
  }

  const app27 = await launchBlank();
  try {
    const page = await openRunner(app27);
    await startCertification(page, { ios: '27.0' });
    await startGate(page, 'A11');
    const row = gate(page, 'A11');
    await row.locator('[data-operator-observation]').fill('Visual regression check performed on iOS 27.');
    await row.locator('[data-attestation]').check();
    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A11'), 'RUNNING', 'iOS 27 alone cannot substitute for the visual/manual checkpoints');
    const checks = row.locator('[data-required-check]');
    for (let i = 0; i < await checks.count(); i++) await checks.nth(i).check();
    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A11'), 'PASS', 'iOS 27 with every required visual checkpoint may close A11');
  } finally {
    await app27.close();
  }
});

test('[FIELD CERT / NEGATIVE] FC-07 A12 requires an explicit Safari-to-Home-Screen storage-partition answer', async () => {
  const app = await launchBlank();
  try {
    const page = await openRunner(app);
    await startCertification(page);
    await startGate(page, 'A12');
    await completeBaseEvidence(page, 'A12');
    const row = gate(page, 'A12');

    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A12'), 'RUNNING', 'A12 cannot pass while the storage-partition result is unknown');
    await row.locator('[data-storage-partition]').selectOption('SHARED');
    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A12'), 'PASS', 'an explicit observed partition answer may satisfy the A12-specific guard');
  } finally {
    await app.close();
  }
});

test('[FIELD CERT / NEGATIVE] FC-08 secrets are scrubbed from persisted and exported field evidence', async () => {
  const app = await launchBlank();
  try {
    const page = await openRunner(app);
    await startCertification(page);
    await startGate(page, 'A5');
    const row = gate(page, 'A5');
    const secrets = ['flk_SUPERSECRET_ABC123', 'verySecretPass', '4321', 'ABCD1234'];
    await row.locator('[data-operator-observation]').fill(`token=${secrets[0]} passphrase=${secrets[1]} PIN=${secrets[2]}`);
    await row.locator('[data-reference]').fill(`inviteCode=${secrets[3]}`);
    await row.locator('[data-reason]').fill(`blocked because token=${secrets[0]}`);
    await row.locator('[data-action="block"]').click();
    eq(await gateStatus(page, 'A5'), 'BLOCKED', 'the row should record a non-secret blocked finding');

    const stored = await page.evaluate(key => localStorage.getItem(key) || '', STORE_KEY);
    for (const secret of secrets) eq(stored.includes(secret), false, `local field evidence must not contain secret value ${secret}`);

    const downloadPromise = page.waitForEvent('download');
    await page.locator('[data-export]').click();
    const download = await downloadPromise;
    const downloadPath = await download.path();
    eq(Boolean(downloadPath), true, 'privacy-safe field evidence export must produce a local JSON file');
    const exported = await readFile(downloadPath, 'utf8');
    for (const secret of secrets) eq(exported.includes(secret), false, `exported field evidence must not contain secret value ${secret}`);
    eq(download.suggestedFilename().startsWith('freightlogic-field-cert-'), true,
      'field evidence export uses the dedicated privacy-safe filename');
  } finally {
    await app.close();
  }
});

test('[FIELD CERT / NEGATIVE] FC-09 a runtime-generation change invalidates an in-progress session', async () => {
  const app = await launchBlank();
  try {
    const page = await openRunner(app);
    await startCertification(page);
    eq(await page.locator('body').getAttribute('data-session-state'), 'ACTIVE', 'precondition: session starts valid');

    await page.route('**/manifest.json*', route => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ name: 'FreightLogic v99.0.0' }),
    }));
    await page.locator('[data-verify-environment]').click();
    await page.waitForFunction(() => document.body.dataset.sessionState === 'INVALID');
    eq(await page.locator('body').getAttribute('data-session-state'), 'INVALID',
      'candidate/environment drift must invalidate rather than silently resume');
    await gate(page, 'A2').locator('[data-action="start"]').click();
    eq(await gateStatus(page, 'A2'), 'NOT_RUN', 'an invalidated session cannot continue physical rows');
  } finally {
    await app.close();
  }
});

test('[FIELD CERT / NEGATIVE] FC-10 FAIL and BLOCKED are terminal until an explicit reset; a generic green action cannot overwrite them', async () => {
  const app = await launchBlank();
  try {
    const page = await openRunner(app);
    await startCertification(page);
    const row = gate(page, 'A2');

    await startGate(page, 'A2');
    await row.locator('[data-reason]').fill('Synthetic UNKNOWN/zero parity failed.');
    await row.locator('[data-action="fail"]').click();
    eq(await gateStatus(page, 'A2'), 'FAIL', 'explicit failure is recorded');
    await completeBaseEvidence(page, 'A2');
    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A2'), 'FAIL', 'PASS cannot overwrite FAIL without a reset');

    await row.locator('[data-action="reset"]').click();
    eq(await gateStatus(page, 'A2'), 'NOT_RUN', 'explicit reset reopens the row');
    await startGate(page, 'A2');
    await row.locator('[data-reason]').fill('Required physical condition unavailable.');
    await row.locator('[data-action="block"]').click();
    eq(await gateStatus(page, 'A2'), 'BLOCKED', 'explicit block is recorded');
    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A2'), 'BLOCKED', 'PASS cannot overwrite BLOCKED without a reset');
  } finally {
    await app.close();
  }
});

test('[FIELD CERT / NEW] FC-11 a RUNNING physical row resumes locally only under the same frozen environment', async () => {
  const app = await launchBlank();
  try {
    const page = await openRunner(app);
    await startCertification(page, { device: 'iPhone resume fixture', ios: '27.1' });
    await startGate(page, 'A3');
    eq(await gateStatus(page, 'A3'), 'RUNNING', 'precondition: A3 is in progress');
    const frozenCandidate = await page.locator('#candidateExpected').inputValue();

    await page.reload({ waitUntil: 'load' });
    await waitEnvironment(page);
    eq(await page.locator('body').getAttribute('data-session-state'), 'ACTIVE',
      'same environment should resume the local certification session');
    eq(await gateStatus(page, 'A3'), 'RUNNING', 'the in-progress row must survive reload');
    eq(await page.locator('#candidateExpected').inputValue(), frozenCandidate, 'candidate identity remains frozen across resume');
    eq(await page.locator('#deviceModel').inputValue(), 'iPhone resume fixture', 'operator-entered physical device remains recorded');
    eq(await page.locator('#iosVersion').inputValue(), '27.1', 'operator-entered iOS version remains recorded');
  } finally {
    await app.close();
  }
});

test('[FIELD CERT / NEW] FC-12 every A1-A12 row is a guided evidence instrument, not an empty PASS button', async () => {
  const app = await launchBlank();
  try {
    const page = await openRunner(app);
    await waitEnvironment(page);
    for (const id of ['A1','A2','A3','A4','A5','A6','A7','A8','A9','A10','A11','A12']) {
      const row = gate(page, id);
      eq(await row.locator('[data-expected]').count(), 1, `${id} must state expected behavior`);
      eq((await row.locator('[data-required-check]').count()) > 0, true, `${id} must expose required physical checkpoints`);
      eq(await row.locator('[data-operator-observation]').count(), 1, `${id} must capture operator observation`);
      eq(await row.locator('[data-attestation]').count(), 1, `${id} must require physical-device attestation`);
      eq(await row.locator('[data-reference]').count(), 1, `${id} must allow local screenshot/reference metadata without storing image bytes`);
      eq(await row.locator('[data-reason]').count(), 1, `${id} must have an explicit FAIL/BLOCKED reason field`);
      for (const action of ['start','pass','fail','block','reset']) {
        eq(await row.locator(`[data-action="${action}"]`).count(), 1, `${id} must expose ${action} transition control`);
      }
    }
    eq(await gate(page, 'A6').locator('[data-background-minutes]').count(), 1, 'A6 must capture measured background minutes');
    eq(await gate(page, 'A6').locator('[data-real-device]').count(), 1, 'A6 must explicitly attest a real-device run');
    eq(await gate(page, 'A11').locator('[data-required-check]').count() >= 6, true, 'A11 must enumerate the iOS 27 visual/regression checkpoints');
    eq(await gate(page, 'A12').locator('[data-storage-partition]').count(), 1, 'A12 must record Safari-to-PWA storage behavior');
  } finally {
    await app.close();
  }
});

export async function runSpec() { return run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const result = await run();
  process.exit(result.fail ? 1 : 0);
}
