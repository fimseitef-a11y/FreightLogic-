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

test('[FIELD CERT / NEW] FC-01 runner loads and exposes exactly A1-A14 as NOT_RUN', async () => {
  const app = await launchBlank();
  try {
    const page = await openRunner(app);
    const gates = await page.locator('[data-gate]').evaluateAll(nodes => nodes.map(node => ({
      id: node.getAttribute('data-gate'),
      status: node.getAttribute('data-status'),
    })));
    eq(gates.length, 14, 'the companion must render exactly the fourteen physical-device gates');
    eq(gates.map(g => g.id).join(','), 'A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14',
      'the companion must preserve the canonical A1-A14 identity and order');
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
    eq(await gate(page, 'A2').locator('[data-action="start"]').isDisabled(), true,
      'an invalidated session must disable physical-row start controls');
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

test('[FIELD CERT / NEW] FC-12 every A1-A14 row is a guided evidence instrument, not an empty PASS button', async () => {
  const app = await launchBlank();
  try {
    const page = await openRunner(app);
    await waitEnvironment(page);
    for (const id of ['A1','A2','A3','A4','A5','A6','A7','A8','A9','A10','A11','A12','A13','A14']) {
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
    const a11Checks = gate(page, 'A11').locator('[data-required-check]');
    eq(await a11Checks.count() >= 8, true, 'A11 must enumerate iOS 27 plus Driver/Glance readability checkpoints');
    const a11Text = (await gate(page, 'A11').textContent()) || '';
    eq(/text-size/i.test(a11Text), true, 'A11 must require every shipped text-size preference to be checked on the real iPhone');
    eq(/Glance Mode/i.test(a11Text), true, 'A11 must require Driver/Glance readability at normal dashboard\/phone-mount distance');
    eq(await gate(page, 'A12').locator('[data-storage-partition]').count(), 1, 'A12 must record Safari-to-PWA storage behavior');
    eq(await gate(page, 'A13').locator('[data-a13-camera]').count(), 1, 'A13 must record the screenshot/camera delivery result');
    eq(await gate(page, 'A13').locator('[data-a13-clipboard]').count(), 1, 'A13 must record the clipboard-image delivery result');
    eq(await gate(page, 'A13').locator('[data-a13-unknown-deadhead]').count(), 1, 'A13 must separately record the UNKNOWN-deadhead outcome');
    eq(await gate(page, 'A14').locator('[data-a14-notification]').count(), 1, 'A14 must record the physical notification tap target');
    eq(await gate(page, 'A14').locator('[data-a14-relay]').count(), 1, 'A14 must record relay prefill versus unsafe auto-save');
    eq(await gate(page, 'A14').locator('[data-a14-safari-warning]').count(), 1, 'A14 must record the direct-link Safari warning');
    eq(await gate(page, 'A14').locator('[data-a14-revoke]').count(), 1, 'A14 must record key revocation behavior');
  } finally {
    await app.close();
  }
});


test('[FIELD CERT / NEW] FC-13 safe automated environment observations record cache-generation and persistent-storage facts without auto-passing rows', async () => {
  const app = await launchBlank();
  try {
    await app.page.addInitScript(() => {
      try {
        if (navigator.storage) {
          Object.defineProperty(navigator.storage, 'persisted', { configurable: true, value: async () => true });
        }
      } catch {}
      try {
        if (typeof CacheStorage !== 'undefined') {
          Object.defineProperty(CacheStorage.prototype, 'keys', {
            configurable: true,
            value: async () => ['freightlogic-24.0.19', 'freightlogic-share-v2']
          });
        } else if (window.caches) {
          window.caches.keys = async () => ['freightlogic-24.0.19', 'freightlogic-share-v2'];
        }
      } catch {}
    });
    await app.page.route('**/manifest.json*', route => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ name: 'FreightLogic v24.0.19', short_name: 'FreightLogic' }),
    }));
    const page = await openRunner(app);
    await startCertification(page, { candidate: '24.0.19' });

    const a1Auto = (await gate(page, 'A1').locator('[data-automated-observation]').textContent()) || '';
    eq(/generation cache/i.test(a1Auto), true, 'A1 must record the generation-cache observation');
    eq(/MATCH/i.test(a1Auto), true, 'exactly one matching generation cache should be reported as MATCH');
    eq(/freightlogic-share-v2.*excluded/i.test(a1Auto), true, 'the share cache must be explicitly excluded from generation counting');

    const a11Auto = (await gate(page, 'A11').locator('[data-automated-observation]').textContent()) || '';
    eq(/storage\.persisted\(\).*GRANTED/i.test(a11Auto), true,
      'A11 must record the browser persistent-storage grant directly');

    eq(await gateStatus(page, 'A1'), 'NOT_RUN', 'automated A1 observations must never auto-certify the physical row');
    eq(await gateStatus(page, 'A11'), 'NOT_RUN', 'automated A11 observations must never auto-certify the physical row');
  } finally {
    await app.close();
  }
});

test('[FIELD CERT / NEW] FC-14 A5 export inspection is structure-only, detects protected field names, and preserves null-vs-zero deadhead evidence', async () => {
  const app = await launchBlank();
  try {
    const page = await openRunner(app);
    await startCertification(page);
    await startGate(page, 'A5');
    const row = gate(page, 'A5');

    const protectedValues = ['TOP_SECRET_TOKEN', '1234', 'cipher-secret', '1700000000'];
    const payload = {
      settings: {
        cloudBackupToken: protectedValues[0],
        appLockPin: protectedValues[1],
        cloudAdminTokenEnc: protectedValues[2],
        appLockoutUntil: protectedValues[3],
      },
      trips: [
        { id: 'synthetic-null', emptyMiles: null },
        { id: 'synthetic-zero', emptyMiles: 0 },
      ],
    };

    await row.locator('[data-a5-export]').setInputFiles({
      name: 'synthetic-export.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify(payload)),
    });
    await page.waitForFunction(() => {
      const text = document.querySelector('[data-gate="A5"] [data-automated-observation]')?.textContent || '';
      return text.includes('A5 export structure');
    });

    const auto = (await row.locator('[data-automated-observation]').textContent()) || '';
    for (const key of ['cloudBackupToken', 'appLockPin', 'cloudAdminTokenEnc', 'appLockoutUntil']) {
      eq(auto.includes(key), true, 'A5 may report protected field name ' + key);
    }
    for (const value of protectedValues) {
      eq(auto.includes(value), false, 'A5 structure-only observation must never retain protected value ' + value);
    }
    eq(/deadhead null=1/i.test(auto), true, 'A5 must report one preserved UNKNOWN/null deadhead');
    eq(/deadhead zero=1/i.test(auto), true, 'A5 must report one explicit zero deadhead');
    eq(await gateStatus(page, 'A5'), 'RUNNING', 'A5 export automation remains advisory and cannot close the physical row');

    const stored = await page.evaluate(key => localStorage.getItem(key) || '', STORE_KEY);
    for (const value of protectedValues) {
      eq(stored.includes(value), false, 'persisted certification evidence must not retain inspected export value ' + value);
    }
  } finally {
    await app.close();
  }
});


test('[FIELD CERT / NEGATIVE] FC-15 A13 blocks below Worker v21 and accepts recorded iOS non-delivery without accepting fabricated deadhead zero', async () => {
  const oldWorkerApp = await launchBlank();
  try {
    await oldWorkerApp.page.route(/https:\/\/freightlogic-backup\.fimseitef\.workers\.dev\/health(?:\?.*)?$/, route => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ ok: true, version: '20' }),
    }));
    const page = await openRunner(oldWorkerApp);
    await startCertification(page);
    await startGate(page, 'A13');
    eq(await gateStatus(page, 'A13'), 'BLOCKED', 'A13 must be BLOCKED, not FAIL or RUNNING, when /extract-image cannot exist on Worker v20');
    const reason = await gate(page, 'A13').locator('[data-reason]').inputValue();
    eq(/Worker v21/i.test(reason), true, 'the Worker-generation block must name the v21 prerequisite');
  } finally {
    await oldWorkerApp.close();
  }

  const app = await launchBlank();
  try {
    await app.page.route(/https:\/\/freightlogic-backup\.fimseitef\.workers\.dev\/health(?:\?.*)?$/, route => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ ok: true, version: '21' }),
    }));
    const page = await openRunner(app);
    await startCertification(page);
    await startGate(page, 'A13');
    eq(await gateStatus(page, 'A13'), 'RUNNING', 'Worker v21 makes A13 eligible for physical observation');
    await completeBaseEvidence(page, 'A13');
    const row = gate(page, 'A13');

    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A13'), 'RUNNING', 'A13 cannot pass while camera/clipboard outcomes are merely assumed');
    await row.locator('[data-a13-camera]').selectOption('NOT_DELIVERED');
    await row.locator('[data-a13-clipboard]').selectOption('NOT_DELIVERED');
    await row.locator('[data-a13-unknown-deadhead]').selectOption('FABRICATED_ZERO');
    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A13'), 'RUNNING', 'recorded camera/clipboard non-delivery is valid, but fabricated deadhead zero must still block PASS');
    const deadheadError = (await row.locator('[data-gate-error]').textContent()) || '';
    eq(/blank\/UNKNOWN/i.test(deadheadError), true, 'UNKNOWN-deadhead failure must be explicit');

    await row.locator('[data-a13-unknown-deadhead]').selectOption('BLANK_PROMPTED');
    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A13'), 'PASS', 'A13 may pass once image-path outcomes are recorded and UNKNOWN deadhead is directly observed fail-closed');
  } finally {
    await app.close();
  }
});

test('[FIELD CERT / NEGATIVE] FC-16 an A1-A13 saved session cannot resume or masquerade as complete after A14 is added', async () => {
  const app = await launchBlank();
  try {
    let page = await openRunner(app);
    await waitEnvironment(page);
    const observed = await page.locator('#candidateExpected').inputValue();
    await page.evaluate(({ key, candidate }) => {
      localStorage.setItem(key, JSON.stringify({
        schemaVersion: 1,
        checklistVersion: 'A1-A13-2026-09-18',
        sessionState: 'COMPLETE',
        candidate,
        deviceModel: 'old fixture',
        iosVersion: '27.0',
        gates: {},
      }));
    }, { key: STORE_KEY, candidate: observed });
    await page.reload({ waitUntil: 'load' });
    await waitEnvironment(page);
    eq(await page.locator('body').getAttribute('data-session-state'), 'IDLE',
      'an older checklist session must be discarded rather than resumed as COMPLETE');
    eq(await gateStatus(page, 'A14'), 'NOT_RUN', 'the newly-added physical gate must start unobserved');
  } finally {
    await app.close();
  }
});

test('[FIELD CERT / NEGATIVE] FC-17 A14 cannot pass from CI-style checkboxes or unsafe Shortcuts outcomes', async () => {
  const app = await launchBlank();
  try {
    const page = await openRunner(app);
    await startCertification(page);
    await startGate(page, 'A14');
    await completeBaseEvidence(page, 'A14', 'Observed Shortcuts relay and Web Push on the physical iPhone.');
    const row = gate(page, 'A14');

    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A14'), 'RUNNING', 'A14 cannot pass while the physical iOS outcomes are unrecorded');

    await row.locator('[data-a14-notification]').selectOption('SAFARI');
    await row.locator('[data-a14-relay]').selectOption('AUTO_SAVED');
    await row.locator('[data-a14-safari-warning]').selectOption('NO_WARNING');
    await row.locator('[data-a14-revoke]').selectOption('STILL_AUTHORIZED');
    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A14'), 'RUNNING', 'unsafe or incorrect Shortcuts/push outcomes must not be certifiable');

    await row.locator('[data-a14-notification]').selectOption('HOME_SCREEN_PWA');
    await row.locator('[data-a14-relay]').selectOption('UNSAVED_PREFILL');
    await row.locator('[data-a14-safari-warning]').selectOption('WARNING_SHOWN');
    await row.locator('[data-a14-revoke]').selectOption('HTTP_401_NO_PUSH');
    await row.locator('[data-action="pass"]').click();
    eq(await gateStatus(page, 'A14'), 'PASS', 'A14 may pass only after the required physical-device outcomes are explicitly recorded');
  } finally {
    await app.close();
  }
});

test('[FIELD CERT / NEGATIVE] FC-18 A14 Shortcut-key-shaped evidence is redacted from local storage and export', async () => {
  const app = await launchBlank();
  try {
    const page = await openRunner(app);
    await startCertification(page);
    await startGate(page, 'A14');
    const row = gate(page, 'A14');
    // Real Shortcut keys use the fls_ prefix. Keep the value bare (no
    // "token=" label) so this proves prefix-shaped redaction itself rather
    // than passing through the generic labelled-secret scrubber.
    const secret = 'fls_SHORTCUT_SECRET_123';
    await row.locator('[data-operator-observation]').fill(`Physical behavior observed with ${secret} on device.`);
    await row.locator('[data-reason]').fill(`blocked after observing ${secret}`);
    await row.locator('[data-action="block"]').click();
    const stored = await page.evaluate(key => localStorage.getItem(key) || '', STORE_KEY);
    eq(stored.includes(secret), false, 'A14 must never persist the Shortcut key value');
    const downloadPromise = page.waitForEvent('download');
    await page.locator('[data-export]').click();
    const download = await downloadPromise;
    const exported = await readFile(await download.path(), 'utf8');
    eq(exported.includes(secret), false, 'A14 privacy-safe export must never contain the Shortcut key value');
  } finally {
    await app.close();
  }
});

export async function runSpec() { return run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const result = await run();
  process.exit(result.fail ? 1 : 0);
}
