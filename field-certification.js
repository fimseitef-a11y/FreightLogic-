(() => {
  'use strict';

  const STORE_KEY = 'freightlogic_field_cert_v1';
  const SCHEMA_VERSION = 1;
  const TERMINAL = new Set(['PASS', 'FAIL', 'BLOCKED']);

  const GATES = {
    A1: {
      expected: 'The installed app reaches the exact certification candidate through the normal update path without data loss or a blank/update loop.',
      checks: ['Normal install/update path completed on the physical iPhone.', 'Existing local data remained present after launch.']
    },
    A2: {
      expected: 'Missing deadhead remains UNKNOWN while an explicitly entered zero remains a known zero.',
      checks: ['Synthetic missing-deadhead case remained UNKNOWN.', 'Synthetic explicit-zero case remained a known zero.']
    },
    A3: {
      expected: 'A synthetic intake record and its provenance survive closing and reopening the app.',
      checks: ['Synthetic opportunity created through the shipped intake path.', 'The same record and evidence were present after reopen.']
    },
    A4: {
      expected: 'The app survives an online → airplane-mode → close/reopen offline → reconnect round trip without duplication or loss.',
      checks: ['Online state was primed before Airplane Mode.', 'Local mutations/navigation worked while offline.', 'Close/reopen while offline preserved the synthetic data.', 'Reconnect produced no duplication or loss.']
    },
    A5: {
      expected: 'Local export/import preserves synthetic data, rejects corrupted input, and excludes protected credentials.',
      checks: ['Synthetic export/import round trip preserved expected data.', 'Corrupted synthetic payload was rejected.', 'Export inspection showed no protected credential material.']
    },
    A6: {
      expected: 'A real-device GPS trip remains recoverable after at least ten minutes backgrounded/locked and records an honest quality state.',
      checks: ['Test trip was started on the physical iPhone.', 'The app was backgrounded/locked for the measured interval.', 'Return, stop and save preserved the trip/quality state.']
    },
    A7: {
      expected: 'Revoking Location permission mid-trip produces a visible paused/degraded state while preserving salvageable trip state.',
      checks: ['Location permission was revoked in iOS Settings during the test trip.', 'The app visibly paused/degraded instead of silently ending the trip.', 'The trip remained salvageable and could be stopped/saved.']
    },
    A8: {
      expected: 'Two real Safari tabs editing the same synthetic record cannot silently lose the newer write.',
      checks: ['The same synthetic record was opened in two Safari tabs.', 'The first tab saved a newer value.', 'The stale second save was rejected or reconciled without overwriting the newer value.']
    },
    A9: {
      expected: 'Doctrine, geography, cargo-fit and profit sanity boundaries behave exactly at the approved synthetic vectors.',
      checks: ['Blank/short market and Gary/Calgary vectors were checked.', '121/122 in and 54.8/54.9 in fit boundaries were checked.', '3000/3001 lb payload boundary was checked.', 'Defensible versus undefended cost input behavior was checked.']
    },
    A10: {
      expected: 'Pickup-feasibility vectors distinguish unset speed, impossible/reachable/tight windows, UNKNOWN deadhead and explicit-zero deadhead.',
      checks: ['Unset planning speed vector was checked.', 'Impossible, reachable and tight pickup windows were checked.', 'UNKNOWN and explicit-zero deadhead vectors remained distinct.']
    },
    A11: {
      expected: 'Real iOS 27+ passes the required visual and iOS-specific regression checklist; emulation alone never counts.',
      checks: ['F31 SVG chart inspected on iOS 27+.', 'Primary tab icons inspected.', 'Required select controls inspected.', 'Scroll anchoring inspected.', 'Persistent-storage behavior inspected.', 'Backup paused/resume behavior inspected.']
    },
    A12: {
      expected: 'Owner invite → Safari claim → Home Screen launch/reclaim preserves one canonical account and records the observed Safari/PWA storage relationship without exposing credentials.',
      checks: ['Owner invite and Safari claim path were observed on the physical device.', 'Home Screen launch/reclaim path was observed.', 'Canonical account/backup continuity was observed.', 'No token, code, PIN or passphrase was copied into evidence.']
    }
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  let environment = null;
  let state = freshState();

  function freshState() {
    const gates = {};
    for (const id of Object.keys(GATES)) {
      gates[id] = {
        status: 'NOT_RUN', startedAt: null, completedAt: null,
        observation: '', reference: '', reason: '', attestation: false,
        checks: [], backgroundMinutes: null, realDevice: false, storagePartition: 'UNKNOWN'
      };
    }
    return {
      version: SCHEMA_VERSION,
      session: {
        state: 'IDLE', candidate: '', origin: location.origin,
        deviceModel: '', iosVersion: '', startedAt: null, completedAt: null,
        environment: null
      },
      gates
    };
  }

  function scrubText(value) {
    let text = String(value || '');
    text = text.replace(/\b(?:admin\s*token|bearer|token|passphrase|password|pin|invite(?:\s*code|code)?|secret)\b\s*[:=]\s*[^\s,;]+/gi,
      match => `${match.split(/[:=]/, 1)[0].trim()}=[REDACTED]`);
    text = text.replace(/\bflk_[A-Za-z0-9_-]+\b/g, '[REDACTED]');
    return text.slice(0, 2000);
  }

  function safeVersion(value) {
    const match = String(value || '').match(/(?:^|\s|v)(\d+\.\d+\.\d+)(?:\b|$)/i);
    return match ? match[1] : '';
  }

  function displayMode() {
    if (window.matchMedia?.('(display-mode: standalone)').matches || navigator.standalone === true) return 'standalone-pwa';
    return 'browser-tab';
  }

  async function appGeneration() {
    try {
      const response = await fetch(`manifest.json?fieldCert=${Date.now()}`, { cache: 'no-store' });
      if (!response.ok) return '';
      const manifest = await response.json();
      return safeVersion(manifest.name || manifest.short_name || '');
    } catch (_) {
      return '';
    }
  }

  async function indexedDbVersion() {
    try {
      if (!indexedDB.databases) return 'UNOBSERVED';
      const dbs = await indexedDB.databases();
      const versions = dbs.map(db => Number(db.version)).filter(Number.isFinite);
      return versions.length ? String(Math.max(...versions)) : 'UNOBSERVED';
    } catch (_) {
      return 'UNOBSERVED';
    }
  }

  async function serviceWorkerFacts() {
    const result = { swScript: 'UNOBSERVED', swScope: 'UNOBSERVED', swCache: 'UNOBSERVED' };
    try {
      const registration = await navigator.serviceWorker?.getRegistration?.();
      const worker = registration?.active || registration?.waiting || registration?.installing;
      if (worker?.scriptURL) result.swScript = worker.scriptURL;
      if (registration?.scope) result.swScope = registration.scope;
    } catch (_) {}
    try {
      if (window.caches?.keys) {
        const names = await caches.keys();
        if (names.length) result.swCache = names.join(', ');
      }
    } catch (_) {}
    return result;
  }

  async function captureEnvironment() {
    const [generation, dbSchema, sw] = await Promise.all([
      appGeneration(), indexedDbVersion(), serviceWorkerFacts()
    ]);
    const observed = generation || 'UNKNOWN';
    const facts = {
      origin: location.origin,
      appGeneration: observed,
      indexedDbSchema: dbSchema,
      swScript: sw.swScript,
      swScope: sw.swScope,
      swCache: sw.swCache,
      workerGeneration: 'UNOBSERVED',
      gitSha: document.querySelector('meta[name="git-sha"]')?.content || 'UNOBSERVED',
      launchMode: displayMode(),
      browser: navigator.userAgent || 'UNOBSERVED',
      deviceModel: $('#deviceModel')?.value || '',
      iosVersion: $('#iosVersion')?.value || '',
      timestamp: new Date().toISOString()
    };
    environment = facts;
    document.body.dataset.observedGeneration = observed;
    for (const [key, value] of Object.entries(facts)) {
      const node = document.querySelector(`[data-env-key="${key}"]`);
      if (node) node.textContent = String(value || 'UNOBSERVED');
    }
    return facts;
  }

  function renderGateDetails() {
    for (const [id, config] of Object.entries(GATES)) {
      const row = document.querySelector(`[data-gate="${id}"]`);
      if (!row) continue;
      const title = row.querySelector('h2')?.textContent || id;
      row.innerHTML = '';

      const head = document.createElement('div');
      head.className = 'gate-head';
      const h2 = document.createElement('h2'); h2.textContent = title;
      const badge = document.createElement('span'); badge.className = 'status'; badge.textContent = 'NOT_RUN';
      head.append(h2, badge);
      row.append(head);

      const expected = document.createElement('p');
      expected.dataset.expected = '';
      expected.className = 'expected';
      expected.textContent = config.expected;
      row.append(expected);

      const checklist = document.createElement('fieldset');
      checklist.className = 'checks';
      const legend = document.createElement('legend'); legend.textContent = 'Required physical checkpoints';
      checklist.append(legend);
      config.checks.forEach((labelText, index) => {
        const label = document.createElement('label'); label.className = 'check-row';
        const input = document.createElement('input'); input.type = 'checkbox'; input.dataset.requiredCheck = ''; input.value = String(index);
        const span = document.createElement('span'); span.textContent = labelText;
        label.append(input, span); checklist.append(label);
      });
      row.append(checklist);

      const evidence = document.createElement('div'); evidence.className = 'evidence-grid';
      evidence.innerHTML = `
        <label>Operator observation<textarea data-operator-observation rows="2" autocomplete="off"></textarea></label>
        <label>Local screenshot/reference metadata<input data-reference type="text" autocomplete="off" placeholder="Optional local filename/reference only"></label>
        <label>FAIL/BLOCKED reason<input data-reason type="text" autocomplete="off" placeholder="Required for FAIL or BLOCKED"></label>
        <label class="attest"><input data-attestation type="checkbox"> I attest this observation was performed on the required physical device.</label>
        <p class="gate-error" data-gate-error aria-live="polite"></p>`;
      row.append(evidence);

      if (id === 'A6') {
        const special = document.createElement('div'); special.className = 'special';
        special.innerHTML = `
          <label>Measured background minutes<input data-background-minutes type="number" min="0" step="1" inputmode="numeric"></label>
          <label class="attest"><input data-real-device type="checkbox"> Confirm this was a real physical-iPhone background/lock run.</label>`;
        row.append(special);
      }
      if (id === 'A12') {
        const special = document.createElement('div'); special.className = 'special';
        special.innerHTML = `<label>Safari → Home Screen credential storage observation
          <select data-storage-partition>
            <option value="UNKNOWN">Not observed yet</option>
            <option value="SHARED">Shared / credential available</option>
            <option value="PARTITIONED">Partitioned / reclaim required</option>
          </select></label>`;
        row.append(special);
      }

      const actions = document.createElement('div'); actions.className = 'actions';
      for (const [action, labelText] of [['start','Start'],['pass','Pass'],['fail','Fail'],['block','Block'],['reset','Reset']]) {
        const button = document.createElement('button');
        button.type = 'button'; button.dataset.action = action; button.textContent = labelText;
        actions.append(button);
      }
      row.append(actions);
    }
  }

  function setGateStatus(id, status) {
    const row = document.querySelector(`[data-gate="${id}"]`);
    if (!row) return;
    row.dataset.status = status;
    const badge = row.querySelector('.status');
    if (badge) badge.textContent = status;
    state.gates[id].status = status;
  }

  function setGateError(id, message) {
    const node = document.querySelector(`[data-gate="${id}"] [data-gate-error]`);
    if (node) node.textContent = message || '';
  }

  function setSessionState(next, message = '') {
    state.session.state = next;
    document.body.dataset.sessionState = next;
    const banner = $('[data-session-banner]');
    if (banner) banner.textContent = message || (next === 'ACTIVE' ? 'Certification session active.' : next);
  }

  function snapshotGate(id) {
    const row = document.querySelector(`[data-gate="${id}"]`);
    if (!row) return;
    const current = state.gates[id];
    current.observation = scrubText($('[data-operator-observation]', row)?.value || '');
    current.reference = scrubText($('[data-reference]', row)?.value || '');
    current.reason = scrubText($('[data-reason]', row)?.value || '');
    current.attestation = Boolean($('[data-attestation]', row)?.checked);
    current.checks = $$('[data-required-check]', row).map(input => Boolean(input.checked));
    if (id === 'A6') {
      const raw = $('[data-background-minutes]', row)?.value;
      current.backgroundMinutes = raw === '' || raw == null ? null : Number(raw);
      current.realDevice = Boolean($('[data-real-device]', row)?.checked);
    }
    if (id === 'A12') current.storagePartition = $('[data-storage-partition]', row)?.value || 'UNKNOWN';
  }

  function persist() {
    try {
      state.session.deviceModel = scrubText($('#deviceModel')?.value || state.session.deviceModel || '');
      state.session.iosVersion = scrubText($('#iosVersion')?.value || state.session.iosVersion || '');
      localStorage.setItem(STORE_KEY, JSON.stringify(state));
    } catch (_) {}
  }

  function loadStored() {
    try {
      const parsed = JSON.parse(localStorage.getItem(STORE_KEY) || 'null');
      if (!parsed || parsed.version !== SCHEMA_VERSION || !parsed.session || !parsed.gates) return null;
      return parsed;
    } catch (_) {
      return null;
    }
  }

  function restoreGateInputs(id, saved) {
    const row = document.querySelector(`[data-gate="${id}"]`);
    if (!row || !saved) return;
    setGateStatus(id, saved.status || 'NOT_RUN');
    const observation = $('[data-operator-observation]', row); if (observation) observation.value = saved.observation || '';
    const reference = $('[data-reference]', row); if (reference) reference.value = saved.reference || '';
    const reason = $('[data-reason]', row); if (reason) reason.value = saved.reason || '';
    const attestation = $('[data-attestation]', row); if (attestation) attestation.checked = Boolean(saved.attestation);
    $$('[data-required-check]', row).forEach((input, index) => { input.checked = Boolean(saved.checks?.[index]); });
    if (id === 'A6') {
      const minutes = $('[data-background-minutes]', row); if (minutes && saved.backgroundMinutes != null) minutes.value = String(saved.backgroundMinutes);
      const real = $('[data-real-device]', row); if (real) real.checked = Boolean(saved.realDevice);
    }
    if (id === 'A12') {
      const partition = $('[data-storage-partition]', row); if (partition) partition.value = saved.storagePartition || 'UNKNOWN';
    }
  }

  function baseEvidenceComplete(id) {
    const row = document.querySelector(`[data-gate="${id}"]`);
    if (!row) return false;
    if (!String($('[data-operator-observation]', row)?.value || '').trim()) {
      setGateError(id, 'Add the operator observation from the required physical device.'); return false;
    }
    if (!$('[data-attestation]', row)?.checked) {
      setGateError(id, 'Physical-device attestation is required.'); return false;
    }
    const checks = $$('[data-required-check]', row);
    if (!checks.length || checks.some(input => !input.checked)) {
      setGateError(id, 'Complete every required physical checkpoint.'); return false;
    }
    return true;
  }

  function specialEvidenceComplete(id) {
    const row = document.querySelector(`[data-gate="${id}"]`);
    if (id === 'A6') {
      const minutes = Number($('[data-background-minutes]', row)?.value);
      if (!$('[data-real-device]', row)?.checked) {
        setGateError(id, 'A6 requires explicit confirmation of a real physical-device run.'); return false;
      }
      if (!Number.isFinite(minutes) || minutes < 10) {
        setGateError(id, 'A6 requires at least 10 measured background minutes.'); return false;
      }
    }
    if (id === 'A11') {
      const version = String($('#iosVersion')?.value || '').trim();
      const major = Number(version.split('.')[0]);
      if (!Number.isFinite(major) || major < 27) {
        setGateError(id, 'A11 requires iOS 27 or later on the real device.'); return false;
      }
    }
    if (id === 'A12') {
      const answer = $('[data-storage-partition]', row)?.value || 'UNKNOWN';
      if (answer === 'UNKNOWN') {
        setGateError(id, 'Record the observed Safari-to-Home-Screen storage-partition result.'); return false;
      }
    }
    return true;
  }

  function handleGateAction(id, action) {
    const gateState = state.gates[id];
    if (!gateState) return;
    const current = gateState.status;

    if (action === 'reset') {
      gateState.startedAt = null; gateState.completedAt = null;
      setGateStatus(id, 'NOT_RUN'); setGateError(id, ''); snapshotGate(id); persist(); return;
    }
    if (state.session.state !== 'ACTIVE') return;
    if (action === 'start') {
      if (current !== 'NOT_RUN') return;
      gateState.startedAt = new Date().toISOString(); gateState.completedAt = null;
      setGateStatus(id, 'RUNNING'); setGateError(id, ''); snapshotGate(id); persist(); return;
    }
    if (TERMINAL.has(current) || current !== 'RUNNING') return;

    if (action === 'fail' || action === 'block') {
      const reason = String($('[data-reason]', document.querySelector(`[data-gate="${id}"]`))?.value || '').trim();
      if (!reason) { setGateError(id, 'A reason is required for FAIL or BLOCKED.'); return; }
      snapshotGate(id);
      gateState.completedAt = new Date().toISOString();
      setGateStatus(id, action === 'fail' ? 'FAIL' : 'BLOCKED');
      setGateError(id, ''); persist(); return;
    }

    if (action === 'pass') {
      if (!baseEvidenceComplete(id) || !specialEvidenceComplete(id)) return;
      snapshotGate(id);
      gateState.completedAt = new Date().toISOString();
      setGateStatus(id, 'PASS'); setGateError(id, ''); persist();
    }
  }

  function bindActions() {
    document.addEventListener('click', event => {
      const button = event.target.closest('[data-action]');
      if (!button) return;
      const row = button.closest('[data-gate]');
      if (!row) return;
      handleGateAction(row.dataset.gate, button.dataset.action);
    });
    $('[data-start-session]')?.addEventListener('click', startSession);
    $('[data-verify-environment]')?.addEventListener('click', verifyEnvironment);
    $('[data-export]')?.addEventListener('click', exportEvidence);
  }

  async function startSession() {
    const candidate = String($('#candidateExpected')?.value || '').trim();
    const observed = environment?.appGeneration || document.body.dataset.observedGeneration || 'UNKNOWN';
    state.session.candidate = candidate;
    state.session.origin = location.origin;
    state.session.deviceModel = scrubText($('#deviceModel')?.value || '');
    state.session.iosVersion = scrubText($('#iosVersion')?.value || '');
    state.session.startedAt ||= new Date().toISOString();
    state.session.environment = { ...environment, deviceModel: state.session.deviceModel, iosVersion: state.session.iosVersion };
    if (!candidate || candidate !== observed) {
      setSessionState('INVALID', `Candidate mismatch: expected ${candidate || 'unset'}, observed ${observed}.`);
      persist(); return;
    }
    setSessionState('ACTIVE', `Candidate ${candidate} frozen. Complete A1–A12 only on the required physical iPhone.`);
    persist();
  }

  async function verifyEnvironment() {
    const current = await captureEnvironment();
    const frozen = state.session.candidate || String($('#candidateExpected')?.value || '').trim();
    if (frozen && current.appGeneration !== frozen) {
      setSessionState('INVALID', `Candidate mismatch: frozen ${frozen}, now observed ${current.appGeneration}. Start a fresh certification session.`);
      persist(); return;
    }
    if (state.session.state === 'ACTIVE') {
      $('[data-session-banner]').textContent = `Environment still matches frozen candidate ${frozen}.`;
    }
  }

  function exportEvidence() {
    for (const id of Object.keys(GATES)) snapshotGate(id);
    persist();
    const payload = {
      schema: 'freightlogic-field-cert-v1',
      candidate: state.session.candidate,
      environment: state.session.environment,
      sessionState: state.session.state,
      startedAt: state.session.startedAt,
      completedAt: state.session.completedAt,
      gates: Object.fromEntries(Object.entries(state.gates).map(([id, gate]) => [id, {
        status: gate.status,
        startedAt: gate.startedAt,
        completedAt: gate.completedAt,
        observation: scrubText(gate.observation),
        reference: scrubText(gate.reference),
        reason: scrubText(gate.reason),
        attestation: Boolean(gate.attestation),
        checks: gate.checks,
        ...(id === 'A6' ? { backgroundMinutes: gate.backgroundMinutes, realDevice: Boolean(gate.realDevice) } : {}),
        ...(id === 'A12' ? { storagePartition: gate.storagePartition } : {})
      }]))
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    const candidate = (state.session.candidate || 'unstarted').replace(/[^A-Za-z0-9._-]+/g, '-');
    anchor.href = url; anchor.download = `freightlogic-field-cert-${candidate}.json`;
    document.body.append(anchor); anchor.click(); anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  async function boot() {
    renderGateDetails(); bindActions();
    const queryCandidate = new URLSearchParams(location.search).get('candidate');
    environment = await captureEnvironment();
    const observed = environment.appGeneration;
    const candidateInput = $('#candidateExpected');
    if (candidateInput) candidateInput.value = queryCandidate || observed;

    const saved = loadStored();
    if (saved) {
      state = saved;
      const sameCandidate = Boolean(saved.session.candidate) && saved.session.candidate === observed;
      const sameOrigin = !saved.session.origin || saved.session.origin === location.origin;
      if (sameCandidate && sameOrigin && saved.session.state === 'ACTIVE') {
        if (candidateInput) candidateInput.value = saved.session.candidate;
        if ($('#deviceModel')) $('#deviceModel').value = saved.session.deviceModel || '';
        if ($('#iosVersion')) $('#iosVersion').value = saved.session.iosVersion || '';
        for (const id of Object.keys(GATES)) restoreGateInputs(id, saved.gates[id]);
        setSessionState('ACTIVE', `Resumed candidate ${saved.session.candidate}. Environment still matches.`);
      } else if (saved.session.state === 'INVALID') {
        if (candidateInput) candidateInput.value = queryCandidate || saved.session.candidate || observed;
        if ($('#deviceModel')) $('#deviceModel').value = saved.session.deviceModel || '';
        if ($('#iosVersion')) $('#iosVersion').value = saved.session.iosVersion || '';
        for (const id of Object.keys(GATES)) restoreGateInputs(id, saved.gates[id]);
        setSessionState('INVALID', 'Previous certification session is invalid. Reset/start a matching candidate before continuing.');
      } else {
        state = freshState();
        if (candidateInput) candidateInput.value = queryCandidate || observed;
      }
    }
    document.body.dataset.environmentReady = 'true';
  }

  boot().catch(error => {
    document.body.dataset.environmentReady = 'true';
    setSessionState('INVALID', `Environment capture failed closed: ${error?.message || 'unknown error'}`);
  });
})();
