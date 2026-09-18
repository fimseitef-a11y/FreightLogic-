(() => {
  'use strict';

  const STORE_KEY = 'freightlogic_field_cert_v1';
  const SCHEMA_VERSION = 1;
  const CHECKLIST_VERSION = 'A1-A12-2026-09-17';
  const BACKUP_WORKER_HEALTH = 'https://freightlogic-backup.fimseitef.workers.dev/health';

  const GATES = {
    A1: {
      expected: 'The installed Home Screen app reaches the exact frozen candidate through the normal non-destructive update path with no data loss or blank/update loop.',
      checks: [
        'Confirmed the installed PWA shows the same candidate generation recorded above.',
        'Confirmed the normal update/launch path completed without clearing site data.',
        'Confirmed existing local FreightLogic data remained present after the update.'
      ]
    },
    A2: {
      expected: 'Missing deadhead remains UNKNOWN while an explicit 0 remains a verified real zero in both quick and full evaluation paths.',
      checks: [
        'Ran a synthetic case with deadhead omitted and observed UNKNOWN rather than 0.',
        'Ran the same synthetic case with deadhead explicitly set to 0 and observed a known zero.',
        'Confirmed the two cases did not collapse to the same canonical result.'
      ]
    },
    A3: {
      expected: 'A synthetic opportunity created through the shipped intake path retains identity and provenance after close/reopen.',
      checks: [
        'Created one synthetic opportunity through the shipped intake surface.',
        'Recorded its non-sensitive identity/provenance summary before closing.',
        'Closed/reopened the app and confirmed the same opportunity/evidence remained.'
      ]
    },
    A4: {
      expected: 'The app survives a real-device offline round trip without duplicating or losing synthetic local mutations.',
      checks: [
        'Primed the app online before disconnecting.',
        'Enabled Airplane Mode on the physical iPhone.',
        'Performed the approved synthetic local mutation/navigation while offline.',
        'Closed and reopened the FreightLogic app while still offline.',
        'Reconnected and confirmed there was no duplicate or missing synthetic record.'
      ]
    },
    A5: {
      expected: 'Local export/import preserves integrity, rejects a corrupted synthetic payload, and exposes no protected credentials.',
      checks: [
        'Exported only synthetic/non-sensitive test data.',
        'Inspected the export without revealing token, PIN, passphrase, invite, or claim secrets.',
        'Re-imported the valid synthetic export and confirmed expected integrity.',
        'Tried the approved corrupted synthetic payload and observed rejection.'
      ]
    },
    A6: {
      expected: 'A real iPhone GPS trip survives background/lock for at least 10 minutes and remains stoppable/salvageable on return.',
      checks: [
        'Started a test trip while safely stationary.',
        'Moved a representative distance without interacting with the phone while driving.',
        'Backgrounded/locked the iPhone, then returned after the measured interval.',
        'Stopped/saved the trip and recorded the visible tracking quality/degradation state.'
      ]
    },
    A7: {
      expected: 'Revoking Location permission mid-trip produces a visible paused/degraded state while preserving a salvageable trip.',
      checks: [
        'Started a synthetic/test trip on the physical iPhone.',
        'Revoked FreightLogic Location permission in iOS Settings.',
        'Observed the visible paused/degraded tracking state.',
        'Confirmed the open trip remained stoppable and salvageable.'
      ]
    },
    A8: {
      expected: 'A stale second Safari-tab edit cannot silently overwrite the newer first save.',
      checks: [
        'Opened the same synthetic record in two real Safari tabs.',
        'Saved a change from the first tab.',
        'Attempted a stale save from the second tab.',
        'Confirmed the newer value survived and the stale writer did not silently overwrite it.'
      ]
    },
    A9: {
      expected: 'Doctrine/geography/cargo-fit/profit boundaries remain exact on the physical candidate.',
      checks: [
        'Checked blank/short market text plus Gary vs Calgary.',
        'Checked cargo length 121 in passes and 122 in blocks.',
        'Checked wheel-well width 54.8 in passes and 54.9 in blocks.',
        'Checked 3000 lb passes and 3001 lb blocks.',
        'Checked defensible cost input versus missing/undefended cost input.'
      ]
    },
    A10: {
      expected: 'Pickup feasibility keeps unset speed inert, distinguishes impossible/reachable/tight windows, and preserves UNKNOWN vs explicit-zero deadhead.',
      checks: [
        'Checked no planning speed set.',
        'Checked an impossible pickup window.',
        'Checked a comfortably reachable pickup window.',
        'Checked a reachable-but-tight pickup window.',
        'Checked UNKNOWN deadhead separately from explicit zero deadhead.'
      ]
    },
    A11: {
      expected: 'The exact candidate has no required visual/regression defect on a real iPhone running iOS 27 or later.',
      checks: [
        'Inspected the F31 SVG chart.',
        'Inspected primary tab icons and labels.',
        'Inspected every required select/menu control.',
        'Checked scroll anchoring/restoration behavior.',
        'Checked persistent-storage grant behavior.',
        'Checked backup-paused banner and Resume behavior.'
      ]
    },
    A12: {
      expected: 'Owner invite → Safari claim → Home Screen launch/reclaim preserves one canonical user/backup history, with storage-partition behavior explicitly observed and no credential value recorded.',
      checks: [
        'Created the owner-side invite using the shipped flow without copying any secret into this runner.',
        'Claimed through Safari and then launched/reclaimed through the Home Screen app.',
        'Confirmed the same canonical user/backup history was preserved.',
        'Observed the real-device delivery/reclaim behavior without recording any token, code, PIN, or passphrase.'
      ]
    }
  };

  const body = document.body;
  const qs = (selector, root = document) => root.querySelector(selector);
  const qsa = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  let currentEnvironment = null;
  let session = null;

  function nowIso() { return new Date().toISOString(); }

  function normalizeGeneration(value) {
    const match = String(value || '').match(/(?:^|\bv)?(\d+\.\d+\.\d+)\b/i);
    return match ? match[1] : 'UNAVAILABLE';
  }

  function sanitizeText(value) {
    let text = String(value || '');
    text = text.replace(/\bflk_[A-Za-z0-9_-]+\b/gi, '[REDACTED_TOKEN]');
    text = text.replace(/\b(bearer|token|admin[_ -]?token|passphrase|password|pin(?:hash)?|invite(?:code)?|claim(?:code)?|secret)\s*[:=]\s*([^\s,;]+)/gi, (_m, key) => `${key}=[REDACTED]`);
    text = text.replace(/\bAuthorization\s*:\s*Bearer\s+[^\s,;]+/gi, 'Authorization: Bearer [REDACTED]');
    return text.slice(0, 4000);
  }

  function safeSessionForStorage(source) {
    if (!source) return null;
    const out = JSON.parse(JSON.stringify(source));
    out.deviceModel = sanitizeText(out.deviceModel);
    out.iosVersion = sanitizeText(out.iosVersion);
    if (out.environment) {
      out.environment.deviceModel = sanitizeText(out.environment.deviceModel);
      out.environment.iosVersion = sanitizeText(out.environment.iosVersion);
    }
    if (out.gates) {
      for (const gate of Object.values(out.gates)) {
        gate.operatorObservation = sanitizeText(gate.operatorObservation);
        gate.reference = sanitizeText(gate.reference);
        gate.reason = sanitizeText(gate.reason);
        if (Array.isArray(gate.automatedObservations)) gate.automatedObservations = gate.automatedObservations.map(sanitizeText);
      }
    }
    return out;
  }

  function saveSession() {
    if (!session) return;
    try { localStorage.setItem(STORE_KEY, JSON.stringify(safeSessionForStorage(session))); } catch (_err) { /* local-only best effort */ }
  }

  function loadSession() {
    try {
      const raw = localStorage.getItem(STORE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      return parsed && parsed.schemaVersion === SCHEMA_VERSION ? parsed : null;
    } catch (_err) { return null; }
  }

  function launchMode() {
    const standalone = (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) || navigator.standalone === true;
    return standalone ? 'HOME_SCREEN_PWA' : 'SAFARI_OR_BROWSER_TAB';
  }

  function browserFact() {
    const ua = navigator.userAgent || '';
    if (/CriOS/i.test(ua)) return 'Chrome iOS';
    if (/FxiOS/i.test(ua)) return 'Firefox iOS';
    if (/Safari/i.test(ua) && !/Chrome|Chromium|CriOS/i.test(ua)) return 'Safari/WebKit';
    if (/Chrome|Chromium/i.test(ua)) return 'Chromium';
    return 'Web browser';
  }

  async function fetchText(url, timeoutMs = 1500) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, { cache: 'no-store', signal: controller.signal });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.text();
    } finally { clearTimeout(timer); }
  }

  async function fetchJson(url, timeoutMs = 1500) {
    return JSON.parse(await fetchText(url, timeoutMs));
  }

  async function observeEnvironment() {
    const observed = {
      origin: location.origin,
      appGeneration: 'UNAVAILABLE',
      indexedDbSchema: 'UNAVAILABLE',
      swScript: 'UNAVAILABLE',
      swScope: 'UNAVAILABLE',
      swCache: 'UNAVAILABLE',
      generationCaches: 'UNAVAILABLE',
      cacheGenerationStatus: 'UNAVAILABLE',
      storagePersisted: 'UNAVAILABLE',
      workerGeneration: 'UNAVAILABLE',
      gitSha: 'UNAVAILABLE',
      launchMode: launchMode(),
      browser: browserFact(),
      deviceModel: 'OPERATOR_REQUIRED',
      iosVersion: 'OPERATOR_REQUIRED',
      timestamp: nowIso()
    };

    try {
      const manifest = await fetchJson(`manifest.json?fieldcert=${Date.now()}`, 1500);
      observed.appGeneration = normalizeGeneration(`${manifest.name || ''} ${manifest.short_name || ''}`);
    } catch (_err) { /* fail closed later if generation cannot be identified */ }

    try {
      const appSource = await fetchText(`app.js?fieldcert=${Date.now()}`, 1500);
      const db = appSource.match(/\bDB_VERSION\s*=\s*(\d+)/);
      if (db) observed.indexedDbSchema = `DB${db[1]}`;
      const sha = appSource.match(/\b(?:GIT_SHA|BUILD_SHA|COMMIT_SHA)\s*=\s*['\"]([0-9a-f]{7,40})['\"]/i);
      if (sha) observed.gitSha = sha[1];
    } catch (_err) { /* informational */ }

    if (observed.indexedDbSchema === 'UNAVAILABLE') {
      try {
        if (indexedDB.databases) {
          const dbs = await indexedDB.databases();
          const versions = dbs.map(db => Number(db.version)).filter(Number.isFinite);
          if (versions.length) observed.indexedDbSchema = `DB${Math.max(...versions)}`;
        }
      } catch (_err) { /* informational */ }
    }

    try {
      if ('serviceWorker' in navigator) {
        const reg = await navigator.serviceWorker.getRegistration();
        if (reg) {
          const worker = reg.active || reg.waiting || reg.installing;
          observed.swScript = worker?.scriptURL || 'UNAVAILABLE';
          observed.swScope = reg.scope || 'UNAVAILABLE';
        }
      }
    } catch (_err) { /* informational */ }

    try {
      if ('caches' in window) {
        const keys = await caches.keys();
        const freight = keys.filter(key => /freightlogic|fl-/i.test(key));
        observed.swCache = freight.length ? freight.sort().join(', ') : 'NONE_OBSERVED';

        // Only version-shaped app caches count toward A1. The share-target cache
        // (for example freightlogic-share-v2) is intentionally not a generation.
        const generationCaches = keys.filter(key => /^freightlogic-v?\d+\.\d+\.\d+$/i.test(key)).sort();
        observed.generationCaches = generationCaches.length ? generationCaches.join(', ') : 'NONE_OBSERVED';
        if (observed.appGeneration !== 'UNAVAILABLE') {
          const matching = generationCaches.filter(key => normalizeGeneration(key) === observed.appGeneration);
          observed.cacheGenerationStatus = generationCaches.length === 1 && matching.length === 1
            ? 'MATCH'
            : `MISMATCH generationCaches=${generationCaches.length} matchingCandidate=${matching.length}`;
        }
      }
    } catch (_err) { /* informational */ }

    try {
      if (navigator.storage && typeof navigator.storage.persisted === 'function') {
        observed.storagePersisted = (await navigator.storage.persisted()) ? 'GRANTED' : 'NOT_GRANTED';
      }
    } catch (_err) { /* informational */ }

    try {
      const health = await fetchJson(`${BACKUP_WORKER_HEALTH}?fieldcert=${Date.now()}`, 1000);
      const raw = health.version ?? health.workerVersion ?? health.generation ?? health.worker_generation;
      if (raw !== undefined && raw !== null) observed.workerGeneration = String(raw).slice(0, 80);
    } catch (_err) { /* never guess Worker state */ }

    return observed;
  }

  function criticalEnvironmentMatches(frozen, observed) {
    if (!frozen || !observed) return false;
    const strict = ['origin', 'appGeneration', 'indexedDbSchema', 'swScript', 'swScope'];
    for (const key of strict) {
      const a = frozen[key];
      const b = observed[key];
      if (a && b && a !== 'UNAVAILABLE' && b !== 'UNAVAILABLE' && a !== b) return false;
    }
    if (frozen.workerGeneration && observed.workerGeneration && frozen.workerGeneration !== 'UNAVAILABLE' && observed.workerGeneration !== 'UNAVAILABLE' && frozen.workerGeneration !== observed.workerGeneration) return false;
    if (frozen.swCache && observed.swCache && !['UNAVAILABLE', 'NONE_OBSERVED'].includes(frozen.swCache) && !['UNAVAILABLE', 'NONE_OBSERVED'].includes(observed.swCache) && frozen.swCache !== observed.swCache) return false;
    return true;
  }

  function environmentFingerprint(env) {
    const fields = ['origin', 'appGeneration', 'indexedDbSchema', 'swScript', 'swScope', 'swCache', 'workerGeneration'];
    return fields.map(key => `${key}=${env?.[key] ?? 'UNAVAILABLE'}`).join('|');
  }

  function renderEnvironment(env) {
    for (const el of qsa('[data-env-key]')) {
      const key = el.getAttribute('data-env-key');
      el.textContent = env?.[key] ?? 'UNAVAILABLE';
    }
    body.dataset.observedGeneration = env?.appGeneration || 'UNAVAILABLE';
  }

  function upsertAutomatedObservation(rec, label, message) {
    if (!rec) return;
    const prefix = `${label}:`;
    const list = Array.isArray(rec.automatedObservations) ? rec.automatedObservations : [];
    rec.automatedObservations = list.filter(item => !String(item).startsWith(prefix));
    rec.automatedObservations.push(`${prefix} ${sanitizeText(message)}`);
  }

  function renderAutomatedObservations(row, rec) {
    const el = qs('[data-automated-observation]', row);
    if (!el || !rec) return;
    const list = Array.isArray(rec.automatedObservations) ? rec.automatedObservations : [];
    el.textContent = list.join(' • ');
  }

  function applyEnvironmentObservations(env) {
    const a1 = gateRecord('A1');
    const a11 = gateRecord('A11');
    upsertAutomatedObservation(
      a1,
      'A1 generation cache',
      `status=${env?.cacheGenerationStatus || 'UNAVAILABLE'}; version-shaped caches=${env?.generationCaches || 'UNAVAILABLE'}; freightlogic-share-v2 is excluded from generation counting.`
    );
    upsertAutomatedObservation(
      a11,
      'A11 persistent storage',
      `navigator.storage.persisted(): ${env?.storagePersisted || 'UNAVAILABLE'}.`
    );
  }

  function isProtectedExportField(key) {
    const normalized = String(key || '').replace(/[^a-z0-9]/gi, '').toLowerCase();
    if (['cloudbackuptoken', 'applockpin', 'cloudadmintokenenc'].includes(normalized)) return true;
    return /lockout|failedpin|pinfail|pinattempt|applockfail/.test(normalized);
  }

  function isDeadheadField(key) {
    const normalized = String(key || '').replace(/[^a-z0-9]/gi, '').toLowerCase();
    return ['emptymiles', 'deadhead', 'deadheadmiles', 'deadmi'].includes(normalized);
  }

  function inspectExportStructure(value) {
    const protectedFieldNames = new Set();
    const deadheadFieldNames = new Set();
    let deadheadNull = 0;
    let deadheadZero = 0;
    let deadheadOther = 0;

    const visit = node => {
      if (Array.isArray(node)) {
        for (const item of node) visit(item);
        return;
      }
      if (!node || typeof node !== 'object') return;
      for (const [key, child] of Object.entries(node)) {
        if (isProtectedExportField(key)) protectedFieldNames.add(key);
        if (isDeadheadField(key)) {
          deadheadFieldNames.add(key);
          if (child === null) deadheadNull++;
          else if (child === 0) deadheadZero++;
          else deadheadOther++;
        }
        visit(child);
      }
    };
    visit(value);
    return {
      protectedFieldNames: Array.from(protectedFieldNames).sort(),
      deadheadFieldNames: Array.from(deadheadFieldNames).sort(),
      deadheadNull,
      deadheadZero,
      deadheadOther
    };
  }

  async function inspectA5Export(row, file) {
    const rec = gateRecord('A5');
    if (!rec || !file) return;
    try {
      const parsed = JSON.parse(await file.text());
      const info = inspectExportStructure(parsed);
      const protectedNames = info.protectedFieldNames.length ? info.protectedFieldNames.join(', ') : 'none';
      const deadheadNames = info.deadheadFieldNames.length ? info.deadheadFieldNames.join(', ') : 'none';
      upsertAutomatedObservation(
        rec,
        'A5 export structure',
        `protected field names detected=${protectedNames}; deadhead field names=${deadheadNames}; deadhead null=${info.deadheadNull}; deadhead zero=${info.deadheadZero}; deadhead other=${info.deadheadOther}; structure-only inspection retained no field values.`
      );
    } catch (_err) {
      upsertAutomatedObservation(rec, 'A5 export structure', 'JSON could not be parsed; no payload values were retained.');
    }
    renderAutomatedObservations(row, rec);
    saveSession();
  }

  function setSessionState(state, message) {
    body.dataset.sessionState = state;
    const banner = qs('[data-session-banner]');
    if (banner) banner.textContent = message || state;
    if (session) {
      session.sessionState = state;
      if (state === 'INVALID') session.invalidatedAt = nowIso();
      saveSession();
    }
    updateControlAvailability();
  }

  function gateRecord(id) {
    return session?.gates?.[id] || null;
  }

  function setGateStatus(id, status) {
    const row = qs(`[data-gate="${id}"]`);
    const rec = gateRecord(id);
    if (!row || !rec) return;
    rec.status = status;
    row.dataset.status = status;
    const badge = qs('.status', row);
    if (badge) badge.textContent = status;
    saveSession();
    updateControlAvailability();
  }

  function clearGateError(row) {
    const error = qs('[data-gate-error]', row);
    if (error) error.textContent = '';
  }

  function gateError(row, message) {
    const error = qs('[data-gate-error]', row);
    if (error) error.textContent = message;
  }

  function readGateInputs(row, rec) {
    rec.operatorObservation = sanitizeText(qs('[data-operator-observation]', row)?.value || '');
    rec.reference = sanitizeText(qs('[data-reference]', row)?.value || '');
    rec.reason = sanitizeText(qs('[data-reason]', row)?.value || '');
    rec.attestedPhysicalDevice = Boolean(qs('[data-attestation]', row)?.checked);
    rec.manualChecks = qsa('[data-required-check]', row).map(input => Boolean(input.checked));
    if (row.dataset.gate === 'A6') {
      rec.realDevice = Boolean(qs('[data-real-device]', row)?.checked);
      rec.backgroundMinutes = Number(qs('[data-background-minutes]', row)?.value || 0);
    }
    if (row.dataset.gate === 'A12') rec.storagePartition = qs('[data-storage-partition]', row)?.value || 'UNANSWERED';
  }

  function restoreGateInputs(row, rec) {
    const observation = qs('[data-operator-observation]', row);
    const reference = qs('[data-reference]', row);
    const reason = qs('[data-reason]', row);
    const attestation = qs('[data-attestation]', row);
    if (observation) observation.value = rec.operatorObservation || '';
    if (reference) reference.value = rec.reference || '';
    if (reason) reason.value = rec.reason || '';
    if (attestation) attestation.checked = Boolean(rec.attestedPhysicalDevice);
    qsa('[data-required-check]', row).forEach((input, i) => { input.checked = Boolean(rec.manualChecks?.[i]); });
    if (row.dataset.gate === 'A6') {
      const real = qs('[data-real-device]', row);
      const mins = qs('[data-background-minutes]', row);
      if (real) real.checked = Boolean(rec.realDevice);
      if (mins && Number.isFinite(rec.backgroundMinutes)) mins.value = rec.backgroundMinutes ? String(rec.backgroundMinutes) : '';
    }
    if (row.dataset.gate === 'A12') {
      const storage = qs('[data-storage-partition]', row);
      if (storage) storage.value = rec.storagePartition || 'UNANSWERED';
    }
    renderAutomatedObservations(row, rec);
  }

  function captureGateProgress(row) {
    if (!session) return;
    const rec = gateRecord(row.dataset.gate);
    if (!rec) return;
    readGateInputs(row, rec);
    saveSession();
  }

  function validatePass(row, rec) {
    if (body.dataset.sessionState !== 'ACTIVE') return 'Certification session is not active.';
    if (rec.status !== 'RUNNING') return 'Start this row before recording PASS.';
    readGateInputs(row, rec);
    if (!rec.operatorObservation.trim()) return 'Record the operator observation from the physical device.';
    if (!rec.attestedPhysicalDevice) return 'Physical-device attestation is required.';
    if (!rec.manualChecks.length || rec.manualChecks.some(value => !value)) return 'Complete every required physical checkpoint.';

    if (row.dataset.gate === 'A6') {
      if (!rec.realDevice) return 'A6 requires explicit real-device confirmation.';
      if (!Number.isFinite(rec.backgroundMinutes) || rec.backgroundMinutes < 10) return 'A6 requires at least 10 measured background/lock minutes.';
    }
    if (row.dataset.gate === 'A11') {
      const major = Number.parseInt(String(session.iosVersion || '').match(/\d+/)?.[0] || '0', 10);
      if (!Number.isFinite(major) || major < 27) return 'A11 requires a real device running iOS 27 or later.';
    }
    if (row.dataset.gate === 'A12' && (!rec.storagePartition || rec.storagePartition === 'UNANSWERED')) {
      return 'A12 requires the observed Safari → Home Screen storage-partition answer.';
    }
    return null;
  }

  function onGateAction(row, action) {
    if (!session) return;
    const id = row.dataset.gate;
    const rec = gateRecord(id);
    if (!rec) return;
    clearGateError(row);

    if (action === 'reset') {
      rec.status = 'NOT_RUN';
      rec.startedAt = null;
      rec.completedAt = null;
      rec.operatorObservation = '';
      rec.reference = '';
      rec.reason = '';
      rec.attestedPhysicalDevice = false;
      rec.manualChecks = (GATES[id].checks || []).map(() => false);
      rec.realDevice = false;
      rec.backgroundMinutes = 0;
      rec.storagePartition = 'UNANSWERED';
      rec.environmentFingerprint = null;
      if (id === 'A5') {
        rec.automatedObservations = (rec.automatedObservations || []).filter(item => !String(item).startsWith('A5 export structure:'));
      }
      restoreGateInputs(row, rec);
      setGateStatus(id, 'NOT_RUN');
      return;
    }

    if (body.dataset.sessionState !== 'ACTIVE') {
      gateError(row, 'Start a valid certification session before changing this row.');
      return;
    }

    if (action === 'start') {
      if (rec.status !== 'NOT_RUN') return;
      rec.startedAt = nowIso();
      rec.environmentFingerprint = session.environmentFingerprint;
      setGateStatus(id, 'RUNNING');
      return;
    }

    if (rec.status !== 'RUNNING') return;
    readGateInputs(row, rec);

    if (action === 'pass') {
      const problem = validatePass(row, rec);
      if (problem) {
        gateError(row, problem);
        saveSession();
        return;
      }
      rec.reason = '';
      rec.completedAt = nowIso();
      setGateStatus(id, 'PASS');
      maybeCompleteSession();
      return;
    }

    if (action === 'fail' || action === 'block') {
      if (!rec.reason.trim()) {
        gateError(row, `Record the ${action === 'fail' ? 'failure' : 'blocking'} reason first.`);
        return;
      }
      rec.completedAt = nowIso();
      setGateStatus(id, action === 'fail' ? 'FAIL' : 'BLOCKED');
      maybeCompleteSession();
    }
  }

  function maybeCompleteSession() {
    if (!session) return;
    const statuses = Object.values(session.gates).map(g => g.status);
    if (statuses.every(status => status === 'PASS')) {
      session.completedAt = nowIso();
      setSessionState('COMPLETE', 'A1–A12 all show operator-recorded PASS for the frozen candidate.');
    }
  }

  function updateControlAvailability() {
    const active = body.dataset.sessionState === 'ACTIVE';
    for (const row of qsa('[data-gate]')) {
      const rec = gateRecord(row.dataset.gate);
      for (const btn of qsa('button[data-action]', row)) {
        if (btn.dataset.action === 'reset') btn.disabled = !rec || rec.status === 'NOT_RUN';
        else btn.disabled = !active;
      }
    }
  }

  function buildGateUI() {
    for (const row of qsa('[data-gate]')) {
      const id = row.dataset.gate;
      const def = GATES[id];
      if (!def) continue;
      const bodyEl = document.createElement('div');
      bodyEl.className = 'gate-body';
      bodyEl.innerHTML = `
        <p data-expected><strong>Expected:</strong> ${def.expected}</p>
        <div class="automated"><strong>Automated observation:</strong> <span data-automated-observation>Related automated regressions are informational only and never close this physical row.</span></div>
        <fieldset class="checks"><legend>Required physical checkpoints</legend>
          ${def.checks.map((label, index) => `<label><input type="checkbox" data-required-check="${index}"> <span>${label}</span></label>`).join('')}
        </fieldset>
        ${id === 'A5' ? `<div class="special"><label>Optional structure-only check of a synthetic export <input type="file" accept="application/json,.json" data-a5-export></label><p class="safety">This parses JSON locally and records matched field names plus null/zero counts only. Payload values are never copied into certification evidence.</p></div>` : ''}
        ${id === 'A6' ? `<div class="special"><label><input type="checkbox" data-real-device> This was executed on the real physical iPhone.</label><label>Measured background/lock minutes <input type="number" min="0" step="1" inputmode="numeric" data-background-minutes></label><p class="safety">Safety: make all phone interactions while safely parked/stationary; never interact with this runner while driving.</p></div>` : ''}
        ${id === 'A12' ? `<div class="special"><label>Safari → Home Screen credential storage observation <select data-storage-partition><option value="UNANSWERED">Not answered yet</option><option value="SHARED">Shared credential/storage state observed</option><option value="PARTITIONED">Partitioned storage / reclaim required</option><option value="OTHER">Other observed behavior</option></select></label></div>` : ''}
        <label class="field">Operator observation<textarea data-operator-observation rows="3" placeholder="Describe only the non-sensitive physical-device observation. Never paste credentials."></textarea></label>
        <label class="attestation"><input type="checkbox" data-attestation> I personally observed the required physical-device behavior described above.</label>
        <label class="field">Optional local screenshot/reference metadata<input data-reference placeholder="e.g. screenshot filename or local note — no secret values"></label>
        <label class="field">FAIL/BLOCKED reason<input data-reason placeholder="Required before FAIL or BLOCKED"></label>
        <div class="gate-actions"><button type="button" data-action="start">Start</button><button type="button" data-action="pass">PASS</button><button type="button" data-action="fail">FAIL</button><button type="button" data-action="block">BLOCKED</button><button type="button" data-action="reset">Reset row</button></div>
        <p class="gate-error" data-gate-error role="alert"></p>`;
      row.appendChild(bodyEl);

      row.addEventListener('click', event => {
        const button = event.target.closest('button[data-action]');
        if (!button) return;
        onGateAction(row, button.dataset.action);
      });
      row.addEventListener('input', () => captureGateProgress(row));
      row.addEventListener('change', () => captureGateProgress(row));
      if (id === 'A5') {
        const fileInput = qs('[data-a5-export]', row);
        fileInput?.addEventListener('change', async () => {
          const file = fileInput.files?.[0];
          if (file) await inspectA5Export(row, file);
          // Do not retain even a synthetic payload in the input control after inspection.
          fileInput.value = '';
        });
      }
    }
  }

  function makeFreshSession() {
    const gates = {};
    for (const id of Object.keys(GATES)) {
      gates[id] = {
        checklistRowId: id,
        checklistVersion: CHECKLIST_VERSION,
        status: 'NOT_RUN',
        expectedBehavior: GATES[id].expected,
        automatedObservations: ['Automated regressions are advisory only; physical PASS requires operator evidence.'],
        manualChecks: GATES[id].checks.map(() => false),
        operatorObservation: '',
        reference: '',
        reason: '',
        attestedPhysicalDevice: false,
        startedAt: null,
        completedAt: null,
        environmentFingerprint: null,
        realDevice: false,
        backgroundMinutes: 0,
        storagePartition: 'UNANSWERED'
      };
    }
    return {
      schemaVersion: SCHEMA_VERSION,
      checklistVersion: CHECKLIST_VERSION,
      sessionState: 'IDLE',
      candidate: '',
      deviceModel: '',
      iosVersion: '',
      startedAt: null,
      completedAt: null,
      invalidatedAt: null,
      environment: null,
      environmentFingerprint: null,
      gates
    };
  }

  function restoreSessionUI() {
    if (!session) return;
    qs('#candidateExpected').value = session.candidate || currentEnvironment?.appGeneration || '';
    qs('#deviceModel').value = session.deviceModel || '';
    qs('#iosVersion').value = session.iosVersion || '';
    for (const row of qsa('[data-gate]')) {
      const rec = gateRecord(row.dataset.gate);
      if (!rec) continue;
      row.dataset.status = rec.status || 'NOT_RUN';
      qs('.status', row).textContent = rec.status || 'NOT_RUN';
      restoreGateInputs(row, rec);
    }
    const message = session.sessionState === 'ACTIVE'
      ? 'Certification session resumed for the same frozen candidate.'
      : session.sessionState === 'COMPLETE'
        ? 'Completed local certification evidence resumed for the same frozen candidate.'
        : session.sessionState;
    setSessionState(session.sessionState || 'IDLE', message);
  }

  function invalidateSession(message) {
    if (!session) session = makeFreshSession();
    setSessionState('INVALID', message || 'Certification environment changed. Start a new session on the intended candidate.');
  }

  async function refreshEnvironment({ initial = false } = {}) {
    body.dataset.environmentReady = 'false';
    const observed = await observeEnvironment();
    currentEnvironment = observed;
    renderEnvironment(observed);

    if (initial) {
      const saved = loadSession();
      if (saved && ['ACTIVE', 'COMPLETE'].includes(saved.sessionState) && criticalEnvironmentMatches(saved.environment, observed) && saved.candidate === observed.appGeneration) {
        session = saved;
        restoreSessionUI();
      } else if (saved && ['ACTIVE', 'COMPLETE'].includes(saved.sessionState)) {
        session = saved;
        invalidateSession('Saved certification session no longer matches the observed runtime environment. Start a fresh session.');
      } else if (saved && saved.sessionState === 'INVALID') {
        session = saved;
        restoreSessionUI();
      } else {
        session = makeFreshSession();
        const requested = new URLSearchParams(location.search).get('candidate');
        session.candidate = requested ? normalizeGeneration(requested) : observed.appGeneration;
        restoreSessionUI();
      }
    } else if (session && ['ACTIVE', 'COMPLETE'].includes(session.sessionState)) {
      if (!criticalEnvironmentMatches(session.environment, observed) || session.candidate !== observed.appGeneration) {
        invalidateSession('Runtime generation/environment mismatch detected. This certification session is invalid and cannot continue.');
      } else {
        setSessionState(session.sessionState, 'Environment re-verified against the frozen candidate.');
      }
    }

    body.dataset.environmentReady = 'true';
    return observed;
  }

  function startCertification() {
    if (!currentEnvironment) return;
    const candidate = normalizeGeneration(qs('#candidateExpected').value);
    const deviceModel = sanitizeText(qs('#deviceModel').value.trim());
    const iosVersion = sanitizeText(qs('#iosVersion').value.trim());

    if (candidate === 'UNAVAILABLE' || currentEnvironment.appGeneration === 'UNAVAILABLE' || candidate !== currentEnvironment.appGeneration) {
      session = makeFreshSession();
      session.candidate = candidate;
      session.deviceModel = deviceModel;
      session.iosVersion = iosVersion;
      session.environment = currentEnvironment;
      invalidateSession(`Candidate/runtime mismatch: expected ${candidate}, observed ${currentEnvironment.appGeneration}.`);
      return;
    }
    if (!deviceModel || !iosVersion) {
      if (!session || session.sessionState === 'INVALID') session = makeFreshSession();
      session.candidate = candidate;
      setSessionState('IDLE', 'Enter the physical iPhone model and exact iOS version before starting.');
      return;
    }

    session = makeFreshSession();
    session.candidate = candidate;
    session.deviceModel = deviceModel;
    session.iosVersion = iosVersion;
    session.startedAt = nowIso();
    session.environment = { ...currentEnvironment, deviceModel, iosVersion };
    session.environmentFingerprint = environmentFingerprint(session.environment);
    applyEnvironmentObservations(session.environment);
    setSessionState('ACTIVE', `Certification active for FreightLogic v${candidate}. Physical-device evidence is required for every PASS.`);
    restoreSessionUI();
    saveSession();
  }

  function newSession() {
    session = makeFreshSession();
    session.candidate = currentEnvironment?.appGeneration || '';
    try { localStorage.removeItem(STORE_KEY); } catch (_err) { /* best effort */ }
    restoreSessionUI();
    setSessionState('IDLE', 'Fresh local certification session prepared.');
  }

  function exportEvidence() {
    if (!session) return;
    for (const row of qsa('[data-gate]')) captureGateProgress(row);
    const safe = safeSessionForStorage(session);
    const summary = {
      schemaVersion: safe.schemaVersion,
      checklistVersion: safe.checklistVersion,
      candidate: safe.candidate,
      sessionState: safe.sessionState,
      startedAt: safe.startedAt,
      completedAt: safe.completedAt,
      invalidatedAt: safe.invalidatedAt,
      environment: safe.environment,
      gates: Object.fromEntries(Object.entries(safe.gates).map(([id, gate]) => [id, {
        checklistRowId: gate.checklistRowId,
        checklistVersion: gate.checklistVersion,
        status: gate.status,
        expectedBehavior: gate.expectedBehavior,
        automatedObservations: gate.automatedObservations,
        manualChecks: gate.manualChecks,
        operatorObservation: gate.operatorObservation,
        reference: gate.reference,
        reason: gate.reason,
        attestedPhysicalDevice: gate.attestedPhysicalDevice,
        startedAt: gate.startedAt,
        completedAt: gate.completedAt,
        environmentFingerprint: gate.environmentFingerprint,
        backgroundMinutes: id === 'A6' ? gate.backgroundMinutes : undefined,
        realDevice: id === 'A6' ? gate.realDevice : undefined,
        storagePartition: id === 'A12' ? gate.storagePartition : undefined
      }]))
    };
    const blob = new Blob([JSON.stringify(summary, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const candidate = (safe.candidate || 'unknown').replace(/[^0-9A-Za-z._-]+/g, '-');
    a.href = url;
    a.download = `freightlogic-field-cert-${candidate}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function bindTopLevelControls() {
    qs('[data-start-session]')?.addEventListener('click', startCertification);
    qs('[data-verify-environment]')?.addEventListener('click', () => refreshEnvironment({ initial: false }));
    qs('[data-new-session]')?.addEventListener('click', newSession);
    qs('[data-export]')?.addEventListener('click', exportEvidence);
  }

  async function init() {
    buildGateUI();
    bindTopLevelControls();
    session = makeFreshSession();
    updateControlAvailability();
    await refreshEnvironment({ initial: true });
  }

  init().catch(error => {
    body.dataset.environmentReady = 'true';
    setSessionState('INVALID', `Field certification environment could not be initialized: ${sanitizeText(error?.message || error)}`);
  });
})();
