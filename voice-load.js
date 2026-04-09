/* FreightLogic v22.0.1 — Voice Load Module */
(() => {
  'use strict';

  const REQUIRED_IDS = [
    'mwVoiceBtn', 'mwVoiceStatus', 'mwRevenue', 'mwLoadedMi', 'mwDeadMi',
    'mwOrigin', 'mwDest', 'mwLoadNotes', 'mwEvalOutput'
  ];

  const STORAGE_KEYS = {
    drafts: 'voiceDrafts',
    corrections: 'voiceCorrections'
  };

  const FIELD_LABELS = {
    revenue: 'Revenue',
    loadedMiles: 'Loaded miles',
    deadMiles: 'Deadhead miles',
    origin: 'Origin',
    destination: 'Destination',
    notes: 'Load notes'
  };

  const COMMAND_ALIASES = {
    revenue: ['revenue', 'rate', 'pay', 'price', 'money'],
    loadedMiles: ['loaded miles', 'loaded', 'miles'],
    deadMiles: ['deadhead', 'dead head', 'empty', 'dead miles'],
    origin: ['origin', 'pickup', 'from'],
    destination: ['destination', 'drop', 'deliver to', 'deliver', 'to'],
    notes: ['note', 'notes', 'comment', 'comments']
  };

  const STATUS_KIND = {
    idle: 'idle',
    listening: 'listening',
    error: 'error',
    success: 'success',
    warn: 'warn'
  };

  let recognition = null;
  let listening = false;
  let currentDraft = blankDraft();
  let baseOutputHtml = '';
  let dom = null;
  let reviewBound = false;

  // --- Draft helpers ---

  function blankDraft() {
    return {
      id: `voice-${Date.now()}`,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      needsReview: true,
      transcriptSummary: '',
      fields: { revenue: '', loadedMiles: '', deadMiles: '', origin: '', destination: '', notes: '' },
      confidence: { revenue: 0, loadedMiles: 0, deadMiles: 0, origin: 0, destination: 0, notes: 0 },
      history: []
    };
  }

  function safeJSONParse(raw, fallback) {
    try { return JSON.parse(raw); } catch (_) { return fallback; }
  }

  function getDraftStore() {
    return safeJSONParse(localStorage.getItem(STORAGE_KEYS.drafts), []);
  }

  function saveDraftStore(store) {
    localStorage.setItem(STORAGE_KEYS.drafts, JSON.stringify(store.slice(-20)));
  }

  function sanitizeDraftForStorage(draft) {
    return {
      id: draft.id,
      createdAt: draft.createdAt,
      updatedAt: draft.updatedAt,
      needsReview: !!draft.needsReview,
      transcriptSummary: String(draft.transcriptSummary || '').slice(0, 240),
      fields: { ...draft.fields },
      confidence: { ...draft.confidence },
      history: (Array.isArray(draft.history) ? draft.history : []).slice(-20)
    };
  }

  function persistDraft() {
    const store = getDraftStore();
    const payload = sanitizeDraftForStorage(currentDraft);
    const idx = store.findIndex(x => x && x.id === payload.id);
    if (idx >= 0) store[idx] = payload;
    else store.push(payload);
    saveDraftStore(store);
  }

  function loadLatestDraft() {
    const store = getDraftStore();
    return store.length ? store[store.length - 1] : null;
  }

  function saveCorrection(entry) {
    const store = safeJSONParse(localStorage.getItem(STORAGE_KEYS.corrections), []);
    store.push({ ...entry, at: Date.now() });
    localStorage.setItem(STORAGE_KEYS.corrections, JSON.stringify(store.slice(-50)));
  }

  // --- String utilities ---

  function escapeHtml(str) {
    return String(str ?? '').replace(/[&<>'"]/g, m => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[m]
    ));
  }

  function normalizeText(input) {
    return String(input || '')
      .replace(/[\u2018\u2019]/g, "'")
      .replace(/[\u201C\u201D]/g, '"')
      .replace(/\s+/g, ' ')
      .trim();
  }

  function toNumber(raw) {
    const cleaned = String(raw || '').replace(/[^\d.\-]/g, '');
    const num = Number(cleaned);
    return Number.isFinite(num) ? num : null;
  }

  function toMiles(raw) {
    const num = toNumber(raw);
    if (num == null || num < 0) return null;
    return Math.round(num * 10) / 10;
  }

  function toMoney(raw) {
    const num = toNumber(raw);
    if (num == null || num <= 0) return null;
    return Math.round(num * 100) / 100;
  }

  // --- UI helpers ---

  function setStatus(message, kind = STATUS_KIND.idle) {
    if (!dom?.status) return;
    const box = dom.status;
    if (!message) {
      box.style.display = 'none';
      box.textContent = '';
      box.style.borderColor = 'var(--accent-border)';
      box.style.color = 'var(--accent)';
      return;
    }
    const palette = {
      [STATUS_KIND.idle]:      ['var(--accent-border)', 'var(--accent)'],
      [STATUS_KIND.listening]: ['var(--accent-border)', 'var(--accent)'],
      [STATUS_KIND.success]:   ['var(--good-border,rgba(52,211,153,.22))', 'var(--good,#34d399)'],
      [STATUS_KIND.warn]:      ['var(--warn-border,rgba(251,191,36,.22))', 'var(--warn,#fbbf24)'],
      [STATUS_KIND.error]:     ['var(--bad-border,rgba(248,113,113,.22))', 'var(--bad,#f87171)']
    };
    const [borderColor, textColor] = palette[kind] || palette[STATUS_KIND.idle];
    box.style.display = '';
    box.textContent = message;
    box.style.borderColor = borderColor;
    box.style.color = textColor;
  }

  function pulseVoiceButton(active) {
    if (!dom?.voiceBtn) return;
    dom.voiceBtn.style.display = '';
    dom.voiceBtn.textContent = active ? '⏹️' : '🎙️';
    dom.voiceBtn.style.color = active ? 'var(--accent)' : 'var(--text-secondary)';
    dom.voiceBtn.setAttribute('aria-pressed', active ? 'true' : 'false');
    dom.voiceBtn.title = active ? 'Stop voice input' : 'Speak load details';
  }

  function restoreOutputHtml() {
    if (dom?.output && baseOutputHtml) dom.output.innerHTML = baseOutputHtml;
  }

  function confidenceLabel(value) {
    return value >= 85 ? 'high' : value >= 55 ? 'medium' : 'low';
  }

  function confidenceColor(value) {
    return value >= 85 ? 'var(--good,#34d399)' : value >= 55 ? 'var(--warn,#fbbf24)' : 'var(--bad,#f87171)';
  }

  // --- Validation & guidance ---

  function validateDraft() {
    const issues = [];
    const revenue = toMoney(currentDraft.fields.revenue);
    const loaded  = toMiles(currentDraft.fields.loadedMiles);
    const dead    = currentDraft.fields.deadMiles === '' ? 0 : toMiles(currentDraft.fields.deadMiles);
    if (!revenue) issues.push('Revenue missing or invalid');
    if (!loaded)  issues.push('Loaded miles missing or invalid');
    if (dead == null) issues.push('Deadhead miles invalid');
    if (currentDraft.fields.origin && currentDraft.fields.origin.length < 3)      issues.push('Origin looks incomplete');
    if (currentDraft.fields.destination && currentDraft.fields.destination.length < 3) issues.push('Destination looks incomplete');
    return { ok: issues.length === 0, issues, revenue, loaded, dead };
  }

  function buildGuidance() {
    const missing = [];
    if (!currentDraft.fields.revenue)     missing.push('revenue');
    if (!currentDraft.fields.loadedMiles) missing.push('loaded miles');
    if (!currentDraft.fields.origin)      missing.push('origin');
    if (!currentDraft.fields.destination) missing.push('destination');
    const v = validateDraft();
    if (v.ok) return 'Review before apply. Nothing saves automatically.';
    if (missing.length) return `Say or type "change ${missing[0]} to …" or tap Speak Fix.`;
    return v.issues[0] || 'Review the draft before applying it.';
  }

  // --- Draft merging ---

  function mergeDraft(partial, meta = {}) {
    currentDraft.updatedAt = Date.now();
    currentDraft.needsReview = true;
    for (const key of Object.keys(currentDraft.fields)) {
      if (partial.fields && partial.fields[key] != null)
        currentDraft.fields[key] = String(partial.fields[key]).trim();
      if (partial.confidence && partial.confidence[key] != null)
        currentDraft.confidence[key] = partial.confidence[key];
    }
    if (meta.summary) currentDraft.transcriptSummary = meta.summary;
    currentDraft.history.push({
      at: Date.now(),
      action: meta.action || 'parse',
      summary: meta.summary || '',
      transcript: meta.transcript ? normalizeText(meta.transcript).slice(0, 240) : ''
    });
    currentDraft.history = currentDraft.history.slice(-20);
    persistDraft();
  }

  // --- NLP extraction ---

  function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function extractLabeledNumber(text, labels) {
    for (const label of labels) {
      const m = text.match(new RegExp(escapeRegex(label) + String.raw`\s*(?:is|to|at|of)?\s*\$?([\d,]+(?:\.\d+)?)`, 'i'));
      if (m) return m[1];
    }
    return null;
  }

  function extractFieldText(text, labels) {
    for (const label of labels) {
      const m = text.match(new RegExp(escapeRegex(label) + String.raw`\s*(?:is|to|as)?\s+([^,.;]+)`, 'i'));
      if (m) return m[1].trim();
    }
    return '';
  }

  function cleanPlace(text) {
    return String(text || '')
      .replace(/\b(city|state|zip|pickup|delivery|drop|destination|origin)\b/gi, '')
      .replace(/\s+/g, ' ')
      .replace(/^[-,:\s]+|[-,:\s]+$/g, '')
      .trim();
  }

  function extractRoute(text) {
    const patterns = [
      /(?:from)\s+(.+?)\s+(?:to)\s+(.+?)(?=$|\b(?:for|pay|rate|loaded|deadhead|note|notes|miles)\b)/i,
      /^(.+?)\s+to\s+(.+?)(?=$|\b(?:for|pay|rate|loaded|deadhead|note|notes|miles)\b)/i
    ];
    for (const pattern of patterns) {
      const m = text.match(pattern);
      if (m) return { origin: cleanPlace(m[1]), destination: cleanPlace(m[2]) };
    }
    return { origin: '', destination: '' };
  }

  function parseFixCommand(text) {
    const m = normalizeText(text).match(/^(?:fix|change|update|correct|set)\s+(.+)$/i);
    if (!m) return null;
    const src = m[1];
    const lo = src.toLowerCase();
    let fieldKey = '';
    for (const [key, aliases] of Object.entries(COMMAND_ALIASES)) {
      if (!fieldKey && aliases.some(a => lo.includes(a))) fieldKey = key;
    }
    if (!fieldKey) return null;
    let value = extractFieldText(src, COMMAND_ALIASES[fieldKey]) ||
      src.replace(/^(?:revenue|rate|pay|loaded miles|loaded|deadhead|dead head|empty|origin|pickup|destination|drop|deliver(?: to)?|to|note|notes)\s*(?:is|to|as)?\s*/i, '');
    value = value.trim();
    if (!value) return null;
    return { field: fieldKey, value };
  }

  function parseEntryCommand(text) {
    const normalized = normalizeText(text);
    const lower = normalized.toLowerCase();
    const fields = {};
    const confidence = {};

    const route = extractRoute(normalized);
    if (route.origin)      { fields.origin      = route.origin;      confidence.origin      = 72; }
    if (route.destination) { fields.destination = route.destination; confidence.destination = 72; }

    const revenueRaw = extractLabeledNumber(normalized, COMMAND_ALIASES.revenue) ||
      (normalized.match(/\$\s*([\d,]+(?:\.\d+)?)/) || [])[1];
    const revenue = toMoney(revenueRaw);
    if (revenue) { fields.revenue = String(revenue); confidence.revenue = /\$/.test(normalized) ? 92 : 78; }

    const loadedRaw = extractLabeledNumber(normalized, ['loaded miles', 'loaded', 'miles']);
    const loaded = toMiles(loadedRaw);
    if (loaded) { fields.loadedMiles = String(loaded); confidence.loadedMiles = /loaded/.test(lower) ? 90 : 63; }

    const deadRaw = extractLabeledNumber(normalized, COMMAND_ALIASES.deadMiles);
    const dead = toMiles(deadRaw);
    if (deadRaw != null && dead != null) { fields.deadMiles = String(dead); confidence.deadMiles = /dead|empty/.test(lower) ? 90 : 60; }

    const noteText = extractFieldText(normalized, COMMAND_ALIASES.notes);
    if (noteText) {
      fields.notes = noteText; confidence.notes = 88;
    } else if (!fields.origin && !fields.destination && normalized.length > 20) {
      fields.notes = normalized.slice(0, 240); confidence.notes = 48;
    }

    const originText = extractFieldText(normalized, COMMAND_ALIASES.origin);
    if (originText && !fields.origin) { fields.origin = cleanPlace(originText); confidence.origin = 82; }

    const destText = extractFieldText(normalized, ['destination', 'drop', 'deliver to']);
    if (destText && !fields.destination) { fields.destination = cleanPlace(destText); confidence.destination = 82; }

    return { fields, confidence, summary: normalized.slice(0, 240) };
  }

  // --- Review UI ---

  function renderReview() {
    if (!dom?.output) return;
    const validation = validateDraft();

    const rows = Object.keys(FIELD_LABELS).map((key) => {
      const value = currentDraft.fields[key]
        ? escapeHtml(currentDraft.fields[key])
        : '<span style="color:var(--text-tertiary)">—</span>';
      const conf = currentDraft.confidence[key] || 0;
      return `
        <div style="display:flex;justify-content:space-between;gap:10px;padding:10px 0;border-top:1px solid var(--border-subtle)">
          <div style="min-width:0;flex:1">
            <div style="font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:var(--text-tertiary);font-weight:600">${escapeHtml(FIELD_LABELS[key])}</div>
            <div style="font-size:15px;font-weight:700;line-height:1.4;word-break:break-word">${value}</div>
          </div>
          <div style="font-size:11px;font-weight:700;white-space:nowrap;color:${confidenceColor(conf)}">${escapeHtml(`${conf}% ${confidenceLabel(conf)}`)}</div>
        </div>`;
    }).join('');

    const issuesHtml = validation.issues.length
      ? `<div style="margin-top:10px;padding:10px 12px;border-radius:10px;background:var(--bad-muted,rgba(248,113,113,.08));border:1px solid var(--bad-border,rgba(248,113,113,.22));font-size:12px;color:var(--bad,#f87171)">${validation.issues.map(escapeHtml).join('<br>')}</div>`
      : `<div style="margin-top:10px;padding:10px 12px;border-radius:10px;background:var(--good-muted,rgba(52,211,153,.08));border:1px solid var(--good-border,rgba(52,211,153,.22));font-size:12px;color:var(--good,#34d399)">Structured draft ready for review. Nothing is applied until you tap Apply to Evaluator.</div>`;

    dom.output.innerHTML = `
      <div class="card" style="padding:18px 16px">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:10px">
          <div>
            <div style="font-size:18px;font-weight:800">Voice Load Review</div>
            <div style="font-size:12px;color:var(--text-secondary);margin-top:3px">Review before apply. No trip is saved here.</div>
          </div>
          <div style="font-size:11px;color:var(--text-tertiary);font-weight:700">Draft ${escapeHtml(currentDraft.id.slice(-6))}</div>
        </div>
        <div style="margin-top:12px;font-size:12px;color:var(--text-secondary)">${escapeHtml(buildGuidance())}</div>
        <div style="margin-top:8px;border-bottom:1px solid var(--border-subtle)">${rows}</div>
        ${issuesHtml}
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px">
          <button id="vApply" class="btn primary" style="min-height:48px">Apply to Evaluator</button>
          <button id="vFix" class="btn" style="min-height:48px">Speak Fix</button>
          <button id="vKeep" class="btn" style="min-height:44px">Keep Draft</button>
          <button id="vClear" class="btn danger" style="min-height:44px">Clear Draft</button>
        </div>
      </div>`;

    if (!reviewBound) {
      reviewBound = true;
      dom.output.addEventListener('click', (e) => {
        const t = e.target;
        if (!(t instanceof HTMLElement)) return;
        if (t.id === 'vApply') applyDraftToEvaluator();
        if (t.id === 'vFix')   startListening(true);
        if (t.id === 'vKeep')  { persistDraft(); setStatus('Draft kept locally for later review.', STATUS_KIND.success); }
        if (t.id === 'vClear') {
          currentDraft = blankDraft();
          localStorage.removeItem(STORAGE_KEYS.drafts);
          restoreOutputHtml();
          setStatus('Voice draft cleared.', STATUS_KIND.idle);
        }
      });
    }
  }

  function applyDraftToEvaluator() {
    const validation = validateDraft();
    if (!validation.ok) {
      setStatus(validation.issues[0] || 'Draft needs review before apply.', STATUS_KIND.error);
      renderReview();
      return;
    }
    for (const key of Object.keys(FIELD_LABELS)) {
      const el = dom.fields[key];
      if (!el) continue;
      el.value = currentDraft.fields[key] || '';
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    }
    currentDraft.needsReview = false;
    currentDraft.updatedAt = Date.now();
    persistDraft();
    setStatus('Structured draft applied to evaluator fields. Review score output below.', STATUS_KIND.success);
  }

  // --- Transcript processing ---

  function onTranscript(transcript, correctionMode = false) {
    const normalized = normalizeText(transcript);
    if (!normalized) {
      setStatus('No speech captured. Try again.', STATUS_KIND.warn);
      return;
    }

    const fix = parseFixCommand(normalized);
    if (fix) {
      mergeDraft(
        { fields: { [fix.field]: fix.value }, confidence: { [fix.field]: 94 } },
        { action: 'fix', summary: `Fixed ${FIELD_LABELS[fix.field]}`, transcript: normalized }
      );
      saveCorrection({ field: fix.field, value: fix.value, transcript: normalized });
      setStatus(`${FIELD_LABELS[fix.field]} updated. Review the draft below.`, STATUS_KIND.success);
      renderReview();
      return;
    }

    const parsed = parseEntryCommand(normalized);
    mergeDraft(parsed, {
      action: correctionMode ? 'speak-fix' : 'voice-entry',
      summary: parsed.summary,
      transcript: normalized
    });
    const v = validateDraft();
    setStatus(
      v.ok ? 'Voice draft parsed. Review before applying it to the evaluator.' : buildGuidance(),
      v.ok ? STATUS_KIND.success : STATUS_KIND.warn
    );
    renderReview();
  }

  // --- Speech Recognition ---

  function startListening(correctionMode = false) {
    if (!recognition) {
      setStatus('Voice input is not supported on this device/browser.', STATUS_KIND.error);
      return;
    }
    if (listening) {
      listening = false;
      pulseVoiceButton(false);
      try { recognition.stop(); } catch (_) {}
      setStatus('Voice input stopped.', STATUS_KIND.idle);
      return;
    }
    listening = true;
    pulseVoiceButton(true);
    setStatus(
      correctionMode
        ? 'Listening for a fix. Example: "change deadhead to 24".'
        : 'Listening for load details. Nothing will be applied automatically.',
      STATUS_KIND.listening
    );
    try {
      recognition.__correctionMode = correctionMode;
      recognition.start();
    } catch (_) {
      listening = false;
      pulseVoiceButton(false);
      setStatus('Unable to start voice input. Try again.', STATUS_KIND.error);
    }
  }

  function initRecognition() {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) return null;
    const rec = new SR();
    rec.lang = 'en-US';
    rec.interimResults = false;
    rec.maxAlternatives = 1;
    rec.continuous = false;
    rec.addEventListener('result', (e) => {
      const transcript = Array.from(e.results || [])
        .map(r => r[0]?.transcript || '')
        .join(' ')
        .trim();
      onTranscript(transcript, !!rec.__correctionMode);
    });
    rec.addEventListener('end', () => { listening = false; pulseVoiceButton(false); });
    rec.addEventListener('error', (e) => {
      listening = false;
      pulseVoiceButton(false);
      const msg = e.error === 'not-allowed' ? 'Microphone access was denied.'
        : e.error === 'no-speech' ? 'No speech detected. Try again.'
        : 'Voice input error. Try again.';
      setStatus(msg, STATUS_KIND.error);
    });
    return rec;
  }

  // --- Init ---

  function hydrateFromStorage() {
    const latest = loadLatestDraft();
    if (!latest) { restoreOutputHtml(); return; }
    currentDraft = {
      ...blankDraft(), ...latest,
      fields:     { ...blankDraft().fields,     ...(latest.fields     || {}) },
      confidence: { ...blankDraft().confidence, ...(latest.confidence || {}) },
      history:    Array.isArray(latest.history) ? latest.history.slice(-20) : []
    };
    renderReview();
    setStatus('Loaded local voice draft. Review it before applying.', STATUS_KIND.idle);
  }

  function init() {
    if (REQUIRED_IDS.some(id => !document.getElementById(id))) return;

    dom = {
      voiceBtn: document.getElementById('mwVoiceBtn'),
      status:   document.getElementById('mwVoiceStatus'),
      output:   document.getElementById('mwEvalOutput'),
      fields: {
        revenue:     document.getElementById('mwRevenue'),
        loadedMiles: document.getElementById('mwLoadedMi'),
        deadMiles:   document.getElementById('mwDeadMi'),
        origin:      document.getElementById('mwOrigin'),
        destination: document.getElementById('mwDest'),
        notes:       document.getElementById('mwLoadNotes')
      }
    };

    if (!baseOutputHtml) baseOutputHtml = dom.output.innerHTML;

    recognition = initRecognition();
    dom.voiceBtn.style.display = '';
    dom.voiceBtn.addEventListener('click', () => startListening(false));
    pulseVoiceButton(false);
    hydrateFromStorage();

    if (!recognition) {
      dom.voiceBtn.style.display = 'none';
      if (loadLatestDraft()) setStatus('Voice input is unavailable here. You can still review a saved voice draft.', STATUS_KIND.warn);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
