/* FreightLogic v23.1.1 — Voice Load Module */
(() => {
  'use strict';

  const REQUIRED_IDS = [
    'mwVoiceBtn','mwVoiceStatus','mwRevenue','mwLoadedMi','mwDeadMi',
    'mwOrigin','mwDest','mwLoadNotes','mwEvalOutput'
  ];

  const STORAGE_KEYS = {
    drafts: 'voiceDrafts',
    corrections: 'voiceCorrections'
  };

  const FIELD_META = {
    revenue: { label: 'Revenue', el: 'mwRevenue', type: 'money', required: true },
    loadedMiles: { label: 'Loaded miles', el: 'mwLoadedMi', type: 'miles', required: true },
    deadMiles: { label: 'Deadhead miles', el: 'mwDeadMi', type: 'miles', required: false },
    origin: { label: 'Origin', el: 'mwOrigin', type: 'text', required: false },
    destination: { label: 'Destination', el: 'mwDest', type: 'text', required: false },
    notes: { label: 'Load notes', el: 'mwLoadNotes', type: 'text', required: false }
  };

  const COMMAND_ALIASES = {
    revenue: ['revenue', 'rate', 'pay', 'price', 'money'],
    loadedMiles: ['loaded', 'loaded miles', 'miles'],
    deadMiles: ['deadhead', 'dead head', 'empty', 'dead miles'],
    origin: ['origin', 'pickup', 'from'],
    destination: ['destination', 'drop', 'deliver', 'to'],
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
  let lastTranscript = '';
  let dom = null;
  let reviewBound = false;

  function blankDraft() {
    return {
      id: `voice-${Date.now()}`,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      source: 'voice',
      fields: {
        revenue: '',
        loadedMiles: '',
        deadMiles: '',
        origin: '',
        destination: '',
        notes: ''
      },
      confidence: {
        revenue: 0,
        loadedMiles: 0,
        deadMiles: 0,
        origin: 0,
        destination: 0,
        notes: 0
      },
      needsReview: true,
      transcriptSummary: '',
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

  function persistDraft() {
    const store = getDraftStore();
    const idx = store.findIndex(x => x.id === currentDraft.id);
    const payload = sanitizeDraftForStorage(currentDraft);
    if (idx >= 0) store[idx] = payload;
    else store.push(payload);
    saveDraftStore(store);
  }

  function sanitizeDraftForStorage(draft) {
    return {
      id: draft.id,
      createdAt: draft.createdAt,
      updatedAt: draft.updatedAt,
      source: draft.source,
      fields: { ...draft.fields },
      confidence: { ...draft.confidence },
      needsReview: !!draft.needsReview,
      transcriptSummary: draft.transcriptSummary || '',
      history: Array.isArray(draft.history) ? draft.history.slice(-20) : []
    };
  }

  function loadLatestDraft() {
    const store = getDraftStore();
    if (!store.length) return null;
    return store[store.length - 1];
  }

  function clearDrafts() {
    localStorage.removeItem(STORAGE_KEYS.drafts);
  }

  function getCorrectionStore() {
    return safeJSONParse(localStorage.getItem(STORAGE_KEYS.corrections), []);
  }

  function saveCorrection(entry) {
    const store = getCorrectionStore();
    store.push({ ...entry, at: Date.now() });
    localStorage.setItem(STORAGE_KEYS.corrections, JSON.stringify(store.slice(-50)));
  }

  function escapeHtml(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
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

  function setStatus(message, kind = STATUS_KIND.idle) {
    if (!dom) return;
    const box = dom.status;
    if (!box) return;
    if (!message) {
      box.style.display = 'none';
      box.textContent = '';
      box.style.borderColor = 'var(--accent-border)';
      box.style.color = 'var(--accent)';
      return;
    }
    box.style.display = '';
    box.textContent = message;
    const palette = {
      [STATUS_KIND.idle]: ['var(--accent-border)', 'var(--accent)'],
      [STATUS_KIND.listening]: ['var(--accent-border)', 'var(--accent)'],
      [STATUS_KIND.error]: ['var(--bad-border, rgba(248,113,113,0.22))', 'var(--bad, #f87171)'],
      [STATUS_KIND.success]: ['var(--good-border, rgba(52,211,153,0.22))', 'var(--good, #34d399)'],
      [STATUS_KIND.warn]: ['var(--warn-border, rgba(251,191,36,0.22))', 'var(--warn, #fbbf24)']
    };
    const [borderColor, textColor] = palette[kind] || palette[STATUS_KIND.idle];
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

  function confidenceLabel(value) {
    if (value >= 85) return 'high';
    if (value >= 55) return 'medium';
    return 'low';
  }

  function confidenceColor(value) {
    if (value >= 85) return 'var(--good, #34d399)';
    if (value >= 55) return 'var(--warn, #fbbf24)';
    return 'var(--bad, #f87171)';
  }

  function validateDraft(draft) {
    const issues = [];
    const revenue = toMoney(draft.fields.revenue);
    const loaded = toMiles(draft.fields.loadedMiles);
    const dead = draft.fields.deadMiles === '' ? 0 : toMiles(draft.fields.deadMiles);

    if (!revenue) issues.push('Revenue missing or invalid');
    if (!loaded) issues.push('Loaded miles missing or invalid');
    if (dead == null) issues.push('Deadhead miles invalid');
    if (draft.fields.origin && draft.fields.origin.length < 3) issues.push('Origin looks incomplete');
    if (draft.fields.destination && draft.fields.destination.length < 3) issues.push('Destination looks incomplete');

    return {
      valid: issues.length === 0,
      issues,
      revenue,
      loaded,
      dead
    };
  }

  function buildGuidance(draft) {
    const validation = validateDraft(draft);
    const missing = [];
    if (!draft.fields.revenue) missing.push('revenue');
    if (!draft.fields.loadedMiles) missing.push('loaded miles');
    if (!draft.fields.origin) missing.push('origin');
    if (!draft.fields.destination) missing.push('destination');

    if (!missing.length && validation.valid) {
      return 'Review the fields below, then apply them to the evaluator.';
    }

    if (missing.length) {
      return `Say or type a fix like “change ${missing[0]} to …” or tap Speak Fix.`;
    }

    return validation.issues[0] || 'Review the draft before applying it.';
  }

  function mergeDraft(partial, meta = {}) {
    currentDraft.updatedAt = Date.now();
    currentDraft.needsReview = true;

    Object.keys(currentDraft.fields).forEach((key) => {
      if (partial.fields && partial.fields[key] !== undefined && partial.fields[key] !== null) {
        currentDraft.fields[key] = String(partial.fields[key]).trim();
      }
      if (partial.confidence && partial.confidence[key] !== undefined && partial.confidence[key] !== null) {
        currentDraft.confidence[key] = partial.confidence[key];
      }
    });

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

  function extractLabeledNumber(text, labels) {
    for (const label of labels) {
      const pattern = new RegExp(`${label}\\s*(?:is|to|at|of)?\\s*\$?([\d,]+(?:\.\d+)?)`, 'i');
      const match = text.match(pattern);
      if (match) return match[1];
    }
    return null;
  }

  function extractFieldText(text, labels) {
    for (const label of labels) {
      const pattern = new RegExp(`${label}\\s*(?:is|to|as)?\\s+([^,.;]+)`, 'i');
      const match = text.match(pattern);
      if (match) return match[1].trim();
    }
    return null;
  }

  function cleanPlace(text) {
    return String(text || '')
      .replace(/\b(city|state|zip|pickup|delivery|drop|destination|origin)\b/gi, '')
      .replace(/\s+/g, ' ')
      .replace(/^[-,:\s]+|[-,:\s]+$/g, '')
      .trim();
  }

  function extractRoute(text) {
    const routePatterns = [
      /(?:from)\s+(.+?)\s+(?:to)\s+(.+?)(?=$|\b(?:for|pay|rate|loaded|deadhead|note|notes|miles)\b)/i,
      /^(.+?)\s+to\s+(.+?)(?=$|\b(?:for|pay|rate|loaded|deadhead|note|notes|miles)\b)/i
    ];

    for (const pattern of routePatterns) {
      const match = text.match(pattern);
      if (match) {
        return {
          origin: cleanPlace(match[1]),
          destination: cleanPlace(match[2])
        };
      }
    }
    return { origin: '', destination: '' };
  }

  function parseFixCommand(text) {
    const normalized = normalizeText(text.toLowerCase());
    const commandMatch = normalized.match(/^(?:fix|change|update|correct|set)\s+(.+)$/i);
    if (!commandMatch) return null;

    let fieldKey = null;
    Object.entries(COMMAND_ALIASES).forEach(([key, aliases]) => {
      if (!fieldKey && aliases.some(alias => commandMatch[1].includes(alias))) {
        fieldKey = key;
      }
    });
    if (!fieldKey) return null;

    const rawValue = extractFieldText(commandMatch[1], COMMAND_ALIASES[fieldKey]) ||
      commandMatch[1].replace(/^(?:revenue|rate|pay|loaded miles|loaded|deadhead|dead head|empty|origin|pickup|destination|drop|deliver|to|note|notes)\s*(?:is|to|as)?\s*/i, '');

    return {
      field: fieldKey,
      value: rawValue.trim()
    };
  }

  function parseEntryCommand(text) {
    const normalized = normalizeText(text);
    const lower = normalized.toLowerCase();
    const fields = {};
    const confidence = {};

    const route = extractRoute(normalized);
    if (route.origin) {
      fields.origin = route.origin;
      confidence.origin = 72;
    }
    if (route.destination) {
      fields.destination = route.destination;
      confidence.destination = 72;
    }

    const revenueRaw = extractLabeledNumber(normalized, COMMAND_ALIASES.revenue) ||
      (normalized.match(/\$\s*([\d,]+(?:\.\d+)?)/) || [])[1] ||
      (lower.match(/(?:pay|rate|revenue)\s*(?:is|to|at)?\s*([\d,]+(?:\.\d+)?)/) || [])[1];
    const revenue = toMoney(revenueRaw);
    if (revenue) {
      fields.revenue = String(revenue);
      confidence.revenue = /\$/.test(normalized) ? 92 : 78;
    }

    const loadedRaw = extractLabeledNumber(normalized, ['loaded miles', 'loaded', 'miles']);
    const loaded = toMiles(loadedRaw);
    if (loaded) {
      fields.loadedMiles = String(loaded);
      confidence.loadedMiles = /loaded/.test(lower) ? 90 : 63;
    }

    const deadRaw = extractLabeledNumber(normalized, COMMAND_ALIASES.deadMiles);
    const dead = toMiles(deadRaw);
    if (dead !== null && dead !== undefined && dead !== false) {
      if (deadRaw !== null) {
        fields.deadMiles = String(dead);
        confidence.deadMiles = /dead|empty/.test(lower) ? 90 : 60;
      }
    }

    const noteText = extractFieldText(normalized, COMMAND_ALIASES.notes);
    if (noteText) {
      fields.notes = noteText;
      confidence.notes = 88;
    } else if (!fields.origin && !fields.destination && normalized.length > 20) {
      fields.notes = normalized.slice(0, 240);
      confidence.notes = 48;
    }

    const originText = extractFieldText(normalized, COMMAND_ALIASES.origin);
    if (originText && !fields.origin) {
      fields.origin = cleanPlace(originText);
      confidence.origin = 82;
    }

    const destText = extractFieldText(normalized, ['destination', 'drop', 'deliver to']);
    if (destText && !fields.destination) {
      fields.destination = cleanPlace(destText);
      confidence.destination = 82;
    }

    return {
      fields,
      confidence,
      summary: normalized.slice(0, 240)
    };
  }

  function renderReview() {
    if (!dom?.output) return;

    const validation = validateDraft(currentDraft);
    const guidance = buildGuidance(currentDraft);

    const rows = Object.keys(FIELD_META).map((key) => {
      const meta = FIELD_META[key];
      const value = currentDraft.fields[key] ? escapeHtml(currentDraft.fields[key]) : '<span style="color:var(--text-tertiary)">—</span>';
      const conf = currentDraft.confidence[key] || 0;
      const confText = `${conf}% ${confidenceLabel(conf)}`;
      return `
        <div style="display:flex;justify-content:space-between;gap:10px;padding:10px 0;border-top:1px solid var(--border-subtle)">
          <div style="min-width:0;flex:1">
            <div style="font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:var(--text-tertiary);font-weight:600">${escapeHtml(meta.label)}</div>
            <div style="font-size:15px;font-weight:700;line-height:1.4;word-break:break-word">${value}</div>
          </div>
          <div style="font-size:11px;font-weight:700;white-space:nowrap;color:${confidenceColor(conf)}">${escapeHtml(confText)}</div>
        </div>`;
    }).join('');

    const issuesHtml = validation.issues.length
      ? `<div style="margin-top:10px;padding:10px 12px;border-radius:10px;background:var(--bad-muted, rgba(248,113,113,0.08));border:1px solid var(--bad-border, rgba(248,113,113,0.22));font-size:12px;color:var(--bad, #f87171)">${validation.issues.map(escapeHtml).join('<br>')}</div>`
      : `<div style="margin-top:10px;padding:10px 12px;border-radius:10px;background:var(--good-muted, rgba(52,211,153,0.08));border:1px solid var(--good-border, rgba(52,211,153,0.22));font-size:12px;color:var(--good, #34d399)">Structured draft ready for review. Nothing is applied until you tap Apply to Evaluator.</div>`;

    dom.output.innerHTML = `
      <div class="card" style="padding:18px 16px">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:10px">
          <div>
            <div style="font-size:18px;font-weight:800">Voice Load Review</div>
            <div style="font-size:12px;color:var(--text-secondary);margin-top:3px">Review before apply. No trip is saved here.</div>
          </div>
          <div style="font-size:11px;color:var(--text-tertiary);font-weight:700">Draft ${escapeHtml(currentDraft.id.slice(-6))}</div>
        </div>
        <div style="margin-top:12px;font-size:12px;color:var(--text-secondary)">${escapeHtml(guidance)}</div>
        <div style="margin-top:8px;border-bottom:1px solid var(--border-subtle)">${rows}</div>
        ${issuesHtml}
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px">
          <button id="voiceApplyBtn" class="btn primary" style="min-height:48px">Apply to Evaluator</button>
          <button id="voiceSpeakFixBtn" class="btn" style="min-height:48px">Speak Fix</button>
          <button id="voiceKeepDraftBtn" class="btn" style="min-height:44px">Keep Draft</button>
          <button id="voiceClearDraftBtn" class="btn danger" style="min-height:44px">Clear Draft</button>
        </div>
      </div>`;

    if (!reviewBound) {
      reviewBound = true;
      dom.output.addEventListener('click', (event) => {
        const target = event.target;
        if (!(target instanceof HTMLElement)) return;

        if (target.id === 'voiceApplyBtn') {
          applyDraftToEvaluator();
        }
        if (target.id === 'voiceSpeakFixBtn') {
          startListening(true);
        }
        if (target.id === 'voiceKeepDraftBtn') {
          persistDraft();
          setStatus('Draft kept locally for later review.', STATUS_KIND.success);
        }
        if (target.id === 'voiceClearDraftBtn') {
          clearCurrentDraft();
        }
      });
    }
  }

  function applyDraftToEvaluator() {
    const validation = validateDraft(currentDraft);
    if (!validation.valid) {
      setStatus(validation.issues[0] || 'Draft needs review before apply.', STATUS_KIND.error);
      renderReview();
      return;
    }

    Object.entries(FIELD_META).forEach(([key, meta]) => {
      const el = dom.fields[key];
      if (!el) return;
      el.value = currentDraft.fields[key] || '';
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    });

    currentDraft.needsReview = false;
    currentDraft.updatedAt = Date.now();
    persistDraft();
    setStatus('Structured draft applied to evaluator fields. Review score output below.', STATUS_KIND.success);

    setTimeout(() => {
      dom.output.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 80);
  }

  function clearCurrentDraft() {
    currentDraft = blankDraft();
    clearDrafts();
    renderReview();
    setStatus('Voice draft cleared.', STATUS_KIND.idle);
  }

  function onTranscript(transcript, correctionMode = false) {
    const normalized = normalizeText(transcript);
    lastTranscript = normalized;

    if (!normalized) {
      setStatus('No speech captured. Try again.', STATUS_KIND.warn);
      return;
    }

    const fix = parseFixCommand(normalized);
    if (fix) {
      mergeDraft({
        fields: { [fix.field]: fix.value },
        confidence: { [fix.field]: 94 }
      }, {
        action: 'fix',
        summary: `Fixed ${FIELD_META[fix.field].label}`,
        transcript: normalized
      });
      saveCorrection({ field: fix.field, value: fix.value, transcript: normalized });
      setStatus(`${FIELD_META[fix.field].label} updated. Review the draft below.`, STATUS_KIND.success);
      renderReview();
      return;
    }

    const parsed = parseEntryCommand(normalized);
    mergeDraft(parsed, {
      action: correctionMode ? 'speak-fix' : 'voice-entry',
      summary: parsed.summary,
      transcript: normalized
    });

    const validation = validateDraft(currentDraft);
    if (validation.valid) {
      setStatus('Voice draft parsed. Review before applying it to the evaluator.', STATUS_KIND.success);
    } else {
      setStatus(buildGuidance(currentDraft), STATUS_KIND.warn);
    }
    renderReview();
  }

  function startListening(correctionMode = false) {
    if (!recognition) {
      setStatus('Voice input is not supported on this device/browser.', STATUS_KIND.error);
      return;
    }
    if (listening) {
      stopListening();
      return;
    }
    listening = true;
    pulseVoiceButton(true);
    setStatus(correctionMode
      ? 'Listening for a fix. Example: “change deadhead to 24”.'
      : 'Listening for load details. Nothing will be applied automatically.', STATUS_KIND.listening);

    try {
      recognition.__correctionMode = correctionMode;
      recognition.start();
    } catch (err) {
      listening = false;
      pulseVoiceButton(false);
      setStatus('Unable to start voice input. Try again.', STATUS_KIND.error);
    }
  }

  function stopListening() {
    if (!recognition || !listening) return;
    listening = false;
    pulseVoiceButton(false);
    try { recognition.stop(); } catch (_) {}
    setStatus('Voice input stopped.', STATUS_KIND.idle);
  }

  function hydrateFromStorage() {
    const latest = loadLatestDraft();
    if (!latest) {
      renderReview();
      return;
    }
    currentDraft = {
      ...blankDraft(),
      ...latest,
      fields: { ...blankDraft().fields, ...(latest.fields || {}) },
      confidence: { ...blankDraft().confidence, ...(latest.confidence || {}) },
      history: Array.isArray(latest.history) ? latest.history : []
    };
    renderReview();
    setStatus('Loaded local voice draft. Review it before applying.', STATUS_KIND.idle);
  }

  function initRecognition() {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) return null;

    const rec = new SR();
    rec.lang = 'en-US';
    rec.interimResults = false;
    rec.maxAlternatives = 1;
    rec.continuous = false;

    rec.addEventListener('result', (event) => {
      const transcript = Array.from(event.results || [])
        .map(result => result[0] && result[0].transcript ? result[0].transcript : '')
        .join(' ')
        .trim();
      onTranscript(transcript, !!rec.__correctionMode);
    });

    rec.addEventListener('end', () => {
      listening = false;
      pulseVoiceButton(false);
    });

    rec.addEventListener('error', (event) => {
      listening = false;
      pulseVoiceButton(false);
      const msg = event.error === 'not-allowed'
        ? 'Microphone access was denied.'
        : event.error === 'no-speech'
          ? 'No speech detected. Try again.'
          : 'Voice input error. Try again.';
      setStatus(msg, STATUS_KIND.error);
    });

    return rec;
  }

  function bindUI() {
    dom.voiceBtn.style.display = '';
    dom.voiceBtn.addEventListener('click', () => startListening(false));
    pulseVoiceButton(false);
  }

  function init() {
    const missing = REQUIRED_IDS.filter(id => !document.getElementById(id));
    if (missing.length) return;

    dom = {
      voiceBtn: document.getElementById('mwVoiceBtn'),
      status: document.getElementById('mwVoiceStatus'),
      output: document.getElementById('mwEvalOutput'),
      fields: {
        revenue: document.getElementById('mwRevenue'),
        loadedMiles: document.getElementById('mwLoadedMi'),
        deadMiles: document.getElementById('mwDeadMi'),
        origin: document.getElementById('mwOrigin'),
        destination: document.getElementById('mwDest'),
        notes: document.getElementById('mwLoadNotes')
      }
    };

    recognition = initRecognition();
    bindUI();
    hydrateFromStorage();

    if (!recognition) {
      dom.voiceBtn.style.display = 'none';
      setStatus('Voice input is unavailable in this browser. You can still review saved local drafts.', STATUS_KIND.warn);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
