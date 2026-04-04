// FreightLogic Cloud Backup Worker v7 - Multi-User + AI Evaluate + AI Extract + Delta Sync
// KV binding: BACKUPS
// Secrets: ADMIN_TOKEN, OPENAI_API_KEY
// Vars: ALLOWED_ORIGIN, OPENAI_MODEL (optional, default: gpt-4.1-mini)

export default {
  async fetch(request, env) {
    const allowedOrigin = env.ALLOWED_ORIGIN || '*';
    const cors = {
      'Access-Control-Allow-Origin': allowedOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Device-Id, X-Backup-Token, X-Admin-Token',
      'Content-Type': 'application/json'
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // ADMIN ENDPOINTS
      if (path.startsWith('/admin/')) {
        const adminToken = request.headers.get('X-Admin-Token');
        if (!adminToken || adminToken !== env.ADMIN_TOKEN) {
          return json({ ok: false, error: 'Unauthorized' }, 401, cors);
        }

        if (request.method === 'POST' && path === '/admin/users') {
          const body = await request.json().catch(() => ({}));
          const name = (body.name || 'Driver').slice(0, 50);
          const userId = 'u_' + crypto.randomUUID().slice(0, 12);
          const token = 'flk_' + crypto.randomUUID().replace(/-/g, '');
          const rec = { userId, name, token, createdAt: new Date().toISOString(), active: true };
          await env.BACKUPS.put('token:' + token, JSON.stringify(rec));
          await env.BACKUPS.put('user:' + userId, JSON.stringify(rec));
          return json({ ok: true, userId, name, token }, 201, cors);
        }

        if (request.method === 'GET' && path === '/admin/users') {
          const list = await env.BACKUPS.list({ prefix: 'user:' });
          const users = [];
          for (const k of list.keys) {
            const val = await env.BACKUPS.get(k.name);
            if (val) { try { users.push(JSON.parse(val)); } catch {} }
          }
          return json({ ok: true, users }, 200, cors);
        }

        if (request.method === 'DELETE' && path.startsWith('/admin/users/')) {
          const delId = path.split('/admin/users/')[1];
          if (!delId || !/^u_[a-f0-9-]{8,36}$/i.test(delId)) {
            return json({ ok: false, error: 'Invalid user ID format' }, 400, cors);
          }
          const userRec = await env.BACKUPS.get('user:' + delId);
          if (!userRec) return json({ ok: false, error: 'Not found' }, 404, cors);
          let parsed;
          try { parsed = JSON.parse(userRec); } catch { return json({ ok: false, error: 'Corrupted record' }, 500, cors); }
          parsed.active = false;
          await env.BACKUPS.put('user:' + delId, JSON.stringify(parsed));
          if (parsed.token) await env.BACKUPS.delete('token:' + parsed.token);
          return json({ ok: true, revoked: delId }, 200, cors);
        }

        return json({ ok: false, error: 'Not found' }, 404, cors);
      }

      // DRIVER ENDPOINTS — require token
      const driverToken = request.headers.get('X-Backup-Token');
      if (!driverToken) {
        return json({ ok: false, error: 'Missing token' }, 401, cors);
      }

      const tokenRaw = await env.BACKUPS.get('token:' + driverToken);
      if (!tokenRaw) {
        return json({ ok: false, error: 'Invalid token' }, 403, cors);
      }

      let tokenData;
      try { tokenData = JSON.parse(tokenRaw); } catch { return json({ ok: false, error: 'Invalid token' }, 403, cors); }
      if (!tokenData.active) {
        return json({ ok: false, error: 'Token revoked' }, 403, cors);
      }

      const driverUserId = tokenData.userId;
      const deviceId = (request.headers.get('X-Device-Id') || 'default').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64) || 'default';

      // POST /evaluate — AI load analysis via OpenAI
      if (request.method === 'POST' && path === '/evaluate') {
        // Rate limit: 20 requests per minute per user
        const rateLimited = await checkRateLimit(env, driverUserId, 20, 'eval');
        if (rateLimited) {
          return json({ ok: false, error: 'Rate limit exceeded. Please wait before evaluating again.' }, 429, cors);
        }

        if (!env.OPENAI_API_KEY) {
          return json({ ok: false, error: 'AI evaluation not configured on server.' }, 500, cors);
        }

        const payload = await request.json().catch(() => null);
        if (!payload) {
          return json({ ok: false, error: 'Invalid JSON payload' }, 400, cors);
        }

        const model = env.OPENAI_MODEL || 'gpt-4.1-mini';
        const prompt = buildEvalPrompt(payload);

        const aiRes = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + env.OPENAI_API_KEY,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            model,
            temperature: 0.3,
            max_tokens: 600,
            response_format: { type: 'json_object' },
            messages: [
              { role: 'system', content: SYSTEM_PROMPT },
              { role: 'user', content: prompt }
            ]
          })
        });

        if (!aiRes.ok) {
          const errText = await aiRes.text().catch(() => '');
          console.error('[FL] OpenAI error:', aiRes.status, errText);
          return json({ ok: false, error: 'AI service error. Local evaluation is still valid.' }, 502, cors);
        }

        const aiJson = await aiRes.json();
        let parsed = null;
        try {
          parsed = JSON.parse(aiJson.choices[0].message.content);
        } catch {
          return json({ ok: false, error: 'AI response parse error. Local evaluation is still valid.' }, 502, cors);
        }

        return json({
          ok: true,
          ai: {
            summary:       String(parsed.summary       || '').slice(0, 500),
            verdict:       validateVerdict(parsed.verdict),
            grade:         validateGrade(parsed.grade),
            trueRpmBand:   String(parsed.trueRpmBand   || '').slice(0, 80),
            bidAdvice:     String(parsed.bidAdvice      || '').slice(0, 300),
            primaryReason: String(parsed.primaryReason || '').slice(0, 200),
            risks:         sanitizeList(parsed.risks),
            positives:     sanitizeList(parsed.positives),
            nextMove:      String(parsed.nextMove       || '').slice(0, 200)
          },
          model,
          user: tokenData.name
        }, 200, cors);
      }

      // POST /extract — AI field extraction from raw load text
      if (request.method === 'POST' && path === '/extract') {
        // Rate limit: 10 requests per minute per user
        const rateLimited = await checkRateLimit(env, driverUserId, 10, 'extract');
        if (rateLimited) {
          return json({ ok: false, error: 'Rate limit exceeded. Please wait before extracting again.' }, 429, cors);
        }

        if (!env.OPENAI_API_KEY) {
          return json({ ok: false, error: 'AI extraction not configured on server.' }, 500, cors);
        }

        const payload = await request.json().catch(() => null);
        if (!payload || !payload.text) {
          return json({ ok: false, error: 'Missing required field: text' }, 400, cors);
        }

        const rawText = String(payload.text).slice(0, 4000);
        const model = env.OPENAI_MODEL || 'gpt-4.1-mini';

        const aiRes = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + env.OPENAI_API_KEY,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            model,
            temperature: 0.1,
            max_tokens: 400,
            response_format: { type: 'json_object' },
            messages: [
              { role: 'system', content: EXTRACT_SYSTEM_PROMPT },
              { role: 'user', content: 'Extract structured fields from this load text:\n\n' + rawText }
            ]
          })
        });

        if (!aiRes.ok) {
          const errText = await aiRes.text().catch(() => '');
          console.error('[FL] OpenAI extract error:', aiRes.status, errText);
          return json({ ok: false, error: 'AI service error.' }, 502, cors);
        }

        const aiJson = await aiRes.json();
        let parsed = null;
        try {
          parsed = JSON.parse(aiJson.choices[0].message.content);
        } catch {
          return json({ ok: false, error: 'AI response parse error.' }, 502, cors);
        }

        return json({
          ok: true,
          fields: {
            orderNo:      String(parsed.orderNo      || '').slice(0, 40),
            customer:     String(parsed.customer     || '').slice(0, 80),
            broker:       String(parsed.broker       || '').slice(0, 80),
            origin:       String(parsed.origin       || '').slice(0, 100),
            destination:  String(parsed.destination  || '').slice(0, 100),
            pay:          finitePositive(parsed.pay),
            loadedMiles:  intPositive(parsed.loadedMiles),
            deadheadMiles:intPositive(parsed.deadheadMiles),
            pickupDate:   safeDate(parsed.pickupDate),
            deliveryDate: safeDate(parsed.deliveryDate),
            weight:       intPositive(parsed.weight),
            commodity:    String(parsed.commodity    || '').slice(0, 80),
            notes:        String(parsed.notes        || '').slice(0, 300),
          },
          model,
          user: tokenData.name
        }, 200, cors);
      }

      // POST /backup — save encrypted data
      if (request.method === 'POST' && path === '/backup') {
        const payload = await request.text();
        if (!payload || payload.length < 10) {
          return json({ ok: false, error: 'Empty payload' }, 400, cors);
        }
        if (payload.length > 5 * 1024 * 1024) {
          return json({ ok: false, error: 'Payload too large (5MB max)' }, 413, cors);
        }
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        const key = 'user:' + driverUserId + ':device:' + deviceId + ':backup:' + ts;
        await env.BACKUPS.put(key, payload);

        // Rotate — keep last 3
        const bp = 'user:' + driverUserId + ':device:' + deviceId + ':backup:';
        const bl = await env.BACKUPS.list({ prefix: bp });
        if (bl.keys.length > 3) {
          const sorted = bl.keys.slice().sort((a, b) => a.name.localeCompare(b.name));
          const toDelete = sorted.slice(0, sorted.length - 3);
          for (const k of toDelete) await env.BACKUPS.delete(k.name);
        }

        return json({ ok: true, key, size: payload.length }, 200, cors);
      }

      // POST /backup/delta — v21 T2B: store delta (partial sync payload)
      if (request.method === 'POST' && path === '/backup/delta') {
        const payload = await request.text();
        if (!payload || payload.length < 10) {
          return json({ ok: false, error: 'Empty payload' }, 400, cors);
        }
        if (payload.length > 2 * 1024 * 1024) {
          return json({ ok: false, error: 'Delta too large (2MB max)' }, 413, cors);
        }
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        const key = 'user:' + driverUserId + ':device:' + deviceId + ':delta:' + ts;
        await env.BACKUPS.put(key, payload, { expirationTtl: 7 * 24 * 3600 }); // expire deltas after 7 days
        // Limit deltas — keep last 20
        const dp = 'user:' + driverUserId + ':device:' + deviceId + ':delta:';
        const dl = await env.BACKUPS.list({ prefix: dp });
        if (dl.keys.length > 20) {
          const dsorted = dl.keys.slice().sort((a, b) => a.name.localeCompare(b.name));
          const toDelete = dsorted.slice(0, dsorted.length - 20);
          for (const k of toDelete) await env.BACKUPS.delete(k.name);
        }
        return json({ ok: true, key, size: payload.length, type: 'delta' }, 200, cors);
      }

      // GET /backup — retrieve latest
      if (request.method === 'GET' && path === '/backup') {
        const gp = 'user:' + driverUserId + ':device:' + deviceId + ':backup:';
        const gl = await env.BACKUPS.list({ prefix: gp });
        if (gl.keys.length === 0) {
          return json({ ok: false, error: 'No backup found' }, 404, cors);
        }
        const gsorted = gl.keys.slice().sort((a, b) => a.name.localeCompare(b.name));
        const data = await env.BACKUPS.get(gsorted[gsorted.length - 1].name);
        return new Response(data, { status: 200, headers: cors });
      }

      // GET /list — list backups for this user+device
      if (request.method === 'GET' && path === '/list') {
        const lp = 'user:' + driverUserId + ':device:' + deviceId + ':';
        const ll = await env.BACKUPS.list({ prefix: lp });
        return json({ ok: true, backups: ll.keys.map(k => k.name), count: ll.keys.length }, 200, cors);
      }

      // GET /status — backup presence check
      if (request.method === 'GET' && path === '/status') {
        const sp = 'user:' + driverUserId + ':device:' + deviceId + ':';
        const sl = await env.BACKUPS.list({ prefix: sp });
        return json({ ok: true, hasBackup: sl.keys.length > 0, count: sl.keys.length, user: tokenData.name }, 200, cors);
      }

      // DELETE /backup — remove all backups for this user+device
      if (request.method === 'DELETE' && path === '/backup') {
        const dp = 'user:' + driverUserId + ':device:' + deviceId + ':backup:';
        const dl = await env.BACKUPS.list({ prefix: dp });
        for (const k of dl.keys) await env.BACKUPS.delete(k.name);
        return json({ ok: true, deleted: dl.keys.length }, 200, cors);
      }

      return json({ ok: false, error: 'Not found' }, 404, cors);
    } catch (err) {
      console.error('[FL] Worker error:', err);
      return json({ ok: false, error: 'Server error' }, 500, cors);
    }
  }
};

// ─── Rate limiter (sliding minute window via KV) ──────────────────────────────

async function checkRateLimit(env, userId, limit, ns = 'eval') {
  const minute = Math.floor(Date.now() / 60000);
  const key = 'rl:' + ns + ':' + userId + ':' + minute;
  const raw = await env.BACKUPS.get(key);
  const count = raw ? parseInt(raw, 10) : 0;
  if (count >= limit) return true;
  // TTL 120s so KV cleans itself up after two minutes
  await env.BACKUPS.put(key, String(count + 1), { expirationTtl: 120 });
  return false;
}

// ─── Prompt builder ───────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a Midwest Stack freight decision advisor for a cargo van expedited carrier.
Your job is to evaluate a single load using the Midwest Stack operating framework.

Core principles:
- True RPM (revenue per loaded mile) is the primary metric — always calculate it.
- Deadhead miles dilute true RPM and must be factored into every decision.
- Density and reload potential matter — empty return lanes are traps.
- Strategic under-floor loads are allowed only when explicitly justified.
- Preserve operator discipline. Do not validate emotional moves.
- Be direct and specific. No generic freight advice.

You must respond with a single JSON object matching this exact structure:
{
  "summary": "2-3 sentence analysis of this load",
  "verdict": "ACCEPT | NEGOTIATE | PASS | STRATEGIC_ONLY",
  "grade": "A | B | C | D | E",
  "trueRpmBand": "$X.XX – $X.XX / loaded mile",
  "bidAdvice": "specific bid or negotiation guidance",
  "primaryReason": "the single most important factor driving this verdict",
  "risks": ["risk 1", "risk 2"],
  "positives": ["positive 1", "positive 2"],
  "nextMove": "what the operator should do right now"
}`;

function buildEvalPrompt(p) {
  const lines = [
    'Evaluate this load:',
    '',
    'Route: ' + (p.origin || 'unknown') + ' → ' + (p.destination || 'unknown'),
    'Loaded miles: ' + (p.loadedMiles || 0),
    'Deadhead miles: ' + (p.deadheadMiles || 0),
    'Revenue: $' + (p.revenue || 0),
    'True RPM (pre-calc): $' + (p.trueRpm || 'not provided'),
    'Weekly gross context: $' + (p.weeklyGross || 'not provided'),
    'Day of week: ' + (p.dayOfWeek || 'unknown'),
    'Fatigue level: ' + (p.fatigue || 'not provided'),
    'MPG: ' + (p.mpg || 'not provided'),
    'Fuel price: $' + (p.fuelPrice || 'not provided'),
    'Operating cost/mile: $' + (p.operatingCostPerMile || 'not provided'),
    'Home location: ' + (p.homeLocation || 'not provided'),
    'Strategic flag: ' + (p.strategic ? 'YES — ' + (p.strategicReason || 'no reason given') : 'No'),
    'Currency: ' + (p.currency || 'USD'),
    'Driver notes: ' + (p.notes || 'none'),
  ];
  return lines.join('\n');
}

// ─── Output sanitizers ────────────────────────────────────────────────────────

const VALID_VERDICTS = new Set(['ACCEPT', 'NEGOTIATE', 'PASS', 'STRATEGIC_ONLY']);
const VALID_GRADES   = new Set(['A', 'B', 'C', 'D', 'E']);

function validateVerdict(v) {
  const s = String(v || '').toUpperCase().replace(/\s+/g, '_');
  return VALID_VERDICTS.has(s) ? s : 'PASS';
}

function validateGrade(g) {
  const s = String(g || '').toUpperCase().trim();
  return VALID_GRADES.has(s) ? s : 'C';
}

function sanitizeList(arr) {
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, 6).map(s => String(s).slice(0, 150));
}

// ─── Extract system prompt ────────────────────────────────────────────────────

const EXTRACT_SYSTEM_PROMPT = `You are a freight data parser for an expedited cargo van operator app.
Extract structured fields from raw load board text, rate confirmations, or OCR output.
Return ONLY a JSON object with these fields (omit or use null for fields not found):
{
  "orderNo": "load or order number string",
  "customer": "shipper or customer name",
  "broker": "freight broker or dispatcher name",
  "origin": "City, ST format if possible",
  "destination": "City, ST format if possible",
  "pay": numeric total rate in USD (no $ symbol),
  "loadedMiles": integer loaded miles,
  "deadheadMiles": integer deadhead miles to pickup,
  "pickupDate": "YYYY-MM-DD",
  "deliveryDate": "YYYY-MM-DD",
  "weight": integer pounds,
  "commodity": "freight type or description",
  "notes": "any special instructions, hazmat, team required, etc."
}
Be precise. Do not invent data. If a field is ambiguous or missing, omit it.`;

// ─── Extract output sanitizers ────────────────────────────────────────────────

function finitePositive(v) {
  const n = parseFloat(v);
  return (Number.isFinite(n) && n > 0) ? Math.round(n * 100) / 100 : null;
}

function intPositive(v) {
  const n = parseInt(v, 10);
  return (Number.isFinite(n) && n > 0) ? n : null;
}

function safeDate(v) {
  if (!v) return null;
  const s = String(v).trim();
  // Accept YYYY-MM-DD only
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
    const d = new Date(s);
    if (!isNaN(d.getTime()) && d.getFullYear() >= 2020 && d.getFullYear() <= 2035) return s;
  }
  return null;
}

// ─── Response helper ──────────────────────────────────────────────────────────

function json(data, status, headers) {
  return new Response(JSON.stringify(data), { status, headers });
}
