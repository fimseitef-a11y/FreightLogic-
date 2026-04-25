// FreightLogic Cloud Backup Worker v8 - Multi-User + AI Evaluate + AI Extract + Delta Sync
// Optimized for Cloudflare free tier: pointer keys replace list() calls; hourly rate-limit windows.
// KV binding: BACKUPS
// Secrets: ADMIN_TOKEN, OPENAI_API_KEY
// Vars: ALLOWED_ORIGIN, OPENAI_MODEL (optional, default: gpt-4.1-mini)

const ALLOWED_ORIGINS = new Set([
  'https://freightlogic.pages.dev',
  'https://www.freightlogic.pages.dev',
]);

export default {
  async fetch(request, env) {
    // Strict CORS origin validation — only allow explicitly whitelisted origins
    const configuredOrigin = env.ALLOWED_ORIGIN;
    const requestOrigin = request.headers.get('Origin') || '';
    let allowedOrigin = 'https://freightlogic.pages.dev';
    if (configuredOrigin && requestOrigin === configuredOrigin) {
      allowedOrigin = configuredOrigin;
    } else if (ALLOWED_ORIGINS.has(requestOrigin)) {
      allowedOrigin = requestOrigin;
    }
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
        // Rate limit admin attempts by IP to prevent brute-force on the admin token
        const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
        const adminRateLimited = await checkRateLimit(env, 'ip:' + clientIp, 20, 'admin');
        if (adminRateLimited) {
          return json({ ok: false, error: 'Too many admin requests. Try again later.' }, 429, cors);
        }
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
          // Write both records in parallel
          await Promise.all([
            env.BACKUPS.put('token:' + token, JSON.stringify(rec)),
            env.BACKUPS.put('user:' + userId, JSON.stringify(rec))
          ]);
          return json({ ok: true, userId, name, token }, 201, cors);
        }

        if (request.method === 'GET' && path === '/admin/users') {
          const list = await env.BACKUPS.list({ prefix: 'user:' });
          // Filter to top-level user records only (exclude device/backup subkeys)
          const userKeys = list.keys.filter(k => /^user:u_[^:]+$/.test(k.name));
          // Fetch all user records in parallel
          const vals = await Promise.all(userKeys.map(k => env.BACKUPS.get(k.name)));
          const users = [];
          for (const val of vals) {
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
          // Deactivate user record and revoke token in parallel
          const ops = [env.BACKUPS.put('user:' + delId, JSON.stringify(parsed))];
          if (parsed.token) ops.push(env.BACKUPS.delete('token:' + parsed.token));
          await Promise.all(ops);
          return json({ ok: true, revoked: delId }, 200, cors);
        }

        return json({ ok: false, error: 'Not found' }, 404, cors);
      }

      // DRIVER ENDPOINTS — require token
      const driverToken = request.headers.get('X-Backup-Token');
      if (!driverToken) {
        return json({ ok: false, error: 'Missing token' }, 401, cors);
      }
      // Validate token format before KV lookup to prevent malformed key injection
      if (!/^flk_[a-f0-9]{32}$/.test(driverToken)) {
        return json({ ok: false, error: 'Invalid token' }, 403, cors);
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
        // Rate limit: 100 requests per hour per user (hourly window = far fewer KV writes than per-minute)
        const rateLimited = await checkRateLimit(env, driverUserId, 100, 'eval');
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
        // Rate limit: 50 requests per hour per user
        const rateLimited = await checkRateLimit(env, driverUserId, 50, 'extract');
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

        // Use a hard delimiter so user text cannot escape into instructions
        const userContent = 'Extract structured fields from this load text:\n\n<<<BEGIN_LOAD_TEXT>>>\n' + rawText + '\n<<<END_LOAD_TEXT>>>';

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
              { role: 'user', content: userContent }
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
            orderNo:       String(parsed.orderNo      || '').slice(0, 40),
            customer:      String(parsed.customer     || '').slice(0, 80),
            broker:        String(parsed.broker       || '').slice(0, 80),
            origin:        String(parsed.origin       || '').slice(0, 100),
            destination:   String(parsed.destination  || '').slice(0, 100),
            pay:           finitePositive(parsed.pay),
            loadedMiles:   intPositive(parsed.loadedMiles),
            deadheadMiles: intPositive(parsed.deadheadMiles),
            pickupDate:    safeDate(parsed.pickupDate),
            deliveryDate:  safeDate(parsed.deliveryDate),
            weight:        intPositive(parsed.weight),
            commodity:     String(parsed.commodity    || '').slice(0, 80),
            notes:         String(parsed.notes        || '').slice(0, 300),
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

        // Write backup data and read pointer in parallel (saves one round-trip)
        const [, ptr] = await Promise.all([
          env.BACKUPS.put(key, payload),
          getPtr(env, driverUserId, deviceId, 'b')
        ]);

        ptr.keys.push(key);
        if (ptr.keys.length > 3) {
          const toDelete = ptr.keys.splice(0, ptr.keys.length - 3);
          ptr.count = ptr.keys.length;
          // Delete old backups and save updated pointer in parallel
          await Promise.all([
            ...toDelete.map(k => env.BACKUPS.delete(k)),
            savePtr(env, driverUserId, deviceId, 'b', ptr)
          ]);
        } else {
          ptr.count = ptr.keys.length;
          await savePtr(env, driverUserId, deviceId, 'b', ptr);
        }

        return json({ ok: true, key, size: payload.length }, 200, cors);
      }

      // POST /backup/delta — store delta (partial sync payload)
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

        // Write delta and read pointer in parallel
        const [, ptr] = await Promise.all([
          env.BACKUPS.put(key, payload, { expirationTtl: 7 * 24 * 3600 }),
          getPtr(env, driverUserId, deviceId, 'd')
        ]);

        ptr.keys.push(key);
        if (ptr.keys.length > 20) {
          const toDelete = ptr.keys.splice(0, ptr.keys.length - 20);
          ptr.count = ptr.keys.length;
          await Promise.all([
            ...toDelete.map(k => env.BACKUPS.delete(k)),
            savePtr(env, driverUserId, deviceId, 'd', ptr)
          ]);
        } else {
          ptr.count = ptr.keys.length;
          await savePtr(env, driverUserId, deviceId, 'd', ptr);
        }

        return json({ ok: true, key, size: payload.length, type: 'delta' }, 200, cors);
      }

      // GET /backup — retrieve latest
      if (request.method === 'GET' && path === '/backup') {
        const ptr = await getPtr(env, driverUserId, deviceId, 'b');
        if (!ptr.keys.length) {
          return json({ ok: false, error: 'No backup found' }, 404, cors);
        }
        const data = await env.BACKUPS.get(ptr.keys[ptr.keys.length - 1]);
        if (!data) return json({ ok: false, error: 'No backup found' }, 404, cors);
        return new Response(data, { status: 200, headers: cors });
      }

      // GET /list — list backup and delta keys for this user+device
      if (request.method === 'GET' && path === '/list') {
        const [bptr, dptr] = await Promise.all([
          getPtr(env, driverUserId, deviceId, 'b'),
          getPtr(env, driverUserId, deviceId, 'd')
        ]);
        const backups = [...bptr.keys, ...dptr.keys];
        return json({ ok: true, backups, count: backups.length }, 200, cors);
      }

      // GET /status — backup presence check (uses pointer key — no list() call)
      if (request.method === 'GET' && path === '/status') {
        const ptr = await getPtr(env, driverUserId, deviceId, 'b');
        return json({ ok: true, hasBackup: ptr.count > 0, count: ptr.count, user: tokenData.name }, 200, cors);
      }

      // DELETE /backup — remove all backups for this user+device
      if (request.method === 'DELETE' && path === '/backup') {
        const ptr = await getPtr(env, driverUserId, deviceId, 'b');
        const ops = ptr.keys.map(k => env.BACKUPS.delete(k));
        ops.push(savePtr(env, driverUserId, deviceId, 'b', { keys: [], count: 0 }));
        await Promise.all(ops);
        return json({ ok: true, deleted: ptr.keys.length }, 200, cors);
      }

      return json({ ok: false, error: 'Not found' }, 404, cors);
    } catch (err) {
      console.error('[FL] Worker error:', err);
      return json({ ok: false, error: 'Server error' }, 500, cors);
    }
  }
};

// ─── Backup/delta pointer helpers ─────────────────────────────────────────────
//
// Instead of calling BACKUPS.list() (limited to 1,000/day on free tier) to find
// the latest backup or count backups, we maintain a small pointer key per
// user+device that stores { keys: string[], count: number }.
//
// type 'b' = full backups  (key suffix: bptr)
// type 'd' = delta backups (key suffix: dptr)
//
// On first access the pointer is absent; we run a one-time list() to migrate
// existing keys and then persist the pointer so future calls skip the list.

async function getPtr(env, userId, deviceId, type) {
  const ptrKey = 'user:' + userId + ':device:' + deviceId + ':' + type + 'ptr';
  const raw = await env.BACKUPS.get(ptrKey);
  if (raw) {
    try { return JSON.parse(raw); } catch {}
  }
  // First-time: lazily migrate existing keys from a list (runs once per user+device+type)
  const prefix = 'user:' + userId + ':device:' + deviceId + ':' + (type === 'b' ? 'backup:' : 'delta:');
  const list = await env.BACKUPS.list({ prefix });
  const keys = list.keys.map(k => k.name).sort();
  const ptr = { keys, count: keys.length };
  if (keys.length > 0) {
    // Persist pointer so all future calls skip the list
    await env.BACKUPS.put(ptrKey, JSON.stringify(ptr));
  }
  return ptr;
}

async function savePtr(env, userId, deviceId, type, ptr) {
  const ptrKey = 'user:' + userId + ':device:' + deviceId + ':' + type + 'ptr';
  await env.BACKUPS.put(ptrKey, JSON.stringify(ptr));
}

// ─── Rate limiter (sliding hour window via KV) ────────────────────────────────
//
// Per-hour windows instead of per-minute drastically reduce KV write churn:
// one rate-limit key is created per user per endpoint per hour rather than
// one per minute. The higher per-hour ceiling (100 eval / 50 extract) is still
// well above legitimate single-driver usage while blocking API abuse.

async function checkRateLimit(env, userId, limit, ns = 'eval') {
  const hour = Math.floor(Date.now() / 3600000);
  const key = 'rl:' + ns + ':' + userId + ':' + hour;
  const raw = await env.BACKUPS.get(key);
  const count = raw ? parseInt(raw, 10) : 0;
  if (count >= limit) return true;
  // TTL 7200s (2 hours) — key auto-cleans after two windows
  await env.BACKUPS.put(key, String(count + 1), { expirationTtl: 7200 });
  return false;
}

// ─── Prompt builder ───────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a Midwest Stack freight decision advisor for a cargo van expedited carrier.
Your job is to evaluate a single load using the Midwest Stack operating framework.

Core principles:
- True RPM = revenue ÷ (loaded miles + deadhead miles) — always the primary metric.
- Loaded RPM is secondary and must never override True RPM.
- Deadhead miles are included in True RPM by definition; always factor them in.
- Density and reload potential matter — empty return lanes are traps.
- Strategic under-floor loads are allowed only when explicitly justified.
- Preserve operator discipline. Do not validate emotional moves.
- Be direct and specific. No generic freight advice.

You must respond with a single JSON object matching this exact structure:
{
  "summary": "2-3 sentence analysis of this load",
  "verdict": "ACCEPT | NEGOTIATE | PASS | STRATEGIC_ONLY",
  "grade": "A | B | C | D | E",
  "trueRpmBand": "$X.XX – $X.XX / true mile (loaded + deadhead)",
  "bidAdvice": "specific bid or negotiation guidance",
  "primaryReason": "the single most important factor driving this verdict",
  "risks": ["risk 1", "risk 2"],
  "positives": ["positive 1", "positive 2"],
  "nextMove": "what the operator should do right now"
}`;

// Sanitize a string field before embedding in an OpenAI prompt to prevent injection
function promptField(v, maxLen = 120) {
  return String(v || '').replace(/[\r\n\t]/g, ' ').slice(0, maxLen);
}
function promptNum(v) {
  const n = parseFloat(v);
  return Number.isFinite(n) ? n : 0;
}

function buildEvalPrompt(p) {
  const lines = [
    'Evaluate this load:',
    '',
    'Route: ' + promptField(p.origin || 'unknown') + ' → ' + promptField(p.destination || 'unknown'),
    'Loaded miles: ' + promptNum(p.loadedMiles),
    'Deadhead miles: ' + promptNum(p.deadheadMiles),
    'Revenue: $' + promptNum(p.revenue),
    'True RPM (pre-calc, loaded+deadhead): $' + (Number.isFinite(parseFloat(p.trueRPM || p.trueRpm)) ? parseFloat(p.trueRPM || p.trueRpm) : 'not provided'),
    'Loaded RPM (pre-calc): $' + (Number.isFinite(parseFloat(p.loadedRPM || p.loadedRpm)) ? parseFloat(p.loadedRPM || p.loadedRpm) : 'not provided'),
    'Weekly gross context: $' + (Number.isFinite(parseFloat(p.weeklyGross)) ? parseFloat(p.weeklyGross) : 'not provided'),
    'Day of week: ' + promptField(p.dayOfWeek || 'unknown', 20),
    'Fatigue level: ' + (Number.isFinite(parseFloat(p.fatigue)) ? parseFloat(p.fatigue) : 'not provided'),
    'MPG: ' + (Number.isFinite(parseFloat(p.mpg)) ? parseFloat(p.mpg) : 'not provided'),
    'Fuel price: $' + (Number.isFinite(parseFloat(p.fuelPrice)) ? parseFloat(p.fuelPrice) : 'not provided'),
    'Operating cost/mile: $' + (Number.isFinite(parseFloat(p.operatingCostPerMile)) ? parseFloat(p.operatingCostPerMile) : 'not provided'),
    'Home location: ' + promptField(p.homeLocation || 'not provided'),
    'Strategic flag: ' + (p.strategic ? 'YES — ' + promptField(p.strategicReason || 'no reason given', 80) : 'No'),
    'Currency: ' + promptField(p.currency || 'USD', 10),
    'Driver notes: ' + promptField(p.notes || 'none', 200),
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
