// FreightLogic Cloud Backup Worker v4 - Multi-User
// KV binding: BACKUPS | Secret: ADMIN_TOKEN

export default {
  async fetch(request, env) {
    var cors = {
      'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Device-Id, X-Backup-Token, X-Admin-Token',
      'Content-Type': 'application/json'
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    var url = new URL(request.url);
    var path = url.pathname;

    try {
      // ADMIN ENDPOINTS
      if (path.startsWith('/admin/')) {
        var adminToken = request.headers.get('X-Admin-Token');
        if (!adminToken || adminToken !== env.ADMIN_TOKEN) {
          return json({ ok: false, error: 'Unauthorized' }, 401, cors);
        }

        if (request.method === 'POST' && path === '/admin/users') {
          var body = await request.json().catch(function() { return {}; });
          var name = (body.name || 'Driver').slice(0, 50);
          var userId = 'u_' + crypto.randomUUID().slice(0, 12);
          var token = 'flk_' + crypto.randomUUID().replace(/-/g, '');
          var rec = { userId: userId, name: name, token: token, createdAt: new Date().toISOString(), active: true };
          await env.BACKUPS.put('token:' + token, JSON.stringify(rec));
          await env.BACKUPS.put('user:' + userId, JSON.stringify(rec));
          return json({ ok: true, userId: userId, name: name, token: token }, 201, cors);
        }

        if (request.method === 'GET' && path === '/admin/users') {
          var list = await env.BACKUPS.list({ prefix: 'user:' });
          var users = [];
          for (var i = 0; i < list.keys.length; i++) {
            var val = await env.BACKUPS.get(list.keys[i].name);
            if (val) { users.push(JSON.parse(val)); }
          }
          return json({ ok: true, users: users }, 200, cors);
        }

        if (request.method === 'DELETE' && path.startsWith('/admin/users/')) {
          var delId = path.split('/admin/users/')[1];
          var userRec = await env.BACKUPS.get('user:' + delId);
          if (!userRec) { return json({ ok: false, error: 'Not found' }, 404, cors); }
          var parsed = JSON.parse(userRec);
          parsed.active = false;
          await env.BACKUPS.put('user:' + delId, JSON.stringify(parsed));
          if (parsed.token) { await env.BACKUPS.delete('token:' + parsed.token); }
          return json({ ok: true, revoked: delId }, 200, cors);
        }

        return json({ ok: false, error: 'Not found' }, 404, cors);
      }

      // DRIVER ENDPOINTS - require token
      var driverToken = request.headers.get('X-Backup-Token');
      if (!driverToken) {
        return json({ ok: false, error: 'Missing token' }, 401, cors);
      }

      var tokenRaw = await env.BACKUPS.get('token:' + driverToken);
      if (!tokenRaw) {
        return json({ ok: false, error: 'Invalid token' }, 403, cors);
      }

      var tokenData = JSON.parse(tokenRaw);
      if (!tokenData.active) {
        return json({ ok: false, error: 'Token revoked' }, 403, cors);
      }

      var driverUserId = tokenData.userId;
      var deviceId = request.headers.get('X-Device-Id') || 'default';

      // POST /backup - save encrypted data
      if (request.method === 'POST' && path === '/backup') {
        var payload = await request.text();
        if (!payload || payload.length < 10) {
          return json({ ok: false, error: 'Empty payload' }, 400, cors);
        }
        if (payload.length > 5 * 1024 * 1024) {
          return json({ ok: false, error: 'Payload too large (5MB max)' }, 413, cors);
        }
        var ts = new Date().toISOString().replace(/[:.]/g, '-');
        var key = 'user:' + driverUserId + ':device:' + deviceId + ':backup:' + ts;
        await env.BACKUPS.put(key, payload);

        // Rotate - keep last 3
        var bp = 'user:' + driverUserId + ':device:' + deviceId + ':backup:';
        var bl = await env.BACKUPS.list({ prefix: bp });
        if (bl.keys.length > 3) {
          var sorted = bl.keys.sort(function(a, b) { return a.name < b.name ? -1 : 1; });
          var delCount = sorted.length - 3;
          for (var d = 0; d < delCount; d++) {
            await env.BACKUPS.delete(sorted[d].name);
          }
        }

        return json({ ok: true, key: key, size: payload.length }, 200, cors);
      }

      // GET /backup - retrieve latest
      if (request.method === 'GET' && path === '/backup') {
        var gp = 'user:' + driverUserId + ':device:' + deviceId + ':backup:';
        var gl = await env.BACKUPS.list({ prefix: gp });
        if (gl.keys.length === 0) {
          return json({ ok: false, error: 'No backup found' }, 404, cors);
        }
        var gsorted = gl.keys.sort(function(a, b) { return a.name < b.name ? -1 : 1; });
        var latest = gsorted[gsorted.length - 1].name;
        var data = await env.BACKUPS.get(latest);
        return new Response(data, { status: 200, headers: cors });
      }

      // GET /list - list backups
      if (request.method === 'GET' && path === '/list') {
        var lp = 'user:' + driverUserId + ':device:' + deviceId + ':';
        var ll = await env.BACKUPS.list({ prefix: lp });
        return json({
          ok: true,
          backups: ll.keys.map(function(k) { return k.name; }),
          count: ll.keys.length
        }, 200, cors);
      }

      // GET /status - check backup status
      if (request.method === 'GET' && path === '/status') {
        var sp = 'user:' + driverUserId + ':device:' + deviceId + ':';
        var sl = await env.BACKUPS.list({ prefix: sp });
        return json({ ok: true, hasBackup: sl.keys.length > 0, count: sl.keys.length, user: tokenData.name }, 200, cors);
      }

      return json({ ok: false, error: 'Not found' }, 404, cors);
    } catch (err) {
      return json({ ok: false, error: 'Server error' }, 500, cors);
    }
  }
};

function json(data, status, headers) {
  return new Response(JSON.stringify(data), {
    status: status,
    headers: headers
  });
}
