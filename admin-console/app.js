const DEFAULT_API_ORIGIN = 'https://freightlogic-backup.fimseitef.workers.dev';
const DEFAULT_DRIVER_ORIGIN = 'https://freightlogic-v2.fimseitef.workers.dev';
const SESSION_KEY = 'freightlogic_admin_session_v1';
const INVITE_RE = /^[A-Z2-7]{24}$/;
const USER_ID_RE = /^u_[a-f0-9-]{8,36}$/i;

function cleanOrigin(value, fallback) {
  const raw = String(value || fallback || '').trim();
  const url = new URL(raw);
  if (url.protocol !== 'https:' && url.hostname !== '127.0.0.1' && url.hostname !== 'localhost') {
    throw new Error('Only HTTPS origins are permitted.');
  }
  url.pathname = '/';
  url.search = '';
  url.hash = '';
  return url.origin;
}

function cleanToken(value) {
  return String(value || '').trim();
}

function requireUserId(userId) {
  const value = String(userId || '').trim();
  if (!USER_ID_RE.test(value)) throw new Error('Invalid user ID.');
  return value;
}

function requireName(name) {
  const value = String(name || '').trim();
  if (!value) throw new Error('Driver name is required.');
  return value.slice(0, 50);
}

async function readJson(response) {
  const body = await response.json().catch(() => null);
  if (!response.ok || !body || body.ok === false) {
    const message = body?.error || `Request failed (${response.status})`;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return body;
}

export function createCredentialStore(storage) {
  if (!storage || typeof storage.getItem !== 'function' || typeof storage.setItem !== 'function' || typeof storage.removeItem !== 'function') {
    throw new Error('A session-scoped storage adapter is required.');
  }
  return {
    get() {
      return cleanToken(storage.getItem(SESSION_KEY));
    },
    set(value) {
      const token = cleanToken(value);
      if (!token) {
        storage.removeItem(SESSION_KEY);
        return;
      }
      storage.setItem(SESSION_KEY, token);
    },
    clear() {
      storage.removeItem(SESSION_KEY);
    },
  };
}

export function createAdminApi({
  apiOrigin = DEFAULT_API_ORIGIN,
  tokenProvider,
  fetchImpl = globalThis.fetch,
} = {}) {
  const base = cleanOrigin(apiOrigin, DEFAULT_API_ORIGIN);
  if (typeof tokenProvider !== 'function') throw new Error('An admin access provider is required.');
  if (typeof fetchImpl !== 'function') throw new Error('A fetch implementation is required.');

  async function request(path, { method = 'GET', body } = {}) {
    const token = cleanToken(tokenProvider());
    if (!token) throw new Error('Admin access is required.');

    const headers = new Headers({
      'Accept': 'application/json',
      'X-Admin-Token': token,
    });
    const init = {
      method,
      headers,
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
    };
    if (body !== undefined) {
      headers.set('Content-Type', 'application/json');
      init.body = JSON.stringify(body);
    }

    return await readJson(await fetchImpl(base + path, init));
  }

  return {
    async listUsers() {
      const result = await request('/admin/users');
      return Array.isArray(result.users) ? result.users : [];
    },
    async createInvite(name) {
      return await request('/admin/invites', { method: 'POST', body: { name: requireName(name) } });
    },
    async reinvite(userId) {
      return await request('/admin/invites', { method: 'POST', body: { userId: requireUserId(userId) } });
    },
    async revoke(userId) {
      return await request('/admin/users/' + encodeURIComponent(requireUserId(userId)), { method: 'DELETE' });
    },
  };
}

export async function verifyAndStoreAdminToken({
  token,
  store,
  apiOrigin = DEFAULT_API_ORIGIN,
  fetchImpl = globalThis.fetch,
} = {}) {
  if (!store || typeof store.set !== 'function' || typeof store.clear !== 'function') {
    throw new Error('A credential store is required.');
  }
  const candidate = cleanToken(token);
  store.clear();
  if (!candidate) throw new Error('Admin access is required.');

  const api = createAdminApi({ apiOrigin, tokenProvider: () => candidate, fetchImpl });
  try {
    const users = await api.listUsers();
    store.set(candidate);
    return users;
  } catch (error) {
    store.clear();
    throw error;
  }
}

export function buildClaimLink(code, driverOrigin = DEFAULT_DRIVER_ORIGIN) {
  const claimCode = String(code || '').trim().toUpperCase();
  if (!INVITE_RE.test(claimCode)) throw new Error('Invalid claim code.');
  const origin = cleanOrigin(driverOrigin, DEFAULT_DRIVER_ORIGIN);
  const url = new URL(origin + '/');
  url.hash = 'i=' + encodeURIComponent(claimCode);
  return url.toString();
}

function byId(id) {
  return document.getElementById(id);
}

function setText(id, value) {
  const el = byId(id);
  if (el) el.textContent = String(value ?? '');
}

function setStatus(message, tone = 'neutral') {
  const el = byId('status');
  if (!el) return;
  el.textContent = message;
  el.dataset.tone = tone;
}

function setConnected(connected) {
  document.body.dataset.connected = connected ? 'true' : 'false';
  const connect = byId('connectForm');
  const workspace = byId('workspace');
  if (connect) connect.hidden = connected;
  if (workspace) workspace.hidden = !connected;
}

function makeButton(label, action, className = '') {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = className;
  button.textContent = label;
  button.addEventListener('click', action);
  return button;
}

function formatDate(value) {
  const d = new Date(value || '');
  return Number.isFinite(d.getTime()) ? d.toLocaleDateString() : '—';
}

async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  throw new Error('Clipboard access is unavailable.');
}

function renderInvite({ invite, driverOrigin }) {
  const box = byId('inviteResult');
  if (!box) return;
  box.replaceChildren();
  const link = buildClaimLink(invite.code, driverOrigin);
  const title = document.createElement('strong');
  title.textContent = invite.reinvite ? 'Re-invite ready' : 'Invite ready';
  const meta = document.createElement('div');
  meta.className = 'muted';
  meta.textContent = invite.expiresAt ? `Expires ${new Date(invite.expiresAt).toLocaleString()}` : 'Short-lived claim link';
  const anchor = document.createElement('a');
  anchor.href = link;
  anchor.target = '_blank';
  anchor.rel = 'noopener noreferrer';
  anchor.textContent = link;
  const actions = document.createElement('div');
  actions.className = 'actions';
  actions.append(
    makeButton('Copy link', async () => {
      try { await copyText(link); setStatus('Claim link copied.', 'good'); }
      catch (error) { setStatus(error.message, 'bad'); }
    }),
    makeButton('Share', async () => {
      try {
        if (!navigator.share) throw new Error('Share sheet is unavailable.');
        await navigator.share({ text: link });
        setStatus('Share sheet opened.', 'good');
      } catch (error) {
        if (error?.name !== 'AbortError') setStatus(error.message, 'bad');
      }
    }, 'secondary'),
  );
  box.append(title, meta, anchor, actions);
  box.hidden = false;
}

function renderUsers(users, { api, refresh, driverOrigin }) {
  const list = byId('driverList');
  if (!list) return;
  list.replaceChildren();
  if (!users.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No drivers found.';
    list.append(empty);
    return;
  }

  for (const user of users) {
    const card = document.createElement('article');
    card.className = 'driver-card';
    const head = document.createElement('div');
    head.className = 'driver-head';
    const identity = document.createElement('div');
    const name = document.createElement('strong');
    name.textContent = String(user.name || 'Driver');
    const meta = document.createElement('div');
    meta.className = 'muted';
    meta.textContent = `${user.active === false ? 'Revoked' : 'Active'} · Added ${formatDate(user.createdAt)} · ${Number(user.backupCount || 0)} backup${Number(user.backupCount || 0) === 1 ? '' : 's'}`;
    identity.append(name, meta);
    head.append(identity);
    card.append(head);

    if (user.active !== false) {
      const actions = document.createElement('div');
      actions.className = 'actions';
      actions.append(
        makeButton('Re-invite', async () => {
          try {
            setStatus('Creating re-invite…');
            const invite = await api.reinvite(user.userId);
            if (invite.userId !== user.userId || invite.reinvite !== true) throw new Error('Worker returned an unexpected re-invite identity.');
            renderInvite({ invite, driverOrigin });
            setStatus('Re-invite created.', 'good');
          } catch (error) { setStatus(error.message, 'bad'); }
        }, 'secondary'),
        makeButton('Revoke access', async () => {
          if (!confirm(`Revoke access for ${String(user.name || 'this driver')}?`)) return;
          try {
            setStatus('Revoking access…');
            await api.revoke(user.userId);
            setStatus('Access revoked.', 'good');
            await refresh();
          } catch (error) { setStatus(error.message, 'bad'); }
        }, 'danger'),
      );
      card.append(actions);
    }
    list.append(card);
  }
}

async function bootstrapBrowser() {
  const cfg = document.documentElement.dataset;
  const apiOrigin = cleanOrigin(cfg.apiOrigin, DEFAULT_API_ORIGIN);
  const driverOrigin = cleanOrigin(cfg.driverOrigin, DEFAULT_DRIVER_ORIGIN);
  const store = createCredentialStore(window.sessionStorage);
  let api = createAdminApi({ apiOrigin, tokenProvider: () => store.get() });

  const refresh = async () => {
    try {
      const users = await api.listUsers();
      renderUsers(users, { api, refresh, driverOrigin });
      setText('driverCount', users.length);
      setStatus('Driver access list refreshed.', 'good');
      return users;
    } catch (error) {
      if (error?.status === 401) {
        store.clear();
        setConnected(false);
        setStatus('Admin access was rejected. Reconnect.', 'bad');
      } else {
        setStatus(error.message, 'bad');
      }
      throw error;
    }
  };

  byId('connectForm')?.addEventListener('submit', async event => {
    event.preventDefault();
    const input = byId('adminAccess');
    const token = cleanToken(input?.value);
    if (input) input.value = '';
    setStatus('Verifying admin access…');
    try {
      const users = await verifyAndStoreAdminToken({ token, store, apiOrigin });
      api = createAdminApi({ apiOrigin, tokenProvider: () => store.get() });
      setConnected(true);
      renderUsers(users, { api, refresh, driverOrigin });
      setText('driverCount', users.length);
      setStatus('Admin connected for this tab only.', 'good');
    } catch (error) {
      setConnected(false);
      setStatus(error.message, 'bad');
    }
  });

  byId('disconnect')?.addEventListener('click', () => {
    store.clear();
    setConnected(false);
    byId('driverList')?.replaceChildren();
    byId('inviteResult')?.replaceChildren();
    setStatus('Admin session cleared.');
  });

  byId('refresh')?.addEventListener('click', () => refresh().catch(() => {}));

  byId('inviteForm')?.addEventListener('submit', async event => {
    event.preventDefault();
    const input = byId('driverName');
    try {
      setStatus('Creating invite…');
      const invite = await api.createInvite(input?.value);
      if (input) input.value = '';
      renderInvite({ invite, driverOrigin });
      setStatus('Invite created.', 'good');
    } catch (error) { setStatus(error.message, 'bad'); }
  });

  setConnected(Boolean(store.get()));
  if (store.get()) await refresh().catch(() => {});
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  bootstrapBrowser().catch(error => setStatus(error.message, 'bad'));
}

export const ADMIN_CONSOLE_DEFAULTS = Object.freeze({
  apiOrigin: DEFAULT_API_ORIGIN,
  driverOrigin: DEFAULT_DRIVER_ORIGIN,
});
