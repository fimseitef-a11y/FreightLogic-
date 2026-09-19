const SECURITY_HEADERS = Object.freeze({
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src https://freightlogic-backup.fimseitef.workers.dev; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; media-src 'none'; manifest-src 'none'",
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()',
});

export default {
  async fetch(request, env) {
    if (!env?.ASSETS || typeof env.ASSETS.fetch !== 'function') {
      return new Response('Admin assets unavailable.', {
        status: 503,
        headers: SECURITY_HEADERS,
      });
    }

    const asset = await env.ASSETS.fetch(request);
    const headers = new Headers(asset.headers);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      headers.set(name, value);
    }

    // API CORS belongs exclusively to the backup/API Worker. This static
    // privileged origin must not widen that boundary itself.
    headers.delete('Access-Control-Allow-Origin');
    headers.delete('Access-Control-Allow-Credentials');

    return new Response(asset.body, {
      status: asset.status,
      statusText: asset.statusText,
      headers,
    });
  },
};

export { SECURITY_HEADERS };
