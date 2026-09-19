const SECURITY_HEADERS = Object.freeze({
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src https://freightlogic-backup.fimseitef.workers.dev; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; media-src 'none'; manifest-src 'none'",
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()',
});

const STATIC_METHODS = new Set(['GET', 'HEAD']);
const CORS_AUTHORITY_HEADERS = Object.freeze([
  'Access-Control-Allow-Origin',
  'Access-Control-Allow-Credentials',
  'Access-Control-Allow-Methods',
  'Access-Control-Allow-Headers',
  'Access-Control-Expose-Headers',
  'Access-Control-Max-Age',
]);

function securityHeaders(extra = {}) {
  const headers = new Headers(SECURITY_HEADERS);
  for (const [name, value] of Object.entries(extra)) headers.set(name, value);
  return headers;
}

export default {
  async fetch(request, env) {
    // This is a privileged STATIC origin. It has no form/action endpoint of its
    // own, so anything other than read-only asset retrieval is rejected before
    // the request can reach the asset binding.
    if (!STATIC_METHODS.has(request.method)) {
      return new Response(null, {
        status: 405,
        headers: securityHeaders({ Allow: 'GET, HEAD' }),
      });
    }

    if (!env?.ASSETS || typeof env.ASSETS.fetch !== 'function') {
      return new Response('Admin assets unavailable.', {
        status: 503,
        headers: securityHeaders(),
      });
    }

    const asset = await env.ASSETS.fetch(request);
    const headers = new Headers(asset.headers);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      headers.set(name, value);
    }

    // API CORS belongs exclusively to the backup/API Worker. If an upstream
    // asset source ever contributes CORS headers, strip the complete authority
    // family rather than leaving a partial policy that can be misread later.
    for (const header of CORS_AUTHORITY_HEADERS) headers.delete(header);

    return new Response(asset.body, {
      status: asset.status,
      statusText: asset.statusText,
      headers,
    });
  },
};

export { SECURITY_HEADERS };
