/**
 * dat-rateview.js
 * DAT RateView API client for FreightLogic
 *
 * Purpose: Pull live spot + contract rates (including expedited / team premiums)
 * for cargo van and other equipment types so you can bid smarter on Dispatch Lane.
 *
 * Requirements (you must have these from DAT):
 * - DAT One load board subscription
 * - RateView Combo Pro or Combo Premium
 * - Connexion (API) license
 * - Service account email + password (org level)
 * - Your regular DAT user email (user level)
 *
 * Docs / portal: https://developer.dat.com
 * Support: techsupportteamleads@dat.com or developersupport@dat.com
 *
 * Usage example (after credentials are set):
 *   const rates = await DatRateView.getLaneRates({
 *     originCity: 'Columbus',
 *     originState: 'OH',
 *     destCity: 'Chicago',
 *     destState: 'IL',
 *     equipment: 'VAN',
 *     rateType: 'SPOT'
 *   });
 */

(function (global) {
  'use strict';

  const CONFIG = {
    // Identity / token endpoint (modeled from public DAT docs)
    identityBase: 'https://identity.api.dat.com',
    // RateView / analytics endpoint
    analyticsBase: 'https://analytics.api.dat.com',
    // Freight / load board endpoint (if you later want search)
    freightBase: 'https://freight.api.dat.com',

    // Fill these from your DAT service account + user login
    serviceAccountEmail: '',      // org-level service account email
    serviceAccountPassword: '',   // org-level password
    userEmail: '',                // your normal DAT login email

    // Optional: store tokens after first auth so you don't re-auth every call
    _orgToken: null,
    _userToken: null,
    _tokenExpiry: null
  };

  /**
   * Set credentials once (call this from your settings / init code)
   */
  function setCredentials({ serviceAccountEmail, serviceAccountPassword, userEmail }) {
    if (serviceAccountEmail) CONFIG.serviceAccountEmail = serviceAccountEmail;
    if (serviceAccountPassword) CONFIG.serviceAccountPassword = serviceAccountPassword;
    if (userEmail) CONFIG.userEmail = userEmail;
  }

  /**
   * Two-step auth required by DAT REST APIs:
   * 1. Authenticate organization with service account
   * 2. Authenticate user with regular login email
   *
   * NOTE: Exact paths and payload shapes are gated behind the developer portal.
   * Update the endpoints below once you have access to the live OpenAPI docs.
   */
  async function authenticate() {
    if (!CONFIG.serviceAccountEmail || !CONFIG.serviceAccountPassword || !CONFIG.userEmail) {
      throw new Error('DAT credentials not set. Call DatRateView.setCredentials(...) first.');
    }

    // Placeholder – replace with real identity endpoints from developer.dat.com
    // Typical pattern seen in TMS integrations:
    // POST /auth/organization  with service account
    // then POST /auth/user     with user email + org token

    const orgRes = await fetch(`${CONFIG.identityBase}/v1/auth/organization`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: CONFIG.serviceAccountEmail,
        password: CONFIG.serviceAccountPassword
      })
    });

    if (!orgRes.ok) {
      const text = await orgRes.text();
      throw new Error(`DAT org auth failed (${orgRes.status}): ${text}`);
    }

    const orgData = await orgRes.json();
    CONFIG._orgToken = orgData.access_token || orgData.token || orgData.orgToken;

    const userRes = await fetch(`${CONFIG.identityBase}/v1/auth/user`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${CONFIG._orgToken}`
      },
      body: JSON.stringify({
        email: CONFIG.userEmail
      })
    });

    if (!userRes.ok) {
      const text = await userRes.text();
      throw new Error(`DAT user auth failed (${userRes.status}): ${text}`);
    }

    const userData = await userRes.json();
    CONFIG._userToken = userData.access_token || userData.token || userData.userToken;
    CONFIG._tokenExpiry = Date.now() + (55 * 60 * 1000); // ~55 min safety margin

    return {
      orgToken: CONFIG._orgToken,
      userToken: CONFIG._userToken
    };
  }

  async function ensureAuth() {
    if (CONFIG._userToken && CONFIG._tokenExpiry && Date.now() < CONFIG._tokenExpiry) {
      return CONFIG._userToken;
    }
    await authenticate();
    return CONFIG._userToken;
  }

  /**
   * Core rate lookup
   * @param {Object} opts
   * @param {string} opts.originCity
   * @param {string} opts.originState   - 2-letter
   * @param {string} [opts.originZip]
   * @param {string} opts.destCity
   * @param {string} opts.destState     - 2-letter
   * @param {string} [opts.destZip]
   * @param {string} [opts.equipment='VAN'] - VAN | REEFER | FLATBED | etc.
   * @param {string} [opts.rateType='SPOT'] - SPOT | CONTRACT
   * @param {boolean} [opts.expedited=false] - request expedited/team attribute premium when available
   * @param {number} [opts.timeframeDays=7]
   */
  async function getLaneRates(opts) {
    const {
      originCity,
      originState,
      originZip,
      destCity,
      destState,
      destZip,
      equipment = 'VAN',
      rateType = 'SPOT',
      expedited = false,
      timeframeDays = 7
    } = opts;

    if (!originCity || !originState || !destCity || !destState) {
      throw new Error('originCity, originState, destCity, destState are required');
    }

    const token = await ensureAuth();

    // Placeholder endpoint – replace with exact RateView lookup path from the portal.
    // Common pattern from TMS integrations:
    // POST /rateview/v1/rates or GET with query params
    const body = {
      origin: {
        city: originCity,
        state: originState.toUpperCase(),
        postalCode: originZip || undefined
      },
      destination: {
        city: destCity,
        state: destState.toUpperCase(),
        postalCode: destZip || undefined
      },
      equipmentType: equipment.toUpperCase(),
      rateType: rateType.toUpperCase(),
      timeframeDays,
      attributes: expedited ? ['EXPEDITED', 'TEAM'] : []
    };

    const res = await fetch(`${CONFIG.analyticsBase}/rateview/v1/rates`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(body)
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`DAT RateView lookup failed (${res.status}): ${text}`);
    }

    const data = await res.json();

    // Normalize a useful shape for FreightLogic
    return {
      raw: data,
      averagePerMile: data.averageRate || data.median || data.rpm?.median || null,
      lowPerMile: data.low || data.rpm?.low || null,
      highPerMile: data.high || data.rpm?.high || null,
      fuelSurchargePerMile: data.fuelSurchargePerMile || data.averageFuelSurchargePerMile || null,
      reports: data.reports || data.companies || null,
      timeframe: data.timeframe || `${timeframeDays}d`,
      equipment: equipment.toUpperCase(),
      rateType: rateType.toUpperCase(),
      expeditedRequested: expedited
    };
  }

  /**
   * Simple quote helper (mirrors the RateView Quote Calculator idea)
   * Takes per-mile rate + miles + optional accessorials + desired margin %
   */
  function buildQuote({ perMileRate, miles, accessorials = 0, marginPercent = 0 }) {
    if (perMileRate == null || miles == null) {
      throw new Error('perMileRate and miles are required');
    }
    const linehaul = perMileRate * miles;
    const subtotal = linehaul + (accessorials || 0);
    const margin = subtotal * (marginPercent / 100);
    const total = subtotal + margin;

    return {
      linehaul: round2(linehaul),
      accessorials: round2(accessorials),
      subtotal: round2(subtotal),
      margin: round2(margin),
      marginPercent,
      total: round2(total),
      perMileAllIn: miles > 0 ? round2(total / miles) : null
    };
  }

  function round2(n) {
    return Math.round((n + Number.EPSILON) * 100) / 100;
  }

  /**
   * Convenience for cargo-van expedite lanes
   */
  async function getCargoVanExpediteRates(opts) {
    return getLaneRates({
      ...opts,
      equipment: opts.equipment || 'VAN',
      expedited: true,
      rateType: opts.rateType || 'SPOT'
    });
  }

  // Public API
  const DatRateView = {
    setCredentials,
    authenticate,
    getLaneRates,
    getCargoVanExpediteRates,
    buildQuote,
    // expose config for debugging (do not log passwords in production)
    _config: CONFIG
  };

  // Attach to global / window for both browser and module use
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = DatRateView;
  } else {
    global.DatRateView = DatRateView;
  }
})(typeof window !== 'undefined' ? window : globalThis);
