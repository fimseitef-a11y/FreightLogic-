import { classifyFreshness } from './freshness.mjs';
import { OPERATOR_FRESH_MS, OPERATOR_STALE_AFTER_MS } from './ingest.mjs';

function parseJson(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function pickDefined(source, keys) {
  const result = {};
  for (const key of keys) {
    if (source?.[key] !== undefined) result[key] = source[key];
  }
  return result;
}

function confidenceOrUnknown(value) {
  return Number.isFinite(value) && value >= 0 && value <= 1 ? value : null;
}

export function projectLaneReadModel(row, { now = new Date().toISOString() } = {}) {
  if (!row || typeof row !== 'object') return null;
  const storedFreshness = parseJson(row.freshness_json, {});
  const freshness = storedFreshness && typeof storedFreshness === 'object' && !Array.isArray(storedFreshness)
    ? { ...storedFreshness } : {};
  if (Object.hasOwn(freshness, 'OPERATOR_PRIVATE')) {
    freshness.OPERATOR_PRIVATE = classifyFreshness({
      sourceAsOf: row.latest_evidence_at, now,
      freshForMs: OPERATOR_FRESH_MS, staleAfterMs: OPERATOR_STALE_AFTER_MS,
    });
  }
  return {
    originMarket: row.origin_market ?? null,
    destinationMarket: row.destination_market ?? null,
    structuralScore: Number.isFinite(row.structural_score) ? row.structural_score : null,
    expediteRelevance: Number.isFinite(row.expedite_relevance) ? row.expedite_relevance : null,
    structuralConfidence: confidenceOrUnknown(row.structural_confidence),
    expediteConfidence: confidenceOrUnknown(row.expedite_confidence),
    freshness,
    unknownFlags: parseJson(row.unknown_flags_json, []),
    conflictFlags: parseJson(row.conflict_flags_json, []),
    evidenceCounts: parseJson(row.evidence_counts_json, {}),
    latestEvidenceAt: row.latest_evidence_at ?? null,
    stage: row.stage ?? null,
    modelRunId: row.model_run_id ?? null,
    governanceFingerprint: row.governance_fingerprint ?? null,
    updatedAt: row.updated_at ?? null,
  };
}

export function reconcilePromotion({ runMode, runtimeGovernanceFingerprint, governance } = {}) {
  if (runMode === 'SHADOW') return { eligible: false, reason: 'SHADOW_RUN' };
  if (!governance?.approved) return { eligible: false, reason: 'GOVERNANCE_NOT_APPROVED' };
  if (!runtimeGovernanceFingerprint || runtimeGovernanceFingerprint !== governance.fingerprint) {
    return { eligible: false, reason: 'GOVERNANCE_FINGERPRINT_MISMATCH' };
  }
  return { eligible: true, reason: null, approvedStage: governance.stage ?? null };
}

export function createPrivateApi(repository, { now = () => new Date().toISOString() } = {}) {
  if (!repository || typeof repository !== 'object') {
    throw new TypeError('repository is required');
  }

  return {
    async getLaneIntelligence({ originMarket, destinationMarket } = {}) {
      if (!originMarket || !destinationMarket) {
        return { status: 'UNKNOWN', reason: 'CANONICAL_MARKETS_REQUIRED', originMarket: originMarket ?? null, destinationMarket: destinationMarket ?? null };
      }
      // Callers (the Agent) speak FreightLogic city names; ELI stores market
      // clusters. A repository resolver translates through Verified aliases
      // only; an unresolved market is UNKNOWN, never guessed.
      let originKey = originMarket;
      let destinationKey = destinationMarket;
      if (typeof repository.resolveMarket === 'function') {
        originKey = await repository.resolveMarket(originMarket);
        destinationKey = await repository.resolveMarket(destinationMarket);
        if (!originKey || !destinationKey) {
          return { status: 'UNKNOWN', reason: 'MARKET_UNRESOLVED', originMarket, destinationMarket };
        }
      }
      const row = await repository.getLaneRow(originKey, destinationKey);
      if (!row) {
        return { status: 'UNKNOWN', reason: 'LANE_NOT_MATERIALIZED', originMarket, destinationMarket };
      }
      return {
        status: 'KNOWN',
        resolved: { originMarket: originKey, destinationMarket: destinationKey },
        intelligence: projectLaneReadModel(row, { now: now() }),
      };
    },

    async getMarketIntelligence({ market } = {}) {
      if (!market) return { status: 'UNKNOWN', reason: 'CANONICAL_MARKET_REQUIRED', market: market ?? null };
      const rows = await repository.getMarketRows(market);
      if (!Array.isArray(rows) || rows.length === 0) {
        return { status: 'UNKNOWN', reason: 'MARKET_NOT_MATERIALIZED', market };
      }
      return {
        status: 'KNOWN',
        market,
        lanes: rows.map(row => projectLaneReadModel(row, { now: now() })).filter(Boolean),
      };
    },

    async health() {
      const snapshot = await repository.getHealthSnapshot();
      return pickDefined(snapshot, [
        'schemaVersion',
        'serviceVersion',
        'modelVersions',
        'queue',
        'dlq',
        'sourceHealthCounts',
        'newestSuccessfulRunAt',
      ]);
    },
  };
}
