const LANE_INTELLIGENCE_FIELDS = Object.freeze([
  "originMarket",
  "destinationMarket",
  "structuralScore",
  "expediteRelevance",
  "structuralConfidence",
  "expediteConfidence",
  "freshness",
  "unknownFlags",
  "conflictFlags",
  "evidenceCounts",
  "latestEvidenceAt",
  "stage",
  "modelRunId",
  "governanceFingerprint",
  "updatedAt",
]);

function projectLaneIntelligence(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const projected = {};
  for (const key of LANE_INTELLIGENCE_FIELDS) {
    if (value[key] !== undefined) projected[key] = value[key];
  }
  return projected;
}

export async function readEliLaneContext(env, envelope) {
  const originMarket = envelope?.facts?.originMarket ?? null;
  const destinationMarket = envelope?.facts?.destinationMarket ?? null;

  if (!originMarket || !destinationMarket) {
    return {
      status: "UNKNOWN",
      reason: "CANONICAL_MARKETS_REQUIRED",
      originMarket,
      destinationMarket,
    };
  }

  const binding = env?.ELI;
  if (!binding || typeof binding.getLaneIntelligence !== "function") {
    return {
      status: "UNAVAILABLE",
      reason: "ELI_BINDING_UNAVAILABLE",
      originMarket,
      destinationMarket,
    };
  }

  let result;
  try {
    result = await binding.getLaneIntelligence({ originMarket, destinationMarket });
  } catch {
    return {
      status: "UNAVAILABLE",
      reason: "ELI_REQUEST_FAILED",
      originMarket,
      destinationMarket,
    };
  }

  if (result?.status !== "KNOWN") {
    return {
      status: result?.status === "UNKNOWN" ? "UNKNOWN" : "UNAVAILABLE",
      reason: result?.reason ?? "ELI_RESULT_UNAVAILABLE",
      originMarket,
      destinationMarket,
    };
  }

  const intelligence = projectLaneIntelligence(result.intelligence);
  if (!intelligence) {
    return {
      status: "UNAVAILABLE",
      reason: "ELI_INVALID_RESPONSE",
      originMarket,
      destinationMarket,
    };
  }

  return { status: "KNOWN", intelligence };
}

export function augmentModelProjection(projection, eliContext) {
  if (!projection || typeof projection !== "object" || Array.isArray(projection)) {
    throw new TypeError("model projection must be an object");
  }
  return {
    ...projection,
    eli: eliContext ?? {
      status: "UNAVAILABLE",
      reason: "ELI_CONTEXT_UNAVAILABLE",
    },
  };
}
