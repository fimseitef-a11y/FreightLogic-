import { classifyPrivacy } from "./contracts.mjs";

const REQUIRED_CANONICAL = ["trueRpm", "grade", "verdict", "authorityVersion"];

export function chooseModelTier(envelope, settings = {}) {
  if (settings.enabled !== true) {
    return { tier: "no-model", reason: "FEATURE_DISABLED" };
  }

  const privacy = classifyPrivacy(envelope);
  if (privacy === "RESTRICTED") {
    return { tier: "no-model", reason: "PRIVACY_RESTRICTED" };
  }
  if (privacy === "UNKNOWN") {
    return { tier: "no-model", reason: "PRIVACY_UNKNOWN" };
  }

  if (envelope.intent === "canonical") {
    return { tier: "no-model", reason: "DETERMINISTIC_INTENT" };
  }

  const snapshot = envelope.canonicalSnapshot || {};
  if (REQUIRED_CANONICAL.some((field) => snapshot[field] === undefined || snapshot[field] === null)) {
    return { tier: "no-model", reason: "CANONICAL_SNAPSHOT_INCOMPLETE" };
  }

  if (envelope.intent !== "explain") {
    return { tier: "no-model", reason: "UNSUPPORTED_INTENT" };
  }

  if (envelope.confidence >= 0.8) {
    return { tier: "small", reason: "EXPLANATION_HIGH_CONFIDENCE" };
  }

  if (envelope.confidence >= 0.45) {
    return { tier: "strong", reason: "EXPLANATION_AMBIGUOUS" };
  }

  return { tier: "no-model", reason: "LOW_CONFIDENCE_FAIL_CLOSED" };
}
