import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { augmentModelProjection, readEliLaneContext } from "../eli-client.mjs";

function envelope() {
  return {
    facts: {
      originMarket: "ATL",
      destinationMarket: "DTW",
      loadedMiles: 720,
      deadheadMiles: 25,
    },
    canonicalSnapshot: {
      trueRpm: 1.61,
      grade: "B",
      verdict: "ACCEPT",
      baselineBid: 1150,
      marketBid: 1200,
      authorityVersion: "24.0.56",
    },
  };
}

export async function runEliIntegrationTests() {
  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    try {
      await fn();
      passed += 1;
      console.log(`PASS ${name}`);
    } catch (error) {
      failed += 1;
      console.error(`FAIL ${name} - ${error?.stack || error}`);
    }
  }

  await test("E01 Agent sends only canonical markets to private ELI RPC", async () => {
    let input = null;
    const env = {
      ELI: {
        async getLaneIntelligence(value) {
          input = value;
          return {
            status: "KNOWN",
            intelligence: {
              originMarket: "ATL",
              destinationMarket: "DTW",
              structuralScore: 0.71,
              expediteRelevance: null,
              structuralConfidence: 0.82,
              expediteConfidence: null,
              freshness: { STRUCTURAL_OD: "FRESH" },
              unknownFlags: ["EQUIPMENT_RELEVANCE_UNRESOLVED"],
              conflictFlags: [],
              evidenceCounts: { STRUCTURAL_OD: 12 },
              latestEvidenceAt: "2026-09-30T00:00:00Z",
              stage: "Pilot Candidate",
              modelRunId: "run-eli-1",
              governanceFingerprint: "gov-1",
              updatedAt: "2026-09-30T20:00:00Z",
              rate: 9000,
              rawEvidence: "must-not-pass",
            },
          };
        },
      },
    };

    const result = await readEliLaneContext(env, envelope());
    assert.deepEqual(input, { originMarket: "ATL", destinationMarket: "DTW" });
    assert.equal(result.status, "KNOWN");
    assert.equal(result.intelligence.stage, "Pilot Candidate");
    assert.equal("rate" in result.intelligence, false);
    assert.equal("rawEvidence" in result.intelligence, false);
  });

  await test("E02 missing ELI binding is non-fatal and explicit", async () => {
    assert.deepEqual(await readEliLaneContext({}, envelope()), {
      status: "UNAVAILABLE",
      reason: "ELI_BINDING_UNAVAILABLE",
      originMarket: "ATL",
      destinationMarket: "DTW",
    });
  });

  await test("E03 ELI RPC failure is non-fatal and explicit", async () => {
    const env = {
      ELI: {
        async getLaneIntelligence() {
          throw new Error("temporary failure");
        },
      },
    };
    assert.deepEqual(await readEliLaneContext(env, envelope()), {
      status: "UNAVAILABLE",
      reason: "ELI_REQUEST_FAILED",
      originMarket: "ATL",
      destinationMarket: "DTW",
    });
  });

  await test("E04 missing canonical markets stays UNKNOWN instead of inventing geography", async () => {
    const env = { ELI: { async getLaneIntelligence() { throw new Error("must not call"); } } };
    const result = await readEliLaneContext(env, { facts: { originMarket: "ATL" } });
    assert.deepEqual(result, {
      status: "UNKNOWN",
      reason: "CANONICAL_MARKETS_REQUIRED",
      originMarket: "ATL",
      destinationMarket: null,
    });
  });

  await test("E05 ELI augmentation cannot change canonical FreightLogic economics", () => {
    const base = {
      facts: envelope().facts,
      canonicalSnapshot: envelope().canonicalSnapshot,
    };
    const context = {
      status: "KNOWN",
      intelligence: {
        originMarket: "ATL",
        destinationMarket: "DTW",
        stage: "Pilot Candidate",
        unknownFlags: ["EXPOSURE_DENOMINATOR_MISSING"],
      },
    };
    const augmented = augmentModelProjection(base, context);
    assert.deepEqual(augmented.canonicalSnapshot, base.canonicalSnapshot);
    assert.deepEqual(augmented.eli, context);
    assert.notEqual(augmented, base);
  });

  await test("E06 Agent worker enriches only the model projection and keeps canonical output guard authority", async () => {
    const source = await readFile(new URL("../worker.mjs", import.meta.url), "utf8");
    assert.match(source, /readEliLaneContext/);
    assert.match(source, /augmentModelProjection/);
    assert.match(source, /runExplanationModel\(this\.env,\s*route\.tier,\s*projection\)/);
    assert.match(source, /assertSafeRecommendation\(result\.recommendation,\s*envelope\.canonicalSnapshot\)/);
  });

  await test("E07 Wrangler binds ELI privately while Agent stays internet-dark and disabled", async () => {
    const config = JSON.parse(await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
    assert.equal(config.vars.AGENT_ENABLED, "false");
    assert.equal(config.workers_dev, false);
    assert.equal(config.preview_urls, false);
    assert.equal("routes" in config, false);
    assert.equal("route" in config, false);
    assert.ok(config.services.some((service) => service.binding === "ELI" && service.service === "freightlogic-eli-runtime-v1"));
  });

  console.log(`\nELI INTEGRATION TOTAL: ${passed} passed, ${failed} failed`);
  if (failed > 0) throw new Error(`${failed} Agent/ELI integration test(s) failed`);
}
