import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { parseScanResponse, type AssessmentData } from "../src/lib/assessment.ts";
import { buildAssessmentView, bandLabel, HEURISTIC_NOTICE } from "../src/lib/view.ts";

const FIXTURES = new URL("../../../packages/contracts/fixtures/", import.meta.url);

function fixture(name: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(readFileSync(new URL(name, FIXTURES), "utf8"));
  assert.ok(typeof parsed === "object" && parsed !== null && !Array.isArray(parsed));
  return parsed as Record<string, unknown>;
}

function assessment(mutate?: (risk: Record<string, unknown>) => void): AssessmentData {
  const scan = structuredClone(fixture("scan-result.complete.json"));
  const risk = scan.risk as Record<string, unknown>;
  if (mutate) {
    mutate(risk);
  }
  const parsed = parseScanResponse(scan);
  if (!parsed.ok) {
    assert.fail(parsed.error.message);
  }
  return parsed.data;
}

test("high-risk evidence is labelled as high risk, not as safe", () => {
  const view = buildAssessmentView(assessment());
  assert.equal(view.state, "high_risk");
  assert.equal(view.headline, "High-risk evidence");
  assert.equal(view.bandLabel, "High");
  assert.equal(view.score, 83);
  assert.equal(view.partial, false);
  assert.equal(view.heuristicNotice, HEURISTIC_NOTICE);
  assert.ok(view.reasons.length > 0);
  assert.ok(view.reasons.length <= 4);
  assert.ok(view.likelihoodLabel.includes("Critical"));
  assert.ok(view.postureLabel.includes("Grade D"));
  assert.ok(view.coverageLabel.includes("100/100"));
});

test("low risk is worded as observed risk, with no safety guarantee", () => {
  const view = buildAssessmentView(
    assessment((risk) => {
      risk.band = "low";
      risk.score = 5;
      risk.verdict = "Low risk.";
      risk.factors = [];
      risk.likelihood = { score: 0.05, band: "low", contributions: [] };
    }),
  );

  assert.equal(view.state, "low");
  assert.equal(view.headline, "Low observed risk");
  assert.equal(view.bandLabel, "Low");
  assert.equal(view.score, 5);
  assert.equal(view.partial, false);
  assert.equal(view.reasons.length, 1);
  assert.ok(view.reasons[0]?.includes("No high-risk indicators"));
  assert.ok(view.heuristicNotice.includes("not a guarantee"));
});

test("guarded and suspicious bands map to their own states", () => {
  const guarded = buildAssessmentView(
    assessment((risk) => {
      risk.band = "guarded";
      risk.score = 30;
      risk.factors = [];
    }),
  );
  assert.equal(guarded.state, "caution");
  assert.equal(guarded.headline, "Some caution indicators");
  assert.equal(guarded.bandLabel, "Guarded");

  const suspicious = buildAssessmentView(
    assessment((risk) => {
      risk.band = "suspicious";
      risk.score = 55;
      risk.factors = [];
    }),
  );
  assert.equal(suspicious.state, "suspicious");
  assert.equal(suspicious.headline, "Suspicious characteristics");
  assert.equal(suspicious.bandLabel, "Suspicious");
});

test("incomplete coverage is explicit and never becomes a score", () => {
  const parsed = parseScanResponse(fixture("scan-result.partial.json"));
  assert.equal(parsed.ok, true);
  if (!parsed.ok) {
    return;
  }

  const view = buildAssessmentView(parsed.data);
  assert.equal(view.state, "incomplete");
  assert.equal(view.headline, "Incomplete assessment");
  assert.equal(view.score, null);
  assert.equal(view.partial, true);
  assert.ok(view.coverageLabel.includes("missing evidence is not safe"));
  assert.ok(view.coverageLabel.includes("partial"));
  assert.ok(view.missing.length > 0);
  assert.ok(view.missing.length <= 5);
});

test("partial scan status is surfaced even when a score exists", () => {
  const scan = structuredClone(fixture("scan-result.complete.json"));
  scan.status = "partial";
  const parsed = parseScanResponse(scan);
  assert.equal(parsed.ok, true);
  if (!parsed.ok) {
    return;
  }

  const view = buildAssessmentView(parsed.data);
  assert.equal(view.partial, true);
  assert.ok(view.coverageLabel.includes("Scan status: partial."));
});

test("missing evidence is truncated to five user-facing entries", () => {
  const view = buildAssessmentView(
    assessment((risk) => {
      (risk.confidence as Record<string, unknown>).missing_evidence = [
        "a",
        "b",
        "c",
        "d",
        "e",
        "f",
        "g",
      ];
      (risk.confidence as Record<string, unknown>).incomplete = true;
    }),
  );

  assert.equal(view.state, "high_risk");
  assert.equal(view.partial, true);
  assert.deepEqual(view.missing, ["a", "b", "c", "d", "e"]);
});

test("band labels are exhaustive for every contract band", () => {
  assert.equal(bandLabel("low"), "Low");
  assert.equal(bandLabel("guarded"), "Guarded");
  assert.equal(bandLabel("suspicious"), "Suspicious");
  assert.equal(bandLabel("high"), "High");
  assert.equal(bandLabel("critical"), "Critical");
  assert.equal(bandLabel("insufficient_evidence"), "Insufficient evidence");
});
