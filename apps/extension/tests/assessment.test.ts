import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  failure,
  isAssessmentData,
  isAssessmentFailure,
  parseScanResponse,
} from "../src/lib/assessment.ts";

const FIXTURES = new URL("../../../packages/contracts/fixtures/", import.meta.url);

function fixture(name: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(readFileSync(new URL(name, FIXTURES), "utf8"));
  assert.ok(typeof parsed === "object" && parsed !== null && !Array.isArray(parsed));
  return parsed as Record<string, unknown>;
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function resultFor(mutate: (scan: Record<string, unknown>) => void) {
  const scan = clone(fixture("scan-result.complete.json"));
  mutate(scan);
  return parseScanResponse(scan);
}

test("parses the complete high-risk fixture", () => {
  const result = parseScanResponse(fixture("scan-result.complete.json"));
  if (!result.ok) {
    assert.fail(result.error.message);
  }

  assert.equal(result.data.status, "complete");
  assert.equal(result.data.band, "high");
  assert.equal(result.data.score, 83);
  assert.equal(result.data.incomplete, false);
  assert.equal(result.data.confidence.coveredWeight, 100);
  assert.equal(result.data.confidence.totalWeight, 100);
  assert.ok(result.data.factors.length > 0);
  assert.ok(result.data.factors.every((factor) => factor.explanation.length > 0));
  assert.equal(result.data.factors[0]?.category, "intel");
  assert.equal(result.data.posture.grade, "D");
});

test("parses the incomplete fixture without inventing a score", () => {
  const result = parseScanResponse(fixture("scan-result.partial.json"));
  if (!result.ok) {
    assert.fail(result.error.message);
  }

  assert.equal(result.data.status, "partial");
  assert.equal(result.data.band, "insufficient_evidence");
  assert.equal(result.data.score, null);
  assert.equal(result.data.incomplete, true);
  assert.equal(result.data.confidence.coveredWeight, 25);
  assert.ok(result.data.confidence.missingEvidence.length > 0);
});

test("reports queued and running results as not ready, never as safe", () => {
  const queued = parseScanResponse(fixture("scan-result.queued.json"));
  assert.equal(queued.ok, false);
  if (queued.ok) {
    throw new Error("queued scans must not be rendered as an assessment");
  }
  assert.equal(queued.error.kind, "not_ready");
  assert.equal(queued.error.retryable, true);

  for (const status of ["queued", "running"]) {
    const result = resultFor((scan) => {
      scan.status = status;
    });
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error.kind, "not_ready");
    }
  }
});

test("reports a failed scan as failed", () => {
  const result = resultFor((scan) => {
    scan.status = "failed";
  });
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.error.kind, "failed");
    assert.equal(result.error.retryable, false);
  }
});

test("reports a missing risk object as no_risk", () => {
  for (const risk of [null, undefined]) {
    const result = resultFor((scan) => {
      scan.risk = risk;
    });
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error.kind, "no_risk");
    }
  }
});

test("rejects structurally malformed responses", () => {
  for (const value of [null, [], "complete", 42]) {
    const result = parseScanResponse(value);
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error.kind, "malformed");
    }
  }

  const cases: Array<[string, (scan: Record<string, unknown>) => void]> = [
    ["unknown status", (scan) => (scan.status = "done")],
    ["missing scan id", (scan) => delete scan.scan_id],
    ["empty scan id", (scan) => (scan.scan_id = "")],
    ["numeric score", (scan) => ((scan.risk as Record<string, unknown>).score = "83")],
    ["unknown band", (scan) => ((scan.risk as Record<string, unknown>).band = "danger")],
    [
      "null score with scored band",
      (scan) => ((scan.risk as Record<string, unknown>).score = null),
    ],
    [
      "scored insufficient evidence",
      (scan) => ((scan.risk as Record<string, unknown>).band = "insufficient_evidence"),
    ],
    ["missing verdict", (scan) => delete (scan.risk as Record<string, unknown>).verdict],
    ["missing incomplete flag", (scan) => delete (scan.risk as Record<string, unknown>).incomplete],
    [
      "coverage above total",
      (scan) =>
        ((scan.risk as Record<string, unknown>).confidence = {
          ...((scan.risk as Record<string, unknown>).confidence as Record<string, unknown>),
          covered_weight: 120,
        }),
    ],
    [
      "likelihood without band",
      (scan) => ((scan.risk as Record<string, unknown>).likelihood = { score: 0.4 }),
    ],
    [
      "likelihood insufficient evidence",
      (scan) =>
        ((scan.risk as Record<string, unknown>).likelihood = {
          ...((scan.risk as Record<string, unknown>).likelihood as Record<string, unknown>),
          band: "insufficient_evidence",
        }),
    ],
    [
      "invalid posture grade",
      (scan) =>
        ((scan.risk as Record<string, unknown>).posture = {
          ...((scan.risk as Record<string, unknown>).posture as Record<string, unknown>),
          grade: "Z",
        }),
    ],
    [
      "factors not an array",
      (scan) => ((scan.risk as Record<string, unknown>).factors = "none"),
    ],
  ];

  for (const [label, mutate] of cases) {
    const result = resultFor(mutate);
    assert.equal(result.ok, false, label);
    if (!result.ok) {
      assert.equal(result.error.kind, "malformed", label);
    }
  }
});

test("sanitizes backend text before it reaches the view", () => {
  const result = resultFor((scan) => {
    const risk = scan.risk as Record<string, unknown>;
    risk.verdict = "High\u0000 risk\u0007 notice";
  });
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.data.verdict, "High risk notice");
  }

  const long = resultFor((scan) => {
    (scan.risk as Record<string, unknown>).verdict = "a".repeat(500);
  });
  assert.equal(long.ok, true);
  if (long.ok) {
    assert.equal(long.data.verdict.length, 280);
    assert.ok(long.data.verdict.endsWith("..."));
  }
});

test("skips invalid factors and caps the rendered reason count", () => {
  const skipped = resultFor((scan) => {
    const risk = scan.risk as Record<string, unknown>;
    risk.factors = [...(risk.factors as unknown[]), { reason_code: "broken" }];
  });
  assert.equal(skipped.ok, true);
  if (skipped.ok) {
    const base = fixture("scan-result.complete.json").risk as Record<string, unknown>;
    assert.equal(skipped.data.factors.length, (base.factors as unknown[]).length);
  }

  const capped = resultFor((scan) => {
    const risk = scan.risk as Record<string, unknown>;
    const template = (risk.factors as unknown[])[0] as Record<string, unknown>;
    risk.factors = Array.from({ length: 60 }, (_value, index) => ({
      ...template,
      reason_code: `factor_${index}`,
    }));
  });
  assert.equal(capped.ok, true);
  if (capped.ok) {
    assert.equal(capped.data.factors.length, 50);
  }
});

test("isAssessmentData validates the parsed view model", () => {
  const parsed = parseScanResponse(fixture("scan-result.complete.json"));
  assert.equal(parsed.ok, true);
  if (!parsed.ok) {
    return;
  }
  assert.equal(isAssessmentData(parsed.data), true);

  const mutated = [...parsed.data.factors];
  assert.equal(
    isAssessmentData({ ...parsed.data, band: "danger", factors: mutated }),
    false,
  );
  assert.equal(isAssessmentData({ ...parsed.data, score: 101 }), false);
  assert.equal(isAssessmentData(null), false);
});

test("isAssessmentFailure accepts only well-formed failures", () => {
  assert.equal(isAssessmentFailure(failure("timeout", "timed out", true)), true);
  assert.equal(
    isAssessmentFailure(failure("rate_limited", "slow down", true, 429, "rate_limited")),
    true,
  );
  assert.equal(isAssessmentFailure({ kind: "unknown", message: "x", retryable: true }), false);
  assert.equal(isAssessmentFailure({ kind: "timeout", message: "", retryable: true }), false);
  assert.equal(isAssessmentFailure({ kind: "timeout", message: "x", retryable: "yes" }), false);
  assert.equal(
    isAssessmentFailure({ kind: "timeout", message: "x", retryable: true, code: "nope" }),
    false,
  );
});
