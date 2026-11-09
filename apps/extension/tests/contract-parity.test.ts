import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CONTRACT_VERSION,
  ENGINE_STATUSES as CONTRACT_ENGINE_STATUSES,
  ERROR_CODES as CONTRACT_ERROR_CODES,
  RISK_BANDS as CONTRACT_RISK_BANDS,
  SCAN_STATUSES as CONTRACT_SCAN_STATUSES,
  SEVERITIES as CONTRACT_SEVERITIES,
} from "@phishguard/contracts";

import {
  ENGINE_STATUSES,
  ERROR_CODES,
  RISK_BANDS,
  SCAN_STATUSES,
  SEVERITIES,
  SUPPORTED_CONTRACT_VERSION,
} from "../src/lib/assessment.ts";

test("the extension supports the current contract version", () => {
  assert.equal(SUPPORTED_CONTRACT_VERSION, CONTRACT_VERSION);
});

test("enum copies stay in lockstep with @phishguard/contracts", () => {
  assert.deepEqual([...SCAN_STATUSES], [...CONTRACT_SCAN_STATUSES]);
  assert.deepEqual([...ENGINE_STATUSES], [...CONTRACT_ENGINE_STATUSES]);
  assert.deepEqual([...SEVERITIES], [...CONTRACT_SEVERITIES]);
  assert.deepEqual([...RISK_BANDS], [...CONTRACT_RISK_BANDS]);
  assert.deepEqual([...ERROR_CODES], [...CONTRACT_ERROR_CODES]);
});
