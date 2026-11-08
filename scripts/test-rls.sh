#!/usr/bin/env bash
# Run the M8 RLS suite against a disposable local/test Supabase database.
# Never point RLS_TEST_DB_URL at production.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if [[ "${ENV:-development}" == "production" ]]; then
  echo "refusing to run RLS tests with ENV=production" >&2
  exit 1
fi

if [[ -z "${RLS_TEST_DB_URL:-}" ]]; then
  echo "RLS_TEST_DB_URL is not set; skipping disposable-database RLS tests"
  exit 0
fi

if ! command -v psql >/dev/null 2>&1; then
  echo "psql is not installed; cannot run RLS tests" >&2
  exit 1
fi

psql "${RLS_TEST_DB_URL}" -v ON_ERROR_STOP=1 -f supabase/tests/m8_rls.sql
