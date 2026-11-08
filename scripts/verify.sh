#!/usr/bin/env bash
# Full verification. Any failing step aborts with a non-zero exit code.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

echo "==> versions"
node --version
pnpm --version
python3 --version
uv --version

echo "==> dependencies (node)"
pnpm install --frozen-lockfile

echo "==> dependencies (python)"
for project in packages/contracts services/analysis services/ml; do
  (cd "${project}" && uv sync --frozen)
done

echo "==> typecheck (typescript)"
pnpm typecheck

echo "==> lint (python)"
bash scripts/lint-python.sh

echo "==> lint (typescript)"
pnpm lint

echo "==> test (python)"
bash scripts/test-python.sh

echo "==> test (typescript)"
pnpm test

echo "==> build (next)"
pnpm build

echo "==> verify: OK"
