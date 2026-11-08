#!/usr/bin/env bash
# Python tests across every independently deployable project.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for project in packages/contracts services/analysis services/ml; do
  echo "==> pytest: ${project}"
  (cd "${ROOT}/${project}" && uv run --frozen pytest)
done
