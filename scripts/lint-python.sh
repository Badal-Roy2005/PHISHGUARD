#!/usr/bin/env bash
# Python lint across every independently deployable project.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for project in packages/contracts services/analysis services/ml; do
  echo "==> ruff: ${project}"
  (cd "${ROOT}/${project}" && uv run --frozen ruff check .)
done
