#!/usr/bin/env bash
# Runs the policy tests with the pinned OPA in Docker (the image pinned in Supply-Chain Baseline's tools.json).
set -euo pipefail
cd "$(dirname "$0")"
docker run --rm --platform "linux/$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" -v "$PWD:/p" -w /p \
  "$(jq -r .opa.image ../../supply-chain-baseline/v1/tools.json)" \
  test --v0-compatible=false "$@" policy.rego policy_test.rego
