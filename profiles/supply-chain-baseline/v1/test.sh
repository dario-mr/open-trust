#!/usr/bin/env bash
# Runs the policy tests with the pinned OPA (v1.22.0) in Docker.
set -euo pipefail
cd "$(dirname "$0")"
docker run --rm --platform "linux/$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" -v "$PWD:/p" -w /p \
  "$(jq -r .opa.image tools.json)" \
  test --v0-compatible=false "$@" policy.rego policy_test.rego fixtures/inputs
