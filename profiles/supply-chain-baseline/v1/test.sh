#!/usr/bin/env bash
# Runs the policy tests with the pinned OPA (v1.22.0) in Docker.
set -euo pipefail
cd "$(dirname "$0")"
docker run --rm --platform "linux/$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" -v "$PWD:/p" -w /p \
  openpolicyagent/opa@sha256:895872de1e8dc5b82e04f9410d2d1ada2f72d28fdcdba0e8789d91cfc27ec0d0 \
  test --v0-compatible=false "$@" policy.rego policy_test.rego fixtures/inputs
