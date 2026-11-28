# Agent rules for this repository

- **No backward compatibility.** This is a greenfield project with no users. Change formats, flags, policies and profile versions freely, and delete old code paths instead of keeping them alongside the new ones: no frozen old policies, no legacy formats, no migration shims.
- **No co-author trailers.** Commit messages must not contain a `Co-Authored-By:` line (or any other AI attribution trailer).

## Working here

- Build and test: `go test ./...`. Policy tests (pinned OPA in docker): `profiles/supply-chain-baseline/v1/test.sh` and `profiles/quality-baseline/v1/test.sh`. CI also runs the end-to-end tests with the real scanners: `profiles/supply-chain-baseline/v1/fixtures/generate.sh` then `OTRUST_E2E=1 go test -count=1 ./internal/assess/ ./internal/verify/` (needs docker; `generate.sh` rewrites the tracked fixture inputs, so restore them unless the change is intended).
- Profiles: `profiles/supply-chain-baseline/v1` and `profiles/quality-baseline/v1`, each a `policy.rego` (with `policy_test.rego`) and a `profile.md` (the spec), registered in `profiles/profiles.go`. One scan, one certificate per profile. The scanner pins (`tools.json`) live with Supply-Chain Baseline.
- Each release assesses otrust itself, with this repository's own exceptions in `.otrust/exceptions.yaml`. A release whose self-assessment fails has no certificate: fix the finding or add a narrow, per-file exception with a reason.
- Release with `scripts/release.sh <version>`: it bumps the version, tags, waits for the release workflow (including the self-assessment), re-pins the CI templates and the demo repository, waits for the demo pipelines and records the demos. `scripts/release_test.sh` replays a past release to check its pin rewriting. Docs name no "needs otrust vX+" minimums: there is no compatibility to describe.
- End-to-end demos: `demo/scenarios.sh` (buyer side), `demo/jenkins/run.sh`, `demo/attacks/run.sh`, `demo/kms/vault.sh`. Their `RESULTS.txt` files are recorded runs.
