# Agent rules for this repository

- **No backward compatibility.** This is a greenfield project with no users. Change formats, flags, policies and profile versions freely, and delete old code paths instead of keeping them alongside the new ones: no frozen old policies, no legacy formats, no migration shims.
- **No co-author trailers.** Commit messages must not contain a `Co-Authored-By:` line (or any other AI attribution trailer).

## Working here

- Build and test: `go test ./...`. Policy tests (pinned OPA in docker): `profiles/supply-chain-baseline/v1/test.sh`.
- The profile is `profiles/supply-chain-baseline/v1`: `policy.rego` (with `policy_test.rego`), `tools.json` (scanner pins), `profile.md` (the spec).
- Each release assesses otrust itself, with this repository's own exceptions in `.otrust/exceptions.yaml`. A release whose self-assessment fails has no certificate: fix the finding or add a narrow, per-file exception with a reason.
- End-to-end demos: `demo/scenarios.sh` (buyer side), `demo/jenkins/run.sh`, `demo/attacks/run.sh`, `demo/kms/vault.sh`. Their `RESULTS.txt` files are recorded runs.
