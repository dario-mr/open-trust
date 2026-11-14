# Open Trust (POC)

**This exact artifact was assessed using this exact methodology. These checks produced these results. The evidence is intact. These are the trust assumptions.** All of it is verifiable offline by a customer who never sees the vendor's source.

`otrust` runs in the vendor's CI. It scans an OCI image and its source with pinned tools (Syft, Trivy, Semgrep), evaluates a versioned policy ([Supply-Chain Baseline v1](profiles/supply-chain-baseline/v1/profile.md)), and signs the result as a Sigstore bundle. The bundle carries an in-toto statement with a SLSA VSA predicate. The evidence stays with the vendor; the certificate holds only its digests.

> Proof of concept. It proves what was checked, not that software is secure, and it is vendor-attested: see the trust levels in [poc-plan.md](poc-plan.md) §3 and the limitations listed in every certificate.

## Verify the demo yourself

The vendor side lives in a separate repository, **[dario-mr/open-trust-demo](https://github.com/dario-mr/open-trust-demo)**. It is a Spring Boot app, built clean and with log4j 2.14.1. Its workflow can only *call* this repository's reusable [`assess.yml`](.github/workflows/assess.yml), pinned by commit. It can't add steps to it. So the signature proves the assessment ran unmodified, at trust level `L1+isolated-assessor`. The demo repository's README has the exact verify commands.

## Use it

| | |
|---|---|
| Key-signed (`L1`), any CI | `otrust keygen --out vendor` then `otrust assess --key vendor.key --image img.oci.tar --source .` |
| Keyless (`L1+ci-identity`), GitHub Actions or any CI exposing `SIGSTORE_ID_TOKEN` | `otrust assess --keyless --image img.oci.tar --source .` |
| Reusable workflow (GitHub), `L1+isolated-assessor` when called from another repository | `uses: dario-mr/open-trust/.github/workflows/assess.yml@<sha>` (see the header of [assess.yml](.github/workflows/assess.yml)) |
| Customer | `otrust verify cert.sigstore.json --image img.oci.tar --trust-policy trust.yaml [--trusted-root root.json] [--evidence dir] [--revocations file]` |

The scanners run in pinned containers, so Docker is required on the assessing side.

## Repository

`cmd/otrust` · `internal/` (subject, ci, adapters, policy, statement, signer, trustlevel, verify) · `profiles/supply-chain-baseline/v1` (spec, Rego policy, real-output fixtures) · [poc-plan.md](poc-plan.md) · [research/](research/)
