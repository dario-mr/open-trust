# Open Trust (POC)

**This exact artifact was assessed using this exact methodology. These checks produced these results. The evidence is intact. These are the trust assumptions.** All of it is verifiable offline by a customer who never sees the vendor's source.

`otrust` runs in the vendor's CI. It scans an OCI image and its source with pinned tools (Syft, Trivy, Semgrep), evaluates a versioned policy ([Supply-Chain Baseline v1](profiles/supply-chain-baseline/v1/profile.md)), and signs the result as a Sigstore bundle. The bundle carries an in-toto statement with a SLSA VSA predicate. The evidence stays with the vendor; the certificate holds only its digests.

> Proof of concept. It proves what was checked, not that software is secure, and it is vendor-attested: see the trust levels in [poc-plan.md](poc-plan.md) §3 and the limitations listed in every certificate.

## Verify the demo yourself

The [`demo`](.github/workflows/demo.yml) workflow builds a Spring Boot image twice: clean, and with log4j 2.14.1. It assesses each one with the reusable [`assess.yml`](.github/workflows/assess.yml) and signs keyless with the workflow's GitHub OIDC identity.

```bash
go build -o otrust ./cmd/otrust
gh run download <run-id> -n demo-clean -n otrust-demo-clean   # image + certificate + evidence
./otrust verify otrust-demo-clean/certificate.sigstore.json \
  --image demo-clean/image.oci.tar \
  --trust-policy examples/spring-boot-demo/trust.yaml \
  --trusted-root internal/verify/testdata/public-good-trusted-root.json \
  --evidence otrust-demo-clean
```

`VERIFIED` (exit 0). The vulnerable image gives `ASSESSMENT_FAILED` (exit 10) with the Log4Shell CVEs listed. Any other image gives `ARTIFACT_MISMATCH` (exit 14). A trust policy that demands an isolated assessor gives `TRUST_LEVEL_TOO_LOW` (exit 13), because this demo's caller is in the same repository.

## Use it

| | |
|---|---|
| Key-signed (`L1`), any CI | `otrust keygen --out vendor` then `otrust assess --key vendor.key --image img.oci.tar --source .` |
| Keyless (`L1+ci-identity`), GitHub Actions or any CI exposing `SIGSTORE_ID_TOKEN` | `otrust assess --keyless --image img.oci.tar --source .` |
| Reusable workflow (GitHub) | `uses: dario-mr/open-trust/.github/workflows/assess.yml@<sha>` (see the header of [assess.yml](.github/workflows/assess.yml)) |
| Customer | `otrust verify cert.sigstore.json --image img.oci.tar --trust-policy trust.yaml [--trusted-root root.json] [--evidence dir] [--revocations file]` |

The scanners run in pinned containers, so Docker is required on the assessing side.

## Repository

`cmd/otrust` · `internal/` (subject, ci, adapters, policy, statement, signer, trustlevel, verify) · `profiles/supply-chain-baseline/v1` (spec, Rego policy, real-output fixtures) · `examples/spring-boot-demo` · [poc-plan.md](poc-plan.md) · [research/](research/)
