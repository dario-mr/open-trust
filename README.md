# Open Trust (POC)

**This exact artifact was assessed using this exact methodology. These checks produced these results. The evidence is intact. These are the trust assumptions.** All of it is verifiable offline by a customer who never sees the vendor's source.

`otrust` runs in the vendor's CI. It scans an OCI image and its source with pinned tools (Syft, Trivy, Semgrep), evaluates a versioned policy ([Supply-Chain Baseline v1](profiles/supply-chain-baseline/v1/profile.md)), and signs the result as a Sigstore bundle. The bundle carries an in-toto statement with a SLSA VSA predicate. The evidence stays with the vendor; the certificate holds only its digests.

> **Buyers:** start with the [consumer guide](docs/consumer-guide.md). The POC result is in [research/g1-go-no-go.md](research/g1-go-no-go.md), and a recorded buyer-side demo is in [demo/RESULTS.txt](demo/RESULTS.txt).

> Proof of concept. It proves what was checked, not that software is secure, and it is vendor-attested: see the trust levels in [poc-plan.md](poc-plan.md) §3 and the limitations listed in every certificate.

## Verify the demo yourself

The vendor side lives in a separate repository, **[dario-mr/open-trust-demo](https://github.com/dario-mr/open-trust-demo)**. It is a Spring Boot app, built clean and with log4j 2.14.1. Its workflow can only *call* this repository's reusable [`assess.yml`](.github/workflows/assess.yml), pinned by commit. It can't add steps to it. So the signature proves the assessment ran unmodified, at trust level `L1+isolated-assessor`. The same demo also runs on **[GitLab](https://gitlab.com/dario-mr/open-trust-demo)** through the GitLab template, where the honest level is `L1+ci-identity`. The demo repository's README has the exact verify commands.

## Use it

| | |
|---|---|
| Key-signed (`L1`), any CI | `otrust keygen --out vendor` then `otrust assess --key vendor.key --image img.oci.tar --source .`. `--key` also takes a KMS key (`awskms://`, `gcpkms://`, `azurekms://`, `hashivault://`); `otrust pubkey --key <uri>` exports the public key. **Private repositories:** use this, not keyless, which publishes the repository name in Sigstore's public log ([guide](docs/private-repositories.md)). |
| Jenkins, Azure DevOps, any other CI | [`ci-templates/generic/otrust-assess.sh`](ci-templates/generic/otrust-assess.sh) downloads a pinned release, checks its digest and signs with a key from the CI's secret store. Examples: [Jenkinsfile](ci-templates/jenkins/Jenkinsfile) (run for real in a local Jenkins: [demo/jenkins](demo/jenkins/run.sh)), [Azure Pipelines](ci-templates/azure-devops/azure-pipelines.yml) (not yet run on Azure). |
| Keyless (`L1+ci-identity`), GitHub Actions, GitLab CI (`ci-templates/gitlab/otrust.gitlab-ci.yml`), or any CI exposing `SIGSTORE_ID_TOKEN` | `otrust assess --keyless --image img.oci.tar --source .` |
| Reusable workflow (GitHub), `L1+isolated-assessor` when called from another repository | `uses: dario-mr/open-trust/.github/workflows/assess.yml@<sha>` with `image-ref: ghcr.io/acme/svc@sha256:…` or an image artifact (see the header of [assess.yml](.github/workflows/assess.yml)) |
| Vendor, attach to the image | `otrust assess … --attach` (registry image), or `otrust attach cert.sigstore.json --image name@sha256:…` afterwards: the certificate is stored on the image as an OCI referrer |
| Customer | `otrust verify [cert.sigstore.json] --image img.oci.tar --trust-policy trust.yaml [--trusted-root root.json] [--evidence dir] [--revocations file] [--online] [--recheck] [--previous old.json] [--report report.md]` |

`--image` takes an OCI layout (directory or tar) or a registry reference pinned by digest (`ghcr.io/acme/svc@sha256:…`). A tag is refused, because it can move. Registry credentials come from the Docker config. Verifying by reference pulls the image, so for fully offline verification pass a local layout.

The scanners run in pinned containers, so Docker is needed on the assessing side, and on the buyer's side for `--recheck`. Without Docker, `--scanners local` runs Syft and Trivy from their release archives, pinned by sha256 in [`tools.json`](profiles/supply-chain-baseline/v1/tools.json), and Semgrep from PATH at the pinned version (recorded as such in the certificate); `verify --recheck --scanners local` needs no Semgrep, so it is fully pinned. `--recheck`, which re-runs the image scanners and compares the results with the certificate ([consumer guide](docs/consumer-guide.md#re-check-dont-take-the-vendors-word-for-the-image)).

**Releases.** [`release.yml`](.github/workflows/release.yml) builds `otrust` on a version tag and attests its build provenance. Check a downloaded binary with `gh attestation verify otrust-linux-amd64 -R dario-mr/open-trust`. The assessors build `otrust` the same way, so a certificate's `agentDigest` is the digest of the released linux/amd64 binary for that revision. Each release also publishes `ghcr.io/dario-mr/otrust` (for running `verify` in CI) and assesses that image with this repository's own assessor: the certificate and evidence are release assets (`otrust-image.*`), at `L1+ci-identity`, since the assessor and the source share a repository. The certificate is also attached to the image, so no file is needed: `otrust verify --image ghcr.io/dario-mr/otrust@<digest of the tag> --trust-policy trust/otrust-image.trust.yaml --online` (policy: [`trust/otrust-image.trust.yaml`](trust/otrust-image.trust.yaml)).

**Revocation.** [`trust/revocations.json`](trust/revocations.json) lists revoked artifacts, `otrust` binaries (by digest) and signers. [`revocations.yml`](.github/workflows/revocations.yml) signs it, re-signs it weekly and publishes it as an asset of the [`revocations`](https://github.com/dario-mr/open-trust/releases/tag/revocations) release. `verify --online` fetches that list, accepts it only if this workflow signed it on `main`, and only until it expires 14 days later. Without `--trusted-root`, `--online` also fetches Sigstore's trusted root through TUF; those are the only network calls `verify` makes besides pulling an image by reference. Without `--online`, verification runs fully offline: `--revocations` takes a downloaded signed list or your own plain list.

**Maintenance.** [`maintenance.yml`](.github/workflows/maintenance.yml) keeps the re-signing schedule enabled, fails a week before the published list would expire, and opens an issue when a pinned scanner has a release at least two weeks old. If the list ever expires, re-sign it with `gh workflow enable revocations.yml && gh workflow run revocations.yml`.

## Repository

`cmd/otrust` · `internal/` (subject, ci, adapters, policy, statement, signer, trustlevel, verify) · `profiles/supply-chain-baseline/v1` (spec, Rego policy, real-output fixtures) · [poc-plan.md](poc-plan.md) · [research/](research/)
