# Research: an isolated assessor outside GitHub

**Question.** `L1+isolated-assessor` means the vendor could not change the assessment. Today it exists only on GitHub Actions, where Fulcio's *Build Signer URI* names our reusable workflow separately from the caller (poc-plan.md §3). Can we offer the same guarantee to vendors on other CIs?

**Short answer.** No CI other than GitHub can do it natively today, and none is about to. Two designs give isolation without depending on the vendor's CI:
- **(C)** The vendor's CI *hands the job to* an isolated assessor, and authenticates the request with its own OIDC token.
- **(D)** The assessment runs inside a TEE whose hardware attestation proves which code ran.

C is a short spike on top of what exists. D is the long-term answer that also keeps source on vendor infrastructure. Recommendation: spike C now, keep D as the follow-up.

## What a solution must guarantee

These are the properties `L1+isolated-assessor` has on GitHub, and each one must survive:
1. **Unmodified assessment.** The vendor can choose the inputs (which artifact, which commit) but cannot change the steps, tools, policy or signing.
2. **Source binding.** The certificate names the vendor's real repository and commit, proven by the vendor's CI rather than claimed by it.
3. **Verifiable offline**, by a buyer who trusts neither us nor the vendor beyond a pinned identity.
4. **Privacy.** The source and evidence go nowhere the vendor hasn't chosen.

## A. Native CI identity: not available (checked 2026-11-16)

| CI | What the OIDC token or Fulcio certificate names | Can it name an included template? |
|---|---|---|
| GitHub Actions | `job_workflow_ref` becomes the SAN and Build Signer URI, separate from `workflow_ref` | **Yes**: this is our isolated level |
| GitLab CI | SAN and Build Signer URI come from `ci_config_ref_uri`, "the ref path to the top-level pipeline definition" | **No**. New claims (`job_project_path` in 18.4; `job_source` and `job_config` in 18.9) still identify no component or `include`. `job_config` is set only for jobs injected by a *pipeline execution policy*. |
| Buildkite, CircleCI, Codefresh, Buddy | Pipeline, organisation and job identifiers; CircleCI adds `pipeline-definition-id` | **No** (all are in Fulcio's issuer list, but no claim identifies an orb or plugin) |
| Jenkins, Azure DevOps, self-hosted | No Fulcio issuer | — |

**GitLab pipeline execution policies** come closest. A policy project injects jobs that project developers cannot remove or skip, and the token's `job_config` names the policy file and commit. But the policy belongs to the vendor's own group, its owners can edit or unlink it, it needs GitLab Ultimate, and Fulcio does not put `job_config` in the certificate. That isolates the assessment from the vendor's *developers*, not from the *vendor*. At most it would justify a future, weaker "policy-enforced" label. It does not give `isolated-assessor`.

**Watch item:** a GitLab claim that identifies a CI/CD component, and Fulcio mapping it to Build Signer URI. If that ships, GitLab gets isolation exactly as GitHub has it, with no design change.

## B. Vendor-run self-hosted assessor: no gain

If the vendor runs the assessor on their own infrastructure without hardware attestation, it is `L1+ci-identity` or `L1` again. Whoever operates the machine can change what runs on it.

## C. Remote isolated assessor, authenticated by the vendor's CI token

The vendor's pipeline (GitLab, Buildkite, CircleCI or any OIDC CI) does not run the assessment. It **requests** one:

```text
vendor CI job ──(1) OIDC token, aud "open-trust"; image digest/location; pipeline info──▶ isolated assessor
isolated assessor:
  (2) verify the token against the CI's JWKS (issuer allowlist, aud, exp, single use by jti)
      → project, ref, sha, runner_environment, pipeline URL: proven by the vendor's CI, not claimed
  (3) fetch the source itself at the token's sha, and the image by digest
  (4) run otrust assess as today and sign keyless with the *assessor's* identity
  (5) record the verified CI identity in the certificate (ci.provider gitlab, verified: true)
```

The assessor runs as a **GitHub reusable workflow that we own** (a new `assess-remote.yml`). That reuses the isolation that already works. The buyer pins its Build Signer URI exactly as today and, through a new trust-policy field, the verified *external* source (for example `gitlab.com/acme/svc @ refs/heads/main`).

Who triggers the run:
- **C1, vendor relay (no Open Trust infrastructure).** The vendor creates a small, private GitHub repository whose only workflow takes `workflow_dispatch` inputs and calls our `assess-remote.yml`. Their CI job triggers it with a GitHub token stored as a CI secret. The vendor can't add steps to our workflow, the same property as today. The vendor needs a GitHub account; GitHub-hosted minutes are free within GitHub's limits.
- **C2, hosted broker.** A small Open Trust service verifies the vendor's token and dispatches the run in a repository we own. The vendor needs nothing else. The broker is not trusted, because the assessor re-verifies the token itself. But we pay for runners and must handle abuse.

How it scores against the requirements:

| Requirement | C |
|---|---|
| Unmodified assessment | **Yes**: the same argument as on GitHub. The vendor chooses only the inputs. |
| Source binding | **Yes**. The token is signed by the vendor's CI and names project, ref and sha, and the assessor fetches that commit itself. The vendor cannot substitute a different source. |
| Offline verification | **Yes**: an unchanged Sigstore bundle. The buyer trusts that our pinned assessor checked the token. It also helps that the assessor's code is public and pinned. |
| Privacy | **Worse.** The source and image go to a GitHub-hosted runner: the vendor's own (C1) or ours (C2). Private repositories also need a read-only deploy token. A GitLab-only vendor may not accept this. |
| CI coverage | Any CI that issues OIDC tokens (GitLab, Buildkite, CircleCI, Codefresh). Jenkins and Azure DevOps are not covered. |

Open questions for the spike:
- **Token lifetime.** GitLab ties `exp` to the job timeout, with 5 minutes reported as the fallback. The dispatch-to-start delay has to fit inside that.
- **Token exposure.** `workflow_dispatch` inputs are visible to anyone with read access to the relay repository, so it must be private (C1). Also mask the token.
- **Fetching the image.** Use a registry pull by digest, or a GitLab job-artifact download. Private projects need credentials.
- **Replay.** Within its lifetime the token can be replayed. Harm is limited, because it can only request another assessment of the same commit. Still, record the `jti` and accept each token only once per run.
- **Naming.** Is it still `L1+isolated-assessor`, or a distinct level such as `L1+remote-assessor` so buyers can tell the paths apart? Distinct, probably: the certificate's signer is GitHub, while the source was on another CI.

## D. Hardware-isolated assessor (TEE), run by the vendor

The vendor runs a **published, reproducible Open Trust assessor image** inside a trusted execution environment on their own cloud. The hardware attests which image is running, and the operator cannot change it or read its memory. The assessor binds its signing key to that attestation, and the buyer checks it against the published measurement.

| Platform | What proves the image | Offline buyer check |
|---|---|---|
| AWS Nitro Enclaves | COSE-signed attestation document; PCR0 measures the enclave image, and a reproducible build gives a known PCR0 | **Good.** The chain ends at the AWS Nitro root certificate, with a published fingerprint. Go verifiers exist (e.g. `hf/nitrite`). |
| GCP Confidential Space | Google-signed attestation token (RS256) with `image_digest`, and `dbgstat: disabled-since-boot` for production images | **Harder.** It is a JWT against rotating Google keys; offline use needs a JWKS snapshot. |
| Azure confidential containers / SEV-SNP, TDX | Raw hardware reports | Possible, more work |

**Strengths.** It is CI-agnostic: any CI or a cron job can call it. Source and evidence stay on vendor infrastructure, so it keeps the privacy property that C loses. It also runs on Jenkins and Azure DevOps.

**Costs.**
- Enclaves have no Docker and no direct network access, so the scanners and their databases must be built into the image, and inputs are passed in through a local channel.
- The image needs a reproducible enclave build.
- It is cloud-specific per vendor, and the verifier needs a new attestation path for each platform.
- This is weeks of work, not days.

## Recommendation

1. **Spike C1** (a few days), entirely on infrastructure we already have:
   - `assess-remote.yml`, a reusable workflow taking an OIDC token and a source and image location;
   - `otrust ci verify-token` (JWKS and issuer allowlist; GitLab first);
   - a new `ci.verified` block in the certificate;
   - a trust-policy field for the external source;
   - a relay repository for open-trust-demo, triggered from its GitLab pipeline.

   Success: the GitLab demo certificate verifies at the remote-isolated level, and a request with a forged or expired token is refused.
2. **Then decide** with buyers whether C's privacy cost is acceptable. If it isn't, D (Nitro first, for its offline-verifiable root) is the path. Scope it as a separate project.
3. **Keep watching** for GitLab component identity (A), the cheapest outcome if it ever lands.

## Sources

- Sigstore, [OIDC usage in Fulcio](https://docs.sigstore.dev/certificate_authority/oidc-in-fulcio/): GitHub's SAN comes from `job_workflow_ref`, GitLab's from `ci_config_ref_uri`.
- Fulcio [identity config](https://github.com/sigstore/fulcio/blob/main/config/identity/config.yaml): the issuers it supports.
- GitLab, [ID token claims](https://docs.gitlab.com/ci/secrets/id_token_authentication/): `ci_config_ref_uri`, `job_project_path` (18.4), `job_source` and `job_config` (18.9).
- GitLab, [pipeline execution policies](https://docs.gitlab.com/user/application_security/policies/pipeline_execution_policies/).
- GitLab issue on [ID token expiry](https://gitlab.com/gitlab-org/gitlab/-/work_items/222252).
- Buildkite [OIDC](https://buildkite.com/docs/pipelines/security/oidc); CircleCI [OIDC tokens](https://circleci.com/docs/openid-connect-tokens/).
- AWS Nitro Enclaves, [verifying the root of trust](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).
- GCP Confidential Space, [attestation token claims](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims).
- SLSA v1.0 [requirements](https://slsa.dev/spec/v1.0-rc2/requirements): isolation allows calls to a remote execution service.
