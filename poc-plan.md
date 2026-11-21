# Open Trust — POC Execution Plan

This plan turns [open-trust-plan.md](open-trust-plan.md) into a POC of about 6 weeks for 1–2 people. The approach is to **build as little as possible**. Existing tools do the scanning, signing and transparency. We write only the parts nobody else has: the profile, the binding of results to an artifact, the trust model and the verifier UX. Research background is in [research/](research/).

**Design principle: CI-agnostic core, CI-specific trust.**
- The assessment, the certificate and the verifier work the same on every CI.
- What differs between CIs is *how much the signature can prove*. Each CI exposes different identity and isolation guarantees.
- So the trust level is **computed from the CI's capabilities and written into the certificate**. It is not something the design assumes.

---

## 1. Key decisions (revisited at the gates)

| # | Decision | Choice | Why |
|---|---|---|---|
| D1 | Language | **Go**: one static binary `otrust` with subcommands `assess` and `verify` | in-toto, sigstore-go, OPA and go-containerregistry are all Go libraries. A single binary runs as a step in any CI. |
| D2 | Scanners | Run the **syft**, **trivy** and **semgrep** CLIs as subprocesses, at pinned versions | No reimplementation. Each adapter is about 50 lines: run the tool, capture its JSON, compute a digest. |
| D3 | Secrets check | `trivy fs --scanners secret` | One less tool than adding gitleaks. |
| D4 | Vulnerability scan | `syft` makes the SBOM, then `trivy sbom` scans **that SBOM** | Ties the vulnerability results to the exact SBOM recorded in the certificate. |
| D5 | Policy | Rego, run in the embedded OPA Go library | The verifier reuses the same engine to re-evaluate. `opa test` runs the fixtures. |
| D6 | Envelope | in-toto Statement v1 in DSSE, as a **Sigstore bundle** (`.sigstore.json`). KMS-signed output uses the same bundle format, carrying a public-key hint. | Standard format, verifiable offline, same shape whichever signer is used. |
| D7 | Predicate | **SLSA VSA** (v1.2). It uses a custom `verifiedLevels` value (`OPENTRUST_SCB_V1`) and a URI-named extension field for per-check results, CI identity and trust level. | VSA allows extension fields and custom levels that don't start with `SLSA_`. |
| D8 | CI adapters | `internal/ci` holds one small adapter per CI. Each detects the CI, reads the revision, run URL and OIDC token, and reports **capabilities** (identity token? isolated template? hosted runner?). POC adapters: **GitHub Actions**, **GitLab CI**, **generic** (env vars or flags). | This is the only CI-specific code. Adding a CI means adding one adapter, with no change to the core. |
| D9 | Signers | A pluggable `Signer` interface. **sigstore-keyless** works with any OIDC issuer Fulcio supports: GitHub, GitLab, Buildkite, CircleCI, Codefresh, Buddy. **kms/key** is the fallback for Jenkins, Azure DevOps, air-gapped setups or anything else. | Keyless where the CI can prove its identity. Otherwise a key, at a lower trust level. |
| D10 | Trust level | `otrust` computes it from what the CI adapter reports and the signer used, records it in the certificate, and the verifier **recomputes it from the signing certificate**. It doesn't trust the claimed value. | No certificate can claim more than its signature proves. See §3. |
| D11 | Verifier trust policy | The buyer passes `--trust-policy trust.yaml`. It lists the accepted signers: Fulcio issuer plus identity pattern, or a public key, with the minimum trust level for each. There is **no default that accepts everything.** | Works the same for every CI. Fixes the "accept any signer" trap found in autogov and `gh` (research/week0-autogov-handson.md). |
| D12 | Artifact format | An OCI image, built as an OCI layout (`buildx --output type=oci`, `buildah`, `kaniko`) or referenced in a registry. The subject is the **image manifest digest**. | Same digest whatever the CI or registry. A `docker save` tarball doesn't give a stable digest. |
| D13 | Provenance | A provenance adapter that accepts any **SLSA provenance** bundle for the subject, signed by a signer in the trust policy. GitHub produces one with `actions/attest-build-provenance`. For GitLab, use the runner's artifact provenance metadata (*verify in week 4*; if it is unsigned, report the check as `WARN: unsigned provenance`). | We don't generate provenance ourselves. Each CI's native source is reused. |
| D14 | Trust files | **Static, signed files** served from any web host: the trusted root, the profiles and a revocation list. | No server and no ties to a CI vendor. |

**Not built:** SaaS, a dashboard, an API server, adapters beyond GitHub, GitLab and generic, Java-specific checks, custom crypto.

---

## 2. Repository layout

```text
open-trust/
├── cmd/otrust/            # CLI entrypoint (assess, verify)
├── internal/
│   ├── ci/                # github.go, gitlab.go, generic.go — detect, identity, capabilities
│   ├── signer/            # sigstore.go (any Fulcio OIDC issuer), kms.go (key/KMS)
│   ├── subject/           # OCI manifest digest (layout dir / registry ref)
│   ├── adapters/          # syft.go, trivy.go, semgrep.go, provenance.go
│   ├── policy/            # embedded Rego, evaluation
│   ├── statement/         # VSA statement + extension fields
│   ├── trustlevel/        # capabilities + signer cert → level (shared by assess & verify)
│   └── verify/            # bundle verify, trust policy, result classification
├── profiles/
│   └── supply-chain-baseline/v1/
│       ├── profile.md     # human spec: claims + limitations
│       ├── policy.rego
│       ├── policy_test.rego
│       └── fixtures/      # pass/ fail/ evidence sets
├── ci-templates/          # thin wrappers — all just run `otrust assess`
│   ├── github/assess.yml          # reusable workflow (strongest isolation available on GitHub)
│   ├── gitlab/assess.gitlab-ci.yml # CI/CD component / include
│   └── generic/assess.sh          # Jenkins, Azure DevOps, anything else
├── .github/workflows/release.yml  # builds + signs otrust itself
├── trust/                 # published static: trusted_root.json, revocations.json, profiles index
├── test/adversarial/      # one script per attack in §6, run per CI where relevant
# the vendor demo lives in its own repository, github.com/dario-mr/open-trust-demo, so its calls to
# the reusable assessor cross a repository boundary (required for L1+isolated-assessor)
```

The CI templates are only a convenience. Every one of them reduces to `otrust assess --image <ref|dir> --profile supply-chain-baseline@v1`.

---

## 3. Trust model: levels depend on what the CI can prove

The underlying problem is the same on every CI. A vendor's own scripts can fake anything they sign. A signature therefore proves only as much as the identity behind it. Each CI provides a different identity:

| CI / signer | What the signature binds to | Can the vendor's scripts change the assessment before it is signed? | Trust level recorded |
|---|---|---|---|
| **GitHub Actions + our reusable workflow + keyless** | Fulcio *Build Signer URI* = our workflow @ pinned SHA (separate from the caller), plus source repo, commit and `runner_environment` | **No.** The caller can't inject steps into a reusable workflow's job. | `L1+isolated-assessor` |
| **GitLab CI / Buildkite / CircleCI / Codefresh + keyless** | The vendor's pipeline identity, project and commit. For GitLab, both Build Signer URI and Build Config URI come from `ci_config_ref_uri`, the top-level pipeline, with no claim for an included component. | **Yes.** It is the vendor's pipeline that signs. | `L1+ci-identity` |
| **Any CI + KMS or key** (Jenkins, Azure DevOps, self-hosted) | Whoever holds the key | **Yes.** | `L1` |

Every level is still **vendor-attested** (Level 1 in open-trust-plan.md). The suffixes tell the buyer *what else* the verifier checked independently. The verifier derives the level from the signing certificate and the trust policy, so a certificate cannot claim a higher level than its signature supports.

How each level is achieved:
- **`L1+isolated-assessor` (GitHub).** The vendor calls `uses: open-trust/assess/.github/workflows/assess.yml@vX`. That workflow checks out `github.sha` itself, downloads and verifies a pinned `otrust`, runs the pinned scanners with the policy embedded in the binary, and signs. The verifier pins the workflow identity and requires `github-hosted` runners. Confirmed in week 0 against real certificates (research/week0-autogov-handson.md).
- **`L1+ci-identity` (GitLab and others).** `otrust` runs as a job in the vendor's pipeline and signs with that CI's OIDC token through Fulcio. The buyer pins the vendor's project, protected ref and, where available, a hosted-runner claim. This proves *which pipeline and commit* produced the result. It does not prove that the assessment was unmodified.
- **`L1` (key).** The vendor holds the key, ideally in a KMS. This proves only *who* signed.

Research started after the POC ([research/isolated-assessor.md](research/isolated-assessor.md)): no CI other than GitHub can name an included template today, so outside GitHub the levels stay `L1+ci-identity` or `L1`, honestly labelled. The remote assessor is dropped, because the system must be self-contained, and the TEE is shelved. The original note follows. A CI-agnostic path to isolated assessment, for example a separate "assessor" runner that pulls the artifact, or a TEE. That would bring `L1+isolated-assessor` to every CI. Also check whether GitLab adds a component-identity claim to its OIDC tokens.

---

## 4. The certificate (VSA plus extension, draft)

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "registry.example.com/acme/svc", "digest": { "sha256": "<manifest digest>" } }],
  "predicateType": "https://slsa.dev/verification_summary/v1",
  "predicate": {
    "verifier": { "id": "https://open-trust.dev/otrust", "version": { "otrust": "0.1.0" } },
    "timeVerified": "2026-11-13T10:00:00Z",
    "resourceUri": "registry.example.com/acme/svc",
    "policy": { "uri": "https://open-trust.dev/profiles/supply-chain-baseline/1.0.0", "digest": { "sha256": "…" } },
    "verificationResult": "PASSED",
    "verifiedLevels": ["OPENTRUST_SCB_V1"],
    "https://open-trust.dev/assessment/v0.1": {
      "agentDigest": { "sha256": "…" },
      "ci": { "provider": "gitlab", "pipeline": "https://gitlab.com/acme/svc/-/pipelines/123", "runner": "hosted" },
      "source": { "repo": "https://gitlab.com/acme/svc", "revision": "<git sha>" },
      "validUntil": "2026-12-13T10:00:00Z",
      "trustLevel": "L1+ci-identity",
      "checks": [
        { "id": "sbom",       "tool": "syft@1.x",    "result": "PASSED", "evidenceDigest": { "sha256": "…" } },
        { "id": "vulns",      "tool": "trivy@0.x",   "result": "PASSED", "summary": { "critical": 0, "high": 0 }, "evidenceDigest": {…} },
        { "id": "secrets",    "tool": "trivy@0.x",   "result": "PASSED", "evidenceDigest": {…} },
        { "id": "sast",       "tool": "semgrep@1.x", "result": "WARN",   "summary": { "error": 0, "warning": 3 }, "evidenceDigest": {…} },
        { "id": "provenance", "result": "WARN", "note": "unsigned provenance" },
        { "id": "subject-binding", "result": "PASSED" }
      ],
      "exceptions": [{ "check": "vulns", "id": "CVE-2026-1234", "reason": "not reachable", "expires": "2026-12-01" }],
      "unmetRequirements": [],
      "limitations": ["Vendor pipeline signs (not an isolated assessor)", "Scanners detect known issues only"]
    }
  }
}
```

Raw evidence (SBOM, trivy JSON, SARIF) **stays with the vendor**. The certificate holds only digests. A vendor can hand the evidence to a customer, and `verify --evidence dir/` then checks the digests and **re-runs the policy**. That catches a summary that doesn't match its evidence. It doesn't catch evidence that was fabricated.

`unmetRequirements` and `exceptions` are **always** filled in and shown, even on PASSED. This is a direct response to the autogov finding: a PASSED VSA hid a code-review requirement that wasn't met.

### Profile v1 policy rules (initial)

| Check | FAIL when | WARN when |
|---|---|---|
| sbom | missing or empty | — |
| vulns | any CRITICAL, or HIGH with a fix available, not excepted | HIGH with no fix available |
| secrets | any finding not excepted | — |
| sast | any semgrep `ERROR` | `WARNING` |
| provenance | missing, or subject digest mismatch | present but unsigned, or its signer isn't in the trust policy |
| subject-binding | digest assessed ≠ digest signed | — |

Exceptions live in `.otrust/exceptions.yaml` in the vendor repo. Each one needs an expiry date, and every exception is copied into the certificate.

Certificate validity: 30 days. A new policy version never changes an old certificate. The verifier can require a minimum profile version, and its output always names the policy version it judged against.

---

## 5. Milestones

### Week 0 (done)
Competitive desk research and hands-on testing of autogov: [research/](research/). The gap and trust-model questions are answered.

**G0 decision: pivot, don't abandon.** Build on existing attestation standards. Our product is a CI-agnostic, buyer-facing profile and verifier that states trust levels honestly. This call rests on research only. Demand is unvalidated until week 5.

### Week 1: profile spec and policy (Phase 1). Done except the second-person check
Delivered in [profiles/supply-chain-baseline/v1/](profiles/supply-chain-baseline/v1/): profile.md, policy.rego, 17 tests against real tool output. Known gaps are in profile.md §9.
- `profile.md`: claims, required tools and versions, rules, exceptions, validity, the trust levels from §3, and limitations.
- `policy.rego` and `policy_test.rego`, plus fixture evidence: one passing set, one failing set per rule, one with an exception.
- **Exit:** `opa test` passes, and a second person evaluates the fixtures by hand from `profile.md` and reaches the same results.

### Week 2: `otrust assess`, CI-agnostic (Phase 2). Done
Delivered as `cmd/otrust` plus `internal/{subject,ci,adapters,policy,statement,assess}`.
- `otrust assess --no-sign` gives PASSED (exit 0) on the clean fixture and FAILED (exit 1) on the vulnerable one.
- Unit tests, plus e2e tests against the real scanners (`OTRUST_E2E=1`).

Shortcuts carried forward:
- scanners run through Docker only, with no pinned-binary mode yet;
- single-platform OCI layouts only;
- registry refs are not supported yet;
- BuildKit provenance is accepted unsigned (WARN).

Original scope:
- Subject digest, the scanner adapters, policy evaluation, the VSA statement and a human-readable summary.
- The `ci` interface with a **generic** adapter first (all values from flags or env). It must run on a laptop with `--no-sign`.
- **Exit:** correct statement and evidence for a passing image and a failing image, run locally, with no CI involved.

### Week 3: signing and `otrust verify` (Phase 3). Done
Delivered as `internal/{signer,trustlevel,verify}`, plus `otrust keygen`, `assess --key` and `otrust verify`.

**Exit met:** a key-signed certificate verified offline in a `--network none` container. That was a container on the same Mac, not a separate physical machine. Results:
- clean: `VERIFIED`, with the evidence re-evaluated;
- vulnerable: `ASSESSMENT_FAILED`;
- the wrong image: `ARTIFACT_MISMATCH`.

What was built and tested:
- Hermetic tamper tests cover every code, plus `MALFORMED` and `POLICY_UNKNOWN`, which the original list lacked.
- `EVIDENCE_MISSING` is now split out from `EVIDENCE_MISMATCH`.
- The keyless *verify* path is tested against a real GitHub-signed bundle.
- A new `context.json` (time, subject, provenance status, exceptions) is digest-bound in the certificate, so `--evidence` re-runs the exact policy input. It catches a vendor that signs honest evidence digests but a dishonest summary.

**Deviation:** keyless *signing* moved to week 4, which needs a real CI OIDC token to test. Revocations are an unsigned local file for now; signing it is week 5.

Original scope:
- The `Signer` interface: sigstore-keyless (any Fulcio issuer) and a key file. A KMS key comes later behind the same interface.
- `trustlevel` package, shared by `assess` and `verify`.
- `otrust verify cert.sigstore.json --image <dir|ref> --trust-policy trust.yaml [--evidence dir] [--trusted-root file] [--revocations file]`
  - **Safe defaults:** no trust policy means refuse to run, and a failed policy means a non-zero exit.
  - Always list unmet requirements, exceptions and the trust level, even on PASSED.
  - Distinct exit codes and messages: `INVALID_SIGNATURE`, `UNTRUSTED_SIGNER`, `TRUST_LEVEL_TOO_LOW`, `ARTIFACT_MISMATCH`, `ASSESSMENT_FAILED`, `EVIDENCE_MISMATCH`, `EXPIRED`, `REVOKED`.
- **Exit:** a key-signed certificate made on a laptop verifies on a different machine, offline.

### Week 4: two real CIs, the demo app and the adversarial suite (Phases 2, 4). Done on both CIs (GitHub incl. the isolated assessor; GitLab at ci-identity)
Delivered:
- `internal/ci`: GitHub Actions detection and OIDC token.
- `assess --keyless` (Fulcio + Rekor). The token and certificate are fetched *after* the scans, because both are short-lived.
- `.github/workflows/assess.yml`, a reusable assessor. It builds `otrust` from its own revision, found via the OIDC `job_workflow_ref` claim.
- `ci.yml`.
- The vendor demo in its own repository, **[dario-mr/open-trust-demo](https://github.com/dario-mr/open-trust-demo)**: a Spring Boot app with clean and log4j-vulnerable variants. It calls `assess.yml@63d2abd`, pinned by commit, across the repository boundary.

**`L1+isolated-assessor`, verified on real CI (open-trust-demo run 43602986686):**
- The signer is `open-trust/.github/workflows/assess.yml@63d2abd…` and the source is `open-trust-demo@41746d7`, on a GitHub-hosted runner.
- Following the demo README as a customer, against its `trust.yaml` (which requires `L1+isolated-assessor` and pins the signer commit):
  - clean: `VERIFIED`, with the evidence re-evaluated;
  - vulnerable: `ASSESSMENT_FAILED`;
  - mixed-up image: `ARTIFACT_MISMATCH`.

**GitLab, verified on real CI ([gitlab.com/dario-mr/open-trust-demo](https://gitlab.com/dario-mr/open-trust-demo) pipeline 3068491156).** The same demo source runs through `ci-templates/gitlab/otrust.gitlab-ci.yml`, pinned to commit `24e872e`, with Docker-in-Docker and keyless signing on GitLab's OIDC identity. Results:
- clean: PASSED and vulnerable: FAILED, signed at `L1+ci-identity`. The signer is the project's own `//.gitlab-ci.yml@refs/heads/main`, on a hosted runner.
- Locally, against the demo's `trust-gitlab.yaml`:
  - clean: `VERIFIED`, with the evidence re-evaluated;
  - vulnerable: `ASSESSMENT_FAILED`;
  - a policy demanding an isolated assessor: `TRUST_LEVEL_TOO_LOW`;
  - the GitHub trust policy applied to the GitLab certificate: `UNTRUSTED_SIGNER`.

**Portability exit met:** the same commit and the same check results on both CIs, with different and correct trust levels.

GitLab lessons:
- buildx needs a Docker context, not TLS environment variables;
- the image and the evidence must live under `$CI_PROJECT_DIR`, because Docker-in-Docker sees only `/builds`, so the scanners now skip non-source paths inside the source tree;
- "instance runners disabled" on a brand-new namespace did not block shared runners.

Found while preparing it: **a vendor `.semgrepignore` could blind SAST.** One `*`, committed at any depth, meant zero files scanned and a vacuous PASS, even with an isolated assessor. `otrust` now blanks every such file for the scan and records them in the certificate. An e2e test covers it, and it fails if the fix is removed.

**Earlier same-repository run (open-trust run 43601753041).** The demo was then in this repository and has since moved out. Results:
- clean: PASSED and vulnerable: FAILED, both signed keyless at `L1+ci-identity`.
- Locally, against that demo's trust policy and the public-good trusted root:
  - clean: `VERIFIED`, with the evidence re-evaluated;
  - vulnerable: `ASSESSMENT_FAILED`;
  - strict policy: `TRUST_LEVEL_TOO_LOW`;
  - wrong branch: `UNTRUSTED_SIGNER`;
  - wrong image: `ARTIFACT_MISMATCH`.

Found along the way: Trivy's secret scan was resolving `pom.xml` parents from Maven Central. That leaked dependency names and hit rate limits. It now runs with `--offline-scan`.

**Remaining in Week 4 (re-scoped 2026-11-14):**
- **Signed provenance: done.** `otrust assess --provenance <bundle>` verifies a Sigstore-bundled SLSA provenance. It checks the signature against the trusted root, that the subject is the image digest, and that the signer is CI of the assessed repository. The GitHub demo attests with `actions/attest-build-provenance`. **Verified (open-trust-demo run 43610582278):** the clean certificate has all six checks PASSED at `L1+isolated-assessor`. GitLab, which has no signed provenance of its own, stays WARN ("provenance is not signed") as designed.
- *Optional:* real CI attack runs: a self-hosted runner, a wrong workflow ref, an outdated assessor pin. Today the trust-policy tests cover these, and the tamper tests run in `ci` through `go test`.

**Moved or dropped:**
- `release.yml` (signed `otrust` binaries) moved to week 5. No assessment depends on it, because the assessor builds `otrust` from pinned source. It belongs with distributing trusted agent versions.
- The autogov baseline trial is dropped. Its purpose was a friction baseline *before* writing our template, and both templates now exist and run. A comparison remains optional research.

Original scope:
- Day 1, half a day at most: wire autogov's reusable workflows into a throwaway **public** repo (private repos need GHEC for attestations). Note the vendor-side friction: lines of YAML, permissions, secrets, failure modes. This is the reference and baseline for our template.
- GitHub adapter plus the `ci-templates/github/assess.yml` reusable workflow, giving `L1+isolated-assessor`.
- GitLab adapter plus `ci-templates/gitlab/`, giving `L1+ci-identity`. Check GitLab's provenance options (D13).
- `release.yml` signs the `otrust` binaries.
- A minimal Spring Boot demo with **both** a GitHub and a GitLab pipeline, plus a branch with a vulnerable dependency (an old `log4j-core`).
- `test/adversarial/`: one script per row in §6, run against both CIs.
- **Exit:** the same commit assessed on GitHub and on GitLab produces two certificates. The verifier gives both the **same check results** and the **correct, different trust levels**.

### Week 5: trust files, the demo and feedback (Phases 5, 6). Done
- `release.yml`: on a version tag, builds `otrust` for linux and darwin (amd64 and arm64), attests the build provenance and publishes a GitHub release. The assessors (`assess.yml`, the GitLab template) use the identical build (`CGO_ENABLED=0 -trimpath -buildvcs=false`). **Verified:** the v0.1.1 release, the GitHub assessor and the GitLab template all produce linux/amd64 digest `df6a7d22…`, the `agentDigest` in their certificates. v0.1.0 did not match, because VCS stamping put the tag into the binary, so it was superseded.
- `trust/revocations.json` is signed keyless by `revocations.yml` (on change and weekly; valid 14 days) and served as an asset of the `revocations` release. `verify --online` fetches it and accepts only that workflow on `main` as the signer. `--revocations` takes a downloaded signed list, or the buyer's own plain list. Its first entry revokes the pre-release assessor binary (df86e37).
- Demo: [demo/scenarios.sh](demo/scenarios.sh) runs the §7 scenarios from the buyer side with the released binary, and its recorded run is [demo/RESULTS.txt](demo/RESULTS.txt): **12 of 12 as expected**. Expiry is covered by a unit test only, since no certificate is 30 days old yet. Consumer page: [docs/consumer-guide.md](docs/consumer-guide.md).
- **Gate G1:** [research/g1-go-no-go.md](research/g1-go-no-go.md). **Technical GO, narrowed, demand unvalidated.**
- Found: GitHub and GitLab built the same commit to **different image digests** (different BuildKit versions). Each certificate binds its own image, so a buyer must get the image and the certificate from the same pipeline.

---

## 6. Adversarial test matrix (expected outcomes per trust level)

| Attack | `L1+isolated-assessor` (GitHub) | `L1+ci-identity` (GitLab etc.) | `L1` (key) |
|---|---|---|---|
| Edit the policy in the vendor repo | **Prevented.** The policy is embedded in the pinned agent. | **Detected.** The policy digest doesn't match the published profile. | **Detected** (policy digest) |
| Use a modified `otrust` or replace a scanner | **Prevented** (pinned and verified) | **Detected only if** the agent digest is checked. The vendor can lie about the digest, so effectively **undetectable**. | **Undetectable** |
| Skip a required check | **Detected** (the check is missing, so FAIL) | **Detected** | **Detected** |
| Change the image after assessment | **Detected** (`ARTIFACT_MISMATCH`) | **Detected** | **Detected** |
| Reuse a certificate for another image | **Detected** | **Detected** | **Detected** |
| Edit the certificate JSON | **Detected** (`INVALID_SIGNATURE`) | **Detected** | **Detected** |
| Sign fabricated results from the vendor's own pipeline | **Detected** (`UNTRUSTED_SIGNER`) | **Undetectable.** The vendor's pipeline *is* the trusted signer. | **Undetectable** |
| Sign from an unexpected project or branch | **Detected** | **Detected** (trust policy pins the project and ref) | n/a |
| Tampered self-hosted runner | **Detected** (`runner_environment`) | **Detected** where the CI exposes a runner claim, otherwise undetectable | **Undetectable** |
| Present a low-level certificate as a higher one | **Detected.** The verifier recomputes the level. | **Detected** | **Detected** |
| Fabricate evidence before the scan (hide a dependency) | **Not detectable** (a limitation) | **Not detectable** | **Not detectable** |
| Old or revoked agent, or an expired certificate | **Detected** (revocations, `validUntil`) | **Detected** | **Detected** |

This table is the honest product pitch. It goes into the consumer documentation as it stands.

---

## 7. Demo script (the customer side)

```bash
# customer receives: image (OCI layout or registry ref) + cert.sigstore.json
otrust verify cert.sigstore.json --image ./svc-oci --trust-policy acme-trust.yaml
```

```text
✔ Signature valid (Rekor entry 123456, 2026-11-13T10:00Z)
✔ Signer: gitlab.com/acme/svc pipeline on refs/heads/main (hosted runner) — allowed by acme-trust.yaml
✔ Source: gitlab.com/acme/svc @ 3f2a9c1
✔ Artifact sha256:ab12… matches
✔ Profile supply-chain-baseline v1.0.0 (policy sha256:…)
✔ Result PASSED — 6/6 checks, 2 warnings (sast, unsigned provenance), 1 exception (CVE-2026-1234, expires 2026-12-01)
ℹ Trust level: L1+ci-identity — the vendor's pipeline ran and signed the assessment; an isolated assessor was not used
```

Scenarios to show:
1. A clean pass on GitHub and on GitLab for the same commit, with different trust levels.
2. A vulnerable dependency makes the assessment fail.
3. A changed image is rejected.
4. An edited certificate is rejected.
5. A revoked or expired certificate is rejected.
6. A key-signed certificate from a "Jenkins" generic run, shown as `L1`.
7. Verification works fully offline.

---

## 8. Risks and open questions

- **Isolated assessment is GitHub-only today.** No other CI's OIDC token identifies an included template separately from the caller. If buyers only value `L1+isolated-assessor`, our portability claim weakens. A CI-agnostic isolated assessor is the follow-up research (§3).
- **Differentiation.** Liatrio autogov already does reusable workflows, Rego and a VSA, but **only on GitHub**. Chainloop and Witness work across CIs but are aimed at internal teams. Our edge is a CI-agnostic, buyer-facing profile and verifier that are honest about trust levels.
- **Private repositories and public Rekor.** Keyless signing through public Sigstore publishes the repo and pipeline identity in Rekor, on every CI. The options are a private Fulcio and Rekor, or KMS-based `L1`. Whether vendors care is unvalidated.
- **GitLab provenance.** It may be unsigned (D13), which would make the provenance check WARN-only on GitLab.
- **Semgrep on Java.** The free rules may be noisy. If so, the SAST check is WARN-only in v1. The ruleset is recorded by digest, not pinned (§9).
- **Digest stability.** An exported OCI layout and a pushed image may differ depending on the build tool. Settled by assessing the registry reference itself (§9 step 3): the certificate binds the digest buyers pull.
- **Demand.** This POC doesn't validate demand at all. A technical go at G1 still leaves the main business risk open. Accepted on purpose (§9): we build first and use dogfooding as the feedback loop.

---

## 9. After the POC: decisions and next steps

Decisions taken after G1 (2026-11-16):
- **Trust levels outside GitHub stay honest.** GitLab and other OIDC CIs reach `L1+ci-identity`, and key-signed runs reach `L1`. That gives accountability through the public signature log, not prevention. A remote assessor was rejected, because it would make vendors depend on GitHub or on a service we run, and the system must be self-contained. A TEE assessor is shelved ([research/isolated-assessor.md](research/isolated-assessor.md)).
- **The SAST ruleset is recorded, not pinned.** Semgrep's registry rules are current but can't be redistributed, and a frozen snapshot would be obsolete. Every certificate records the exact rules it used, by digest, rule count and fetch time (profile.md §9).

Decision taken 2026-11-21:
- **Build first, no customer interviews.** The goal is a tool that is great and useful on its own merits; demand stays unvalidated on purpose. Instead of interviews, the compass is **"be the toughest buyer"**: a step is worth doing if it makes the certificate more useful to the person *receiving* it. More trust plumbing for its own sake is not. The bar to beat is Liatrio autogov plus GitHub attestations (research/week0-competitive-analysis.md): what a buyer gets from us must be clearly more than a signed pass/fail.

### Roadmap: build-first

| # | Step | Why | Size |
|---|---|---|---|
| 1 | ~~Buyer-side re-check~~ **Done.** `otrust verify --recheck` re-runs Syft and Trivy on the image, evaluates the policy with the certificate's own exceptions, and gives `RECHECK_MISMATCH` for a failing vulnerability published more than 30 days before the vendor's DB update but absent from the certificate, or (with `--evidence`) for packages that differ from the vendor's SBOM. Checked on the live GitHub demo, from a tar and from ghcr.io: packages identical, PASSED. *Shortcut:* the 30-day re-rating grace is a guess. Original plan: The verifier runs the image-based checks itself (Syft SBOM, Trivy vulnerabilities) on the image it was given, at the profile's pinned versions, and compares them with what the certificate claims: same packages, and the same or fewer findings at assessment time. Mismatch is a new result class. Compare package sets rather than raw SBOM digests, since Syft output carries timestamps. | For the image checks it removes the need to trust the vendor, **on every CI**. That lifts the GitHub-only ceiling without a server and is something autogov and GitHub attestations don't do. | Medium |
| 2 | ~~Vulnerabilities as of today~~ **Done with step 1:** an honest certificate that fails today gives `OUTDATED`, with each new finding listed. Original plan: falls out of step 1: the re-check reports CVEs known *now* next to the ones known at assessment time, so a buyer sees when a passing certificate has gone stale. | A certificate is a snapshot; buyers deploy long after it was issued. | Small, after 1 |
| 3 | **A verify report worth reading.** Replace the terse PASSED with a report a non-expert can act on: the verdict, what was proven and what was not, the trust level in plain words, exceptions and unmet requirements, re-check results, and what changed since a previous certificate (`--previous cert.sigstore.json`). Text by default, plus a Markdown or HTML file to pass on. | Today the value is buried in the output. This is what the buyer actually looks at. | Medium |
| 4 | **Dogfood as our own buyer.** Assess `otrust` itself on every release, and assess one non-Java real-world service (Go or Node). Verify each from a clean machine using only the consumer guide. Fix everything that is confusing. Bar: a buyer decides deploy or don't deploy from the report alone, in under five minutes. | It replaces interviews as the feedback loop, and proves the profile isn't Java-shaped. | Small, recurring |
| 5 | **Private repositories**: document the key-signed (`L1`) path for vendors who can't publish their identity in Rekor, ideally with a KMS-held key | Keyless signing puts the repository name in the public log | Small (docs). A private Fulcio/Rekor is large and deferred. |
| 6 | **Live CI attack runs**: a self-hosted runner, a wrong workflow ref and an outdated assessor pin, run on real CI | Today these rows of the §6 matrix rest on unit tests and reasoning | Small–medium |

Parked: a TEE assessor; GitLab component identity, if GitLab ever adds such a claim to its tokens; a private Fulcio/Rekor.

### Done after G1

| # | Step | Why | Size |
|---|---|---|---|
| — | ~~Release v0.1.2 and re-pin the demo~~ **Done.** The v0.1.2 release, the GitHub assessor and the GitLab template all give `agentDigest` `3ba9dd14…`. Both certificates record ruleset `800b43b6…`, and the demo re-ran 12/12. | Live certificates carry the recorded ruleset | Small |
| — | ~~Registry image references~~ **Done in the CLI.** `--image registry/name@sha256:…` works for assess and verify. Tags are refused, credentials come from the Docker config, and the pulled copy is not kept. An index digest keeps BuildKit provenance. Tested against an in-process registry, including with the real scanners. The CI templates support it too: `assess.yml` takes `image-ref` and logs in to ghcr.io with the job token; the GitLab template logs in to the project registry. The demo pushes to ghcr.io and the GitLab registry and is assessed by digest. One buildx build writes both the registry image and the tar. Their *indexes* differ (exporter annotations), but the image manifest the certificate binds is identical (v0.1.3; demo 12/12). *Shortcut:* other registries must be public to the runner. | The biggest adoption hurdle. Teams push to registries, and buyers pull from them. | Medium |
| — | ~~Maintenance hygiene~~ **Done.** [`maintenance.yml`](.github/workflows/maintenance.yml) runs weekly. It re-enables the scheduled workflows through the API (GitHub disables them after 60 days without activity). It checks the published revocation list the way buyers fetch it, and fails if the list expires within 7 days. It opens an issue when a scanner in `tools.json` has a release at least 14 days old. [Dependabot](.github/dependabot.yml) bumps action and Go pins monthly, with a 14-day cooldown. *Shortcut:* the API re-enable relies on community reports that it resets the 60-day counter; if it doesn't, the health check fails a week before buyers notice. | A certificate is only as current as its tools | Small, recurring |
