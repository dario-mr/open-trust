# Week 0 — Competitive Analysis & Gap Statement

Date: 2026-11-13. Desk research only: docs, specs, package pages. **No hands-on trials yet.** Each claim below lists its source. Items marked *unconfirmed* need a hands-on trial before we rely on them.

## TL;DR

- **Every technical building block already exists.** That covers identity-bound signing from reusable workflows, custom attestation predicates, offline bundle verification, a standard summary format (VSA), and Rego evaluation of attestations.
- **The closest competitor is Liatrio `autogov`.** It is a Go CLI plus reusable workflows that attest provenance, SBOM and vulnerability scans, evaluate them with Rego, and emit a signed SLSA VSA, and it verifies offline. It covers most of the plumbing in our POC.
- **What is still missing is mostly product, not technology:**
  - a published, versioned assurance profile written for a *software buyer*, with explicit claims and limitations;
  - a buyer-facing verifier that explains the result;
  - a workable story for **private repositories**.
- **G0 verdict: pivot, don't abandon.** Build *on* GitHub artifact attestations, Sigstore bundles and VSA, not beside them. Our product becomes the profile, the hardened assessment workflow and the buyer-side verifier. The custom signing and certificate stack goes.

## 1. Building blocks (all reusable)

| Need in our plan | Already exists | Source |
|---|---|---|
| Signer = our reusable workflow, not the vendor's scripts | The Fulcio certificate extension **Build Signer URI** (`1.3.6.1.4.1.57264.1.9`) = `job_workflow_ref`, which is the reusable workflow. **Build Config URI** (`.18`) = `workflow_ref`, which is the caller. **Runner Environment** (`.11`) is also there. | [Fulcio OID docs](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md) |
| Verify the signer identity, offline | `gh attestation verify --bundle … --custom-trusted-root … --signer-repo … --signer-workflow … --deny-self-hosted-runners --predicate-type …` | [gh manual](https://cli.github.com/manual/gh_attestation_verify) |
| Sign a custom predicate in Actions | `actions/attest` with `predicate-type` and `predicate-path`. It outputs `bundle-path` (Sigstore bundle) and can `push-to-registry`. | [actions/attest](https://github.com/actions/attest) |
| Standard pass/fail summary | SLSA **VSA**. It allows URI-named extension fields and custom `verifiedLevels` values, as long as they don't start with `SLSA_`. The v1.0 page is marked retired; **v1.2** is current. | [VSA spec](https://slsa.dev/spec/v1.0/verification_summary) |
| Rego evaluated over attestations, then a VSA | Liatrio autogov | [autogov](https://pkg.go.dev/github.com/liatrio/autogov) |

**This answers the poc-plan.md §3 spike on paper.** The certificate records the reusable workflow as the signer, which is the same mechanism slsa-github-generator relies on. We still need an empirical check in week 2; it is now a confirmation, not an unknown.

## 2. Competitors

| | Liatrio autogov | Chainloop | in-toto Witness | SignPath | GitHub artifact attestations |
|---|---|---|---|---|---|
| What it is | CLI plus reusable workflows that attest, run a Rego policy and emit a VSA | Evidence store and policy engine with a control plane | Framework of attestors plus a policy verifier, with the Archivista store | Code-signing service with origin verification | Built-in signing of provenance or custom predicates |
| Runs checks in vendor CI | Yes (reusable workflows) | Yes (CLI in GHA, GitLab, Jenkins, Dagger) | Yes (wraps commands) | No, it signs; checks are out of scope | No, it signs what you give it |
| Bound to artifact digest | Yes | Yes | Yes | Yes (signed binary) | Yes |
| Policy | Rego, separate policy library repo, vulnerability thresholds | Rego attached to "workflow contracts" | Witness policy plus Rego | Signing policy (branch, repo, review) | None (that's the verifier's job) |
| Summary for a consumer | **VSA** | Signed attestation referencing evidence in CAS | Policy-verify result, exit code | Signed binary plus SLSA provenance | Bundle |
| Offline verify | Yes (`autogov offline`, skips tlog) | *unconfirmed* | Yes, with policy and keys | Signature verify | Yes (`--bundle`, `--custom-trusted-root`) |
| Main audience | Internal release gating | Internal compliance and security teams | Platform engineers | Software publishers (Windows/OSS code signing) | Any GitHub user |
| Ready-made buyer profile with claims and limits | No (generic policy library) | No | No | No | No |
| Notes | Single maintainer (stated on its page). Apache-2.0, v1.x. | Requires control plane. Thoughtworks Radar listing. | CNCF in-toto project | GHA origin verification is preview-only. Enterprise. States plainly that it cannot guarantee the CI is safe. | **Private and internal repos need GitHub Enterprise Cloud.** Not on GHES. |

Sources: [autogov](https://pkg.go.dev/github.com/liatrio/autogov), [Chainloop (Help Net Security)](https://helpnetsecurity.com/2026/08/10/chainloop-open-source-supply-chain-security/), [Chainloop (Thoughtworks Radar)](https://thoughtworks.com/radar/platforms/chainloop), [Witness policy docs](https://github.com/in-toto/witness/blob/main/docs/concepts/policy.md), [SignPath origin verification](https://docs.signpath.io/origin-verification), [SignPath trusted build systems](https://docs.signpath.io/trusted-build-systems), [actions/attest](https://github.com/actions/attest).

## 3. New finding: the private-repository problem

Most commercial vendors keep their repositories private. Today they have three options:

1. **GitHub artifact attestations.** These need GitHub Enterprise Cloud for private repos, and GitHub then signs on its own Sigstore instance.
2. **Sigstore public-good keyless.** The Fulcio certificate sits in the **public Rekor log**, which publishes the private repo name, commit SHA, workflow path and run URL. That violates our "privacy" criterion.
3. **A KMS key held by the vendor.** The certificate no longer carries the workflow identity. That drops us to Level 1 with no identity binding.

This is a real gap that buyers would feel: identity-bound assurance for private repositories without leaking metadata and without requiring GHEC. A possible direction is an Open Trust Fulcio and Rekor instance, or a private transparency log. That is exactly the "trust infrastructure" in open-trust-plan.md §2, and it gives the optional cloud service a concrete job. *Unconfirmed:* whether vendors care.

## 4. Gap statement (G0)

> A software buyer today can verify *that* a vendor signed something about an artifact. They cannot easily verify **which standard methodology was applied**, **what it does and doesn't claim**, and **that the vendor couldn't edit the results**. Nor can they do this for vendors whose source is private, without the vendor buying GHEC or leaking repository metadata. Existing tools (autogov, Chainloop, Witness) are built for a company's *internal* release gating. None publishes a buyer-oriented, versioned assurance profile with a matching verifier.

Differentiated capabilities to carry forward:

1. **Published assurance profile** ("Supply-Chain Baseline v1") with claims, limitations and trust level, written for buyers and procurement.
2. **A hardened reusable assessment workflow that we own.** Its Build Signer URI is the trust anchor, and the verifier pins it.
3. **A buyer-side verifier** that says *what it means*, not only "signature OK". It is a thin layer over sigstore-go and the VSA.
4. **Private-repo identity-bound signing** (§3). This is a candidate only; demand is unvalidated.

What is **not** differentiated and must not be rebuilt: scanners, the SBOM format, the attestation envelope, signing, the transparency log, and offline bundle verification.

## 5. Changes to poc-plan.md (applied)

- D7 → use **VSA**, with a custom `verifiedLevels` value and an extension field for per-check results.
- §3 spike → answered on paper; week 2 confirms it empirically.
- §8 risks → add the private-repo / Rekor metadata leak and autogov overlap.
- **Later revision: the plan is now CI-agnostic.** CI adapters plus pluggable signers (Sigstore keyless with any Fulcio issuer, or a KMS/key). The trust level is computed per CI.
  - Fulcio maps claims for GitHub, GitLab, Buildkite, CircleCI, Codefresh and Buddy. It does not map Jenkins, Azure DevOps or Cloud Build.
  - For GitLab, Build Signer URI = Build Config URI = `ci_config_ref_uri`, the top-level pipeline. So GitLab can't identify an isolated assessor, and only GitHub reaches `L1+isolated-assessor` today.
  - A CI-agnostic, buyer-facing profile and verifier is a differentiator in itself: autogov and GitHub attestations only work on GitHub.

## 6. Still to do this week (needs you)

- [x] Hands-on: verified autogov's own release as a consumer and inspected its VSA. See [week0-autogov-handson.md](week0-autogov-handson.md). A published PASSED VSA hides a review requirement that was not met.
- [x] Hands-on: `gh attestation verify --signer-workflow` against a bundle from a reusable workflow. Works, and the spike is confirmed.
- [x] G0 call: pivot. Build on existing attestations, as a CI-agnostic buyer-facing profile plus verifier (see poc-plan.md, Week 0).
- Moved to week 4: run autogov's reusable workflows in a repo of our own, as the reference for our GitHub template.
