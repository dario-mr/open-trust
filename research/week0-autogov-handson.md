# Week 0: autogov hands-on trial

Date: 2026-11-13. Subject: the **autogov v1.4.6 release binary** (`liatrio/autogov`). Its own release ships 5 attestation bundles and a signed VSA, so it is a real, published example of what autogov produces. I did not run the reusable workflows in my own repo. Everything below is consumer-side verification: the buyer's view.

Setup: `gh` 2.102.1. autogov ran in a `linux/amd64` Alpine container with **`--network none`**. The trusted root came from `gh attestation trusted-root` and the policy bundle from `autogov-policy-library` v1.1.11, both fetched beforehand.

## What the vendor (Liatrio) ships

| Item | Content |
|---|---|
| 5 Sigstore bundles, all with subject `autogov` sha256 `c5947ea2…` (matches the local file) | SLSA provenance v1, in-toto vulns v0.2 (**Grype** 0.118.0, 0 results), CycloneDX SBOM, `autogov.dev/metadata/v1`, `autogov.dev/source-review/v0.2` |
| Signer of all 5 | `…/liatrio/autogov-workflows/.github/workflows/rw-attest-blob.yaml@d4c4d30…`, a reusable workflow pinned by SHA |
| `vsa-PASSED.json` | SLSA VSA v1, `PASSED`, `verifiedLevels: [SLSA_BUILD_LEVEL_3]`, policy pinned by digest, 5 input attestations. Signed by a **different** reusable workflow, `rw-verify.yaml`. |

Fulcio certificate extensions, read directly from the certificate:

| OID | Value |
|---|---|
| .1.9 Build Signer URI | `liatrio/autogov-workflows/.github/workflows/rw-attest-blob.yaml@d4c4d30…` (the **reusable** workflow) |
| .1.18 Build Config URI | `liatrio/autogov/.github/workflows/attest.yaml@refs/heads/main` (the caller) |
| .1.11 Runner Environment | `github-hosted` |
| .1.12 / .1.13 Source repo / digest | `liatrio/autogov` @ `93fad35…` |

→ **The poc-plan §3 spike is confirmed empirically.** The certificate identifies the reusable workflow separately from the caller, so a verifier can pin it.

## Verification results

`gh attestation verify` (online TUF fetch, bundles from file):

| Case | Result |
|---|---|
| `-R liatrio/autogov --signer-workflow <rw-attest-blob>` | ✅ exit 0 |
| … `+ --source-digest 93fad35… --deny-self-hosted-runners` | ✅ exit 0 |
| `-R liatrio/autogov` alone (no signer flag) | ❌ exit 1. With reusable workflows you **must** add `--signer-workflow` or `--signer-repo`. |
| `--signer-repo` **and** `--signer-workflow` together | ❌ exit 1. The two flags are mutually exclusive, and nothing tells you so. |
| Tamper: one byte of the binary flipped | ❌ exit 1 (correct) |
| Tamper: wrong signer workflow / wrong owner / wrong source digest | ❌ exit 1 (correct) |

Every failure printed the same message: `Error: verifying with issuer "sigstore.dev"`. It doesn't say whether the digest, the signer or the repo was wrong.

`autogov offline` (no network):

| Case | Result |
|---|---|
| Correct blob + `--cert-identity` | ✅ 5/5 attestations verified |
| Modified blob | ❌ "5 of 5 attestations failed verification" |
| Wrong identity | ❌ same message |
| **No identity given** | ⚠️ **exit 0**. It accepts *any* valid Fulcio signature, with a printed warning. |
| `--generate-vsa` with today's policy (v1.1.11) | **Policy FAILED**: `source_review: 0 distinct approval(s), need at least 1`. Exit 0 unless you pass `--fail-on-policy-error`. |
| Policy check without `--generate-vsa` | Not evaluated at all. `--fail-on-policy-error` alone never ran it. |

## Findings that matter for Open Trust

1. **autogov already does our POC's plumbing, and it works offline.** It covers reusable-workflow signing, scanner attestations, Rego, a signed VSA, and offline verification with tamper detection. Rebuilding that would be pointless.
2. **The PASSED VSA hides a requirement that was not met.** The source-review attestation says `requirementMet: false` (0 approvals; the PR was self-merged by the single maintainer). The October VSA still says `PASSED`, with `attestation.source_review: true`, under policy digest `3adb5d97…`. Today's policy fails the same artifact. The October VSA records no exception and no limitation. **A buyer reading it cannot tell.** This is the clearest gap evidence so far, and it maps directly to our "exceptions and limitations in the certificate" plus "policy versioning" design.
3. **The policy identity is hard for a third party to check.** The VSA policy digest covers "resolved policy contents (not archive bytes)". The release archive hashes to `3e0a5c48…`, so a buyer can't easily map the digest to a policy version.
4. **It is built for an operator, not a buyer.**
   - Its defaults are unsafe for a consumer: with no identity flag, any signer is accepted, and a failed policy still exits 0.
   - The policy only runs when you generate a VSA.
   - Errors don't say what failed.
   - `gh`'s reusable-workflow flags are a trap (see above).
   
   A buyer-facing verifier with safe defaults and explained verdicts is a real, narrow product.
5. **`verifiedLevels: SLSA_BUILD_LEVEL_3`** is the only standard "meaning" in the VSA. It says nothing about vulnerability, secret or SAST outcomes, which is the part a buyer actually asks about. That supports our custom `OPENTRUST_SCB_V1` level plus a per-check extension field.

## Impact on the plan

- **G0 leans to the pivot already noted:** profiles plus a buyer verifier on top of existing attestations.
- Consider **consuming autogov output directly** instead of writing our own `assess`. Our verifier would accept autogov, `actions/attest` or Witness bundles. Open question: do vendors already use autogov or similar? Unvalidated.
- The verifier requirements now in poc-plan.md: safe defaults (the signer must be pinned, and a failed policy means a non-zero exit), one specific reason per failure, and a list of unmet requirements and exceptions in the output, even when the result is PASSED.

## Not checked

- I did not run autogov's reusable workflows in a repo of my own, so the vendor-side integration effort is unmeasured.
- I did not test container-image subjects, only a blob.
- I did not test private-repo behaviour.
- The VSA that autogov generated offline is an unsigned local file. I did not test signing it.
