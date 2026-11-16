# Gate G1: technical go/no-go

**Verdict: GO, technically. Narrowed, and with demand unvalidated.** The verdict can only be "technically viable", not "worth building". Customer interviews and a pilot are out of scope for this POC (poc-plan.md §5), so the two demand criteria in open-trust-plan.md §7 are still open.

## The five POC questions (open-trust-plan.md §4)

| Question | Answer | Evidence |
|---|---|---|
| 1. Can a useful assessment run in a vendor-controlled pipeline? | **Yes** | The same Spring Boot demo was assessed on GitHub Actions and GitLab CI with pinned Syft, Trivy and Semgrep. Log4Shell fails it, and the clean build passes. |
| 2. Can the results be bound to the exact artifact? | **Yes** | The subject is the OCI image manifest digest, and every blob is verified. A swapped image gives `ARTIFACT_MISMATCH`. Signed SLSA provenance must name the same digest. |
| 3. Can a third party verify without trusting our cloud? | **Yes** | `otrust verify` runs in a container with no network. The only network use is the optional `--online` revocation fetch, and that list is signed and checked like a certificate. |
| 4. Can the trust limitations be explicit and still meaningful? | **Yes, with an honest ceiling** | There are three trust levels, recomputed by the verifier from the signature and never taken from the certificate. Limitations, exceptions and unmet requirements are printed even on PASSED. |
| 5. Is it simple enough to adopt? | **Mostly** | GitHub: one `uses:` job pinned by commit. GitLab: one `include:` and a few variables. Vendors still need an OCI-layout build output, and Docker for the scanners. |

The success condition ("a developer can integrate the tool, produce a certificate and give another person enough to verify it independently") is met. [demo/scenarios.sh](../demo/scenarios.sh) does exactly that from the buyer's side, with the released binary. The recorded run is [demo/RESULTS.txt](../demo/RESULTS.txt): 12 of 12 scenarios gave the expected result. Releases are reproducible: the v0.1.1 binary, the GitHub assessor and the GitLab template all have the same linux/amd64 digest, and that digest is the `agentDigest` in the certificates.

## Technical criteria (open-trust-plan.md §7)

| Dimension | Result | Why |
|---|---|---|
| **Differentiation** | **Pass, narrowly** | Every building block is commodity: Sigstore, in-toto, VSA, scanners and Rego. Liatrio autogov already does reusable workflows plus a Rego VSA, but on GitHub only. Chainloop and Witness are cross-CI but built for internal release gating. SignPath covers origin verification of signing, not assessment. What survives is product rather than technology: a **buyer-facing, versioned profile** with stated claims and limitations; a **verifier that explains** what was proven, at which trust level and with which exceptions; and **one certificate format across CIs**. That is a thin moat. |
| **Trust** | **Pass** | It is clearly stronger than a vendor-signed PDF. On GitHub, `L1+isolated-assessor` stops the vendor from changing the assessment, which an ordinary vendor signature can't offer. Ten attacks were tested: edited certificate, wrong artifact, untrusted signer, inflated trust level, lying summary (caught by re-evaluating with `--evidence`), revoked agent, revoked artifact, skipped files via `.semgrepignore` (fixed and recorded), cross-CI policy confusion, and an expired certificate (unit test). Two limits remain whatever the level: evidence fabricated *before* the scan, and source completeness. |
| **Portability** | **Partial** | Verification is fully portable: offline, one static binary and a public trust root. The same commit built on GitHub and on GitLab gave different image digests, so the certificates are per-pipeline. Assessment runs on any CI, but **isolation is GitHub-only**. GitLab's OIDC token names the vendor's pipeline, never an included template, so GitLab stops at `L1+ci-identity`. Jenkins-style CIs stop at `L1`. If buyers only value isolation, the cross-CI story weakens to "same format, lower proof". |
| **Privacy** | **Pass, with one caveat** | Source and raw evidence never leave the vendor; the certificate carries only digests, and the vendor chooses whether to share evidence. *Caveat:* keyless signing writes the repository and workflow identity to the public Rekor log. Private repositories need a private Fulcio/Rekor or KMS-based `L1`. |
| **Adoption** | **Pass** | It takes about 10 lines of CI configuration on GitHub and about 8 on GitLab, plus a trust policy on the buyer side. Friction points: an OCI-layout tarball (not a registry reference), Docker-in-Docker on GitLab, and roughly 2–4 minutes of scan time. |
| Usefulness | *Not assessed* | It needs buyers. Out of scope for this POC. |
| Economics | *Not assessed* | It needs demand and pricing. The maintenance load is visible, though: scanner pins, the vulnerability DB, the Semgrep ruleset (still not pinned by content) and trust-root rotation. |

## Go criteria (open-trust-plan.md §7)

| Criterion | Status |
|---|---|
| At least one clearly differentiated capability survives competitive research | **Met**: a buyer-facing profile and verifier that are honest about trust levels across CIs. It is a product differentiator, not a technical one. |
| A complete assessment and independent verification flow works | **Met** on GitHub, on GitLab and with a key (generic CI), including signed releases and a signed revocation list |
| The trust model is understandable and defensible | **Met** with three levels, each with a one-line "proves / doesn't prove" ([consumer guide](../docs/consumer-guide.md)) |
| At least three vendors or buyers confirm the problem matters | **Not tested** (out of scope) |
| At least one potential customer agrees to a pilot | **Not tested** (out of scope) |

## No-go and pivot criteria

| Criterion | Status |
|---|---|
| Existing products already solve it adequately | **Not for buyers.** For internal gating on GitHub, autogov plus GitHub attestations comes close. |
| The certificate is just an SBOM plus a scanner report | **No.** It binds a policy decision to an artifact digest, a pinned methodology and a proven signer identity, with a recomputed trust level and revocation. The SBOM and reports are only optional evidence. |
| The trust model can't support the claims customers expect | **Open risk.** If customers expect "independently audited", every level here is still vendor-attested (Level 1). |
| Customers see no value beyond CI reports | **Not tested** |
| Integration and maintenance cost more than the value | **Not tested** for value. Cost looks modest for integration and is ongoing for maintenance. |

## Recommendation

1. **Go to demand validation before more engineering.** The technology is not the risk. Show the consumer guide and the demo to 3–5 security and procurement people on the buyer side, and to 2–3 vendors. Ask whether `L1+ci-identity` is worth anything to them, or only isolation is.
2. If demand holds, the next technical steps, in order:
   - a CI-agnostic isolated assessor (a separate assessor runner, or GitLab component identity if it ever ships), which decides portability;
   - pinning the Semgrep ruleset by content;
   - registry references instead of OCI tarballs;
   - private-repository signing.
3. If demand is weak, pivot along the narrower line the plan suggests: **standardized assurance profiles plus a buyer-side verifier** for attestations vendors already produce (GitHub attestations, autogov VSAs), without running the assessment ourselves.
