# Open Trust — POC Execution Plan

Turns [open-trust-plan.md](open-trust-plan.md) into a ~6-week, one-to-two-person POC. The approach: **build as little as possible**. Existing tools do the scanning, signing and transparency. We write only the parts nobody else has: the profile, the binding of results to an artifact, the trust model, and the verifier UX.

---

## 1. Key decisions (made up front, revisited at the gates)

| # | Decision | Choice | Why |
|---|---|---|---|
| D1 | Language | **Go**, single binary `otrust` with `assess` and `verify` subcommands | in-toto, sigstore-go, OPA and go-containerregistry are all Go libraries. One static binary is easy to ship. |
| D2 | Scanners | Call the CLIs **syft**, **trivy**, **semgrep** as subprocesses, at pinned versions | No reimplementation. Each adapter is about 50 lines: run, capture JSON, compute its digest. |
| D3 | Secrets check | `trivy fs --scanners secret` | One tool fewer than adding gitleaks. |
| D4 | Vulnerability scan | `syft` makes the SBOM, then `trivy sbom` scans **that SBOM** | Ties the vulnerability results to the exact SBOM in the certificate. |
| D5 | Policy | Rego, evaluated with the embedded OPA Go library (`rego` package) | The verifier reuses the same engine to re-evaluate. `opa test` covers the fixtures. |
| D6 | Envelope | in-toto Statement v1 in DSSE, packaged as a **Sigstore bundle** (`.sigstore.json`) | Standard format. The bundle holds the certificate, signature and Rekor inclusion proof, so it verifies offline. |
| D7 | Predicate | `https://open-trust.dev/assessment/v0.1`, with fields modelled on SLSA VSA | **Week 1 gate:** if SLSA VSA v1 can carry per-check results cleanly, use VSA itself and drop the custom type. |
| D8 | Signing | **Sigstore keyless** (GitHub OIDC → Fulcio → Rekor) | No key management. The signer identity is the workflow, not a person. |
| D9 | Trust anchor | **A reusable GitHub workflow that we publish** (`open-trust/assess/.github/workflows/assess.yml@vX`) runs the assessment | This is the most important choice; see §3. |
| D10 | Artifact format | OCI image. The vendor builds with `docker buildx --output type=oci` or pushes to a registry. The subject is the **image manifest digest**. | A `docker save` tarball does not give a stable digest that matches the registry digest. OCI layout does. |
| D11 | Provenance | GitHub `actions/attest-build-provenance`. Check 6 verifies it against the subject digest. | We reuse it instead of generating provenance ourselves. |
| D12 | "Registry" | **Static files on GitHub Pages**: trust bundle, profile, revocation list (all signed) | No server. Phase 5 only has to show the files are useful, not that a service is. |

Explicitly not built: SaaS, dashboard, API server, support for other CI systems, Java-specific checks, custom crypto.

---

## 2. Repository layout

```text
open-trust/
├── cmd/otrust/            # CLI entrypoint (assess, verify)
├── internal/
│   ├── subject/           # artifact digest (OCI layout / registry ref)
│   ├── adapters/          # syft.go, trivy.go, semgrep.go — run + digest output
│   ├── policy/            # embedded Rego, evaluation
│   ├── statement/         # build in-toto statement + predicate
│   └── verify/            # bundle verify, identity check, result classification
├── profiles/
│   └── supply-chain-baseline/v1/
│       ├── profile.md     # human spec: claims + limitations
│       ├── policy.rego
│       ├── policy_test.rego
│       └── fixtures/      # pass/ fail/ evidence sets
├── .github/workflows/
│   ├── assess.yml         # THE reusable workflow vendors call
│   └── release.yml        # builds + signs otrust itself
├── trust/                 # published to Pages: trusted_root.json, revocations.json, profiles index
├── test/adversarial/      # one script per attack in §6
└── examples/spring-boot-demo/   # separate repo later; folder is fine for POC
```

---

## 3. Trust model for the POC (Level 1, plus verifiable Level 2 signals)

A vendor's own scripts can fake anything they sign. So **vendor scripts never sign.** Signing happens only inside our reusable workflow:

1. The vendor workflow builds the image, then calls `uses: open-trust/assess/.github/workflows/assess.yml@v0.1` with `image-digest` as input.
2. The reusable workflow runs as its own job. The caller **cannot inject steps** into it. It:
   - checks out the source **itself** at `github.sha`;
   - downloads a pinned `otrust` release and checks its signature;
   - runs the scanners at pinned versions, with the policy embedded in the binary;
   - signs keylessly. Fulcio puts `job_workflow_ref = open-trust/assess/...@v0.1`, the source repo, the commit and `runner_environment` into the signing certificate.
3. The verifier **requires** that the certificate identity is our workflow at an allowed version, on `github-hosted` runners.

**What this stops:** signing results that were edited, an assessment from a modified agent or policy, and swapped scanner binaries (the workflow pins and checks digests).

**What it does not stop:** a GitHub compromise, a vendor that controls the GitHub org and rewrites history before the run, or a vulnerability the scanners cannot detect.

This is the pattern slsa-github-generator uses. It still counts as Level 1 + identity-bound execution, not Level 3. The certificate must say so in its `trustLevel` and `limitations` fields.

> **Spike (week 2, day 1):** confirm that a reusable workflow can request an `id-token` and that the Fulcio certificate carries the reusable workflow's ref, not the caller's. If it does not, the fallback is plain Level 1 with a key held in a GitHub Environment secret that requires approval. Record the result.

---

## 4. The certificate (predicate draft)

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "ghcr.io/acme/svc", "digest": { "sha256": "<manifest digest>" } }],
  "predicateType": "https://open-trust.dev/assessment/v0.1",
  "predicate": {
    "profile": { "id": "supply-chain-baseline", "version": "1.0.0", "policyDigest": { "sha256": "…" } },
    "agent":   { "id": "otrust", "version": "0.1.0", "digest": { "sha256": "…" } },
    "source":  { "repo": "https://github.com/acme/svc", "revision": "<git sha>" },
    "provenance": { "predicateType": "https://slsa.dev/provenance/v1", "digest": { "sha256": "…" } },
    "timeAssessed": "2026-11-13T10:00:00Z",
    "validUntil":   "2026-12-13T10:00:00Z",
    "result": "PASSED",
    "checks": [
      { "id": "sbom",       "tool": "syft@1.x",    "result": "PASSED", "evidenceDigest": { "sha256": "…" } },
      { "id": "vulns",      "tool": "trivy@0.x",   "result": "PASSED", "summary": { "critical": 0, "high": 0 }, "evidenceDigest": {…} },
      { "id": "secrets",    "tool": "trivy@0.x",   "result": "PASSED", "evidenceDigest": {…} },
      { "id": "sast",       "tool": "semgrep@1.x", "result": "WARN",   "summary": { "error": 0, "warning": 3 }, "evidenceDigest": {…} },
      { "id": "provenance", "result": "PASSED" },
      { "id": "subject-binding", "result": "PASSED" }
    ],
    "exceptions": [{ "check": "vulns", "id": "CVE-2026-1234", "reason": "not reachable", "expires": "2026-12-01" }],
    "trustLevel": "L1-identity-bound",
    "limitations": ["Vendor controls source and GitHub org", "Scanners detect known issues only"]
  }
}
```

Raw evidence (SBOM, trivy JSON, SARIF) **stays with the vendor**. The certificate holds only digests. A vendor can hand the evidence to a customer, and `verify --evidence dir/` then checks the digests and **re-runs the policy**. That check catches a summary that does not match its evidence; it cannot catch evidence that was fabricated.

### Profile v1 policy rules (initial)

| Check | FAIL when | WARN when |
|---|---|---|
| sbom | missing or empty | — |
| vulns | any CRITICAL, or HIGH with a fix available, not excepted | HIGH with no fix available |
| secrets | any finding not excepted | — |
| sast | any semgrep `ERROR` | `WARNING` |
| provenance | missing, or subject digest mismatch | — |
| subject-binding | digest assessed ≠ digest signed | — |

Exceptions live in `.otrust/exceptions.yaml` in the vendor repo. Each needs an expiry. Every exception is copied into the certificate, so the customer sees each one.

Certificate validity: 30 days. A newer policy version never changes an old certificate. The verifier can still require a minimum profile version.

---

## 5. Milestones

### Week 0 (parallel, 3–5 days): research and customer validation, time-boxed
- Get hands-on with **Chainloop**, **Witness**, and **GitHub artifact attestations + `gh attestation verify`**. Read up on SignPath and SLSA VSA. For each, answer: what does the customer receive, how do they verify it, and is the evidence bound to the artifact?
- Book **5 conversations** (3 software buyers or security reviewers, 2 vendors). Show them the mock certificate from §4 and the `verify` output from §7. Ask: *"Would this change a procurement or deployment decision? What would you need instead?"*
- **Gate G0:** write one paragraph naming the gap. If GitHub attestations + Witness + a VSA already cover it, stop or pivot to "profiles + verifier on top of existing attestations".

### Week 1: profile spec and policy (Phase 1)
- `profile.md`: claims, required tools and versions, rules, exceptions, validity, limitations.
- `policy.rego` and `policy_test.rego`, with fixture evidence sets: one pass, one fail per rule, one excepted.
- Decide D7 (custom predicate or VSA).
- **Exit:** `opa test` passes. A second person evaluates the fixtures by hand from `profile.md` and gets the same results. That counts as the "two implementations" check, at POC scale.

### Week 2: `otrust assess` (Phase 2)
- Day 1: the spike from §3.
- Subject digest from an OCI layout or registry ref. Adapters for syft, trivy (sbom and secret) and semgrep. Policy evaluation. Statement generation. Human-readable summary on stdout.
- Run locally without signing (`--no-sign`) against the demo image.
- **Exit:** produces a correct statement and evidence directory for a passing image and a failing image.

### Week 3: signing and `otrust verify` (Phase 3)
- Sign with sigstore-go and write a `.sigstore.json` bundle. Publish `trust/trusted_root.json` (a Sigstore public-good TUF snapshot).
- `otrust verify cert.sigstore.json --image oci-layout-dir|ref [--evidence dir] [--trusted-root file] [--revocations file]`.
- Use distinct exit codes and messages: `INVALID_SIGNATURE`, `UNTRUSTED_SIGNER`, `ARTIFACT_MISMATCH`, `ASSESSMENT_FAILED`, `EVIDENCE_MISMATCH`, `EXPIRED`, `REVOKED`.
- **Exit:** verifies on a clean machine with no network access, given the bundle, the image and the trusted root.

### Week 4: reusable workflow, demo app and adversarial suite (Phases 2, 4)
- `assess.yml` reusable workflow. `release.yml` signs the `otrust` binaries.
- Minimal Spring Boot demo with a Dockerfile and a workflow that calls `assess.yml`, plus a branch with a vulnerable dependency (for example an old `log4j-core`).
- `test/adversarial/`: one script per row in §6. Run them in CI.
- **Exit:** a clean run on the demo repo produces a certificate that verifies.

### Week 5: trust files, demo and feedback (Phases 5, 6)
- `trust/revocations.json`, signed and served from Pages. `verify --online` fetches it, and runs offline without it.
- Record the six demo scenarios (§7). Write the consumer docs: one page on what the certificate proves and what it does not.
- Run the second round of customer conversations with the live demo.
- **Gate G1 (go/no-go):** apply the criteria in open-trust-plan.md §7.

---

## 6. Adversarial test matrix (expected outcomes)

| Attack | Expected under the POC trust model |
|---|---|
| Edit the policy in the vendor repo | **Prevented.** The policy is embedded in the pinned agent, and the policy digest is in the certificate. |
| Replace a scanner binary | **Prevented** on our workflow (pinned digests). **Undetectable** if the vendor signs outside it, but then the verifier rejects the signer. |
| Skip a required check | **Detected.** The policy treats a missing check as FAIL, and the verifier checks that all checks are present. |
| Change the image after assessment | **Detected** (`ARTIFACT_MISMATCH`). |
| Reuse a certificate for another image | **Detected** (`ARTIFACT_MISMATCH`). |
| Edit the certificate JSON | **Detected** (`INVALID_SIGNATURE`). |
| Sign fabricated results with the vendor's own workflow or key | **Detected** (`UNTRUSTED_SIGNER`), because the identity is not our reusable workflow. |
| Fabricate evidence *before* the scan (e.g. hide a dependency from the build context) | **Not detectable.** Document it as a limitation. |
| Use an old or revoked agent version | **Detected.** The verifier keeps an allowlist of `job_workflow_ref` versions and checks `revocations.json`. |
| Run on a self-hosted, tampered runner | **Detected.** The verifier requires `runner_environment=github-hosted`. |
| Expired certificate | **Detected** (`EXPIRED`). |

---

## 7. Demo script (the customer side)

```bash
# customer receives: image (OCI layout or registry ref) + cert.sigstore.json
otrust verify cert.sigstore.json --image ./svc-oci --trusted-root trusted_root.json
```

```text
✔ Signature valid (Rekor entry 123456, 2026-11-13T10:00Z)
✔ Signer: open-trust/assess assess.yml@v0.1 on github-hosted runner
✔ Source: github.com/acme/svc @ 3f2a9c1
✔ Artifact sha256:ab12… matches
✔ Profile supply-chain-baseline v1.0.0 (policy sha256:…)
✔ Result PASSED — 6/6 checks, 1 warning, 1 exception (CVE-2026-1234, expires 2026-12-01)
ℹ Trust level: L1-identity-bound — see limitations below
```

The six scenarios: clean pass, vulnerable dependency fails, changed image, edited certificate, revoked or expired certificate, and verification fully offline.

---

## 8. Risks and open questions

- **Reusable-workflow identity in Fulcio:** the §3 spike decides whether Level-2 signals hold.
- **Differentiation:** GitHub artifact attestations combined with a VSA may already cover most of this. G0 has to answer that honestly.
- **Semgrep on Java:** the free rules may be noisy. If they are, mark SAST as WARN-only in v1 instead of tuning rules.
- **Image digest stability:** test early that the OCI-layout digest equals the registry digest for the same build.
- **Demand:** the technical POC proves nothing about willingness to pay. The customer conversations in weeks 0 and 5 are the real gate.
