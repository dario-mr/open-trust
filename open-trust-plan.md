# Product Discovery & POC Plan: Verifiable Software Assurance

## 1. Product idea

### Working concept

Build a developer-oriented tool that automatically assesses software supply-chain integrity and selected software quality/security properties directly inside the software owner's CI/CD infrastructure.

After each relevant build or commit, it produces a cryptographically signed, independently verifiable **Software Assurance Certificate**.

The certificate binds the assessment to:
- The exact source revision.
- The resulting build artifact (container image, binary, package, etc.).
- The assessment policy and its version.
- The checks that were executed and their results.
- The identity of the assessment tool and the CI environment.
- The timestamp and signature.

A software vendor can provide this certificate to customers without exposing its source code or requiring the customer to repeat the assessment.

### Core value proposition

**Prove what was checked, against which artifact, under which rules, and whether the evidence has been tampered with — without disclosing source code.**

The product should make software assurance:
- Automated rather than dependent on manual audits.
- Repeatable across commits and releases.
- Cryptographically verifiable by third parties.
- Portable across CI/CD providers and software vendors.
- Transparent about the scope and limitations of each assessment.

### Non-goals

The product must not claim to:
- Prove that software is bug-free or completely secure.
- Guarantee that a vendor is honest.
- Replace penetration testing, formal certification or independent security audits.
- Prove that checks were executed merely because a vendor signed a JSON report.
- Require source code or proprietary scan results to be uploaded to our infrastructure.

---

## 2. Fundamental architectural decision

**All assessment checks execute on the software owner's infrastructure.**

Our product does not receive source code and does not execute the assessment in its cloud.

The architecture consists of three components:

1. **Local assessment agent**
   - Runs in the vendor's CI/CD pipeline.
   - Executes and orchestrates checks.
   - Collects evidence.
   - Associates evidence with the source revision and build artifact.
   - Produces signed attestations and a certificate.

2. **Trust and policy infrastructure (optional cloud service)**
   - Publishes versioned assessment profiles and policies.
   - Distributes signed agent releases.
   - Hosts public verification metadata.
   - Provides certificate discovery and revocation.
   - May provide vulnerability intelligence and policy updates.
   - Never needs source code or unrestricted access to private evidence.

3. **Independent verification tool**
   - Allows a customer to verify a certificate locally.
   - Checks signatures, artifact identity, policy version and assessment evidence.
   - Does not require access to the vendor's CI environment.

The certificate should remain verifiable even if our cloud service becomes unavailable. The cloud registry is a convenience and trust-distribution mechanism, not a mandatory dependency.

### Critical trust limitation

The vendor controls its own infrastructure. Therefore, a malicious vendor could modify the agent, skip checks, fabricate evidence or misuse its signing key.

A signature proves the origin and integrity of a statement. It does not prove that the statement is true.

The product must explicitly distinguish:

**Level 1 — Vendor-attested**
- Checks are executed by the vendor's CI.
- The vendor signs the results.
- The customer verifies integrity and provenance.
- Trust ultimately depends on the vendor's CI controls.

**Level 2 — Verified execution**
- The assessment uses protected, versioned agent binaries and policies.
- CI identity and workflow provenance are validated.
- Evidence is independently checked against the policy.
- Signing credentials are protected from arbitrary pipeline scripts.
- The product makes stronger claims about the assessment process, subject to the actual trust guarantees implemented.

**Level 3 — Independently trusted execution**
- Assessment execution is rooted in a separately trusted environment or execution mechanism.
- Potential approaches include hardware-backed attestation, trusted execution environments or independently controlled assessment infrastructure.
- This is a future research direction, not a POC requirement.

Do not present Level 1 as Level 2 or Level 3.

---

## 3. Existing ecosystem to reuse

The POC should build on existing standards and tools rather than inventing a new supply-chain format.

| Area | Candidate technology | Purpose |
|---|---|---|
| Attestation format | in-toto / DSSE | Standardized signed statements |
| Provenance | SLSA provenance | Describe how an artifact was built |
| Verification | SLSA Verifier | Validate provenance and verification summaries |
| Signing | Sigstore / Cosign | Cryptographic signing and identity |
| Build evidence | Syft | Generate SBOMs |
| Vulnerability scanning | Trivy | Scan dependencies and artifacts |
| Code security | Semgrep | Static security analysis |
| Policy engine | OPA / Rego | Evaluate assessment rules |
| Evidence collection | Witness | Capture and verify SDLC activities |
| Risk graph (future) | GUAC | Correlate SBOM, provenance and vulnerability information |

Investigate Chainloop and SignPath as direct competitive references. Also study Witness and SLSA Verification Summary Attestations (VSA) before designing any proprietary certificate format.

The product should add value through its assessment profiles, trust model, integration experience and portable verification — not by reinventing SBOMs, signatures or provenance.

---

## 4. POC objectives

The POC should answer five questions:

1. Can we reliably execute a useful assessment in a vendor-controlled CI pipeline?
2. Can we bind its results to the exact artifact produced by that pipeline?
3. Can a third party verify the resulting certificate without trusting our cloud?
4. Can we make the trust limitations explicit while still providing meaningful assurance?
5. Is the workflow sufficiently simple that a development team would actually adopt it?

The POC is successful if a developer can integrate the tool into an existing pipeline, produce a certificate, and give another person enough information to independently verify it.

---

# 5. POC implementation plan

## Phase 0 — Product and ecosystem validation

**Goal:** Avoid building something that already exists.

Tasks:
- Study Chainloop, Witness, SignPath and SLSA VSA in depth.
- Identify their supported assessment workflows and trust models.
- Compare their local execution capabilities and evidence formats.
- Investigate how they bind evidence to artifacts.
- Determine whether their output can already satisfy the intended use case.
- Identify what a customer receives and how they verify it.
- Document gaps rather than assuming that a unified certificate is missing.

Deliverable:
- Competitive analysis.
- A short list of genuinely differentiated product capabilities.
- A decision on whether to build a new product, extend an existing ecosystem or abandon the idea.

**Exit criterion:** We can articulate a concrete customer problem that existing products do not adequately solve.

## Phase 1 — Define the first assurance profile

**Goal:** Define precisely what the certificate means.

Start with one deliberately narrow profile:

### Initial profile: Software Supply-Chain Baseline

Required checks:
1. Generate an SBOM.
2. Scan dependencies and container/image vulnerabilities.
3. Check for known vulnerable dependencies.
4. Check for exposed secrets.
5. Run static security analysis.
6. Validate build provenance.
7. Verify that the resulting artifact digest matches the assessed artifact.
8. Evaluate the results against a versioned policy.

Define:
- Which tools and versions are required.
- Which checks are mandatory.
- Which findings cause failure.
- Which findings are warnings.
- How exceptions are declared and recorded.
- How policy changes affect previously issued certificates.
- How long certificates remain valid.

Avoid claiming that this profile represents a complete security audit. Call it something precise, such as "Supply-Chain Baseline v1".

Deliverables:
- Written profile specification.
- Machine-readable policy.
- Example passing and failing assessments.
- Defined certificate claims and limitations.

**Exit criterion:** Two independent implementations of the profile should be able to evaluate the same evidence consistently.

## Phase 2 — Build the local assessment agent

**Goal:** Demonstrate that the entire assessment can run in customer infrastructure.

Implement a CLI with commands conceptually similar to:

```bash
assurance init
assurance assess
assurance verify ./certificate.dsse
```

The exact command interface can be refined later.

The `assess` command should:

1. Identify the CI environment and source revision.
2. Identify the build artifact and calculate its digest.
3. Execute the configured checks.
4. Collect tool outputs and structured evidence.
5. Evaluate evidence against the selected profile.
6. Generate a machine-readable assessment statement.
7. Sign the statement.
8. Output the certificate and a human-readable summary.

Initial integrations:
- GitHub Actions.
- Docker/container image.
- Syft.
- Trivy.
- Semgrep.
- OPA.

Keep the agent modular. Each check should be an adapter with a well-defined input and output format.

Do not upload source code or raw evidence to a remote service.

Deliverables:
- Working CLI.
- Docker image or downloadable binary.
- GitHub Actions example.
- Example assessment output.

**Exit criterion:** A clean repository can run the agent in CI and produce a valid certificate for a real container image.

## Phase 3 — Certificate and verification

**Goal:** Make the result independently verifiable.

Prefer an existing standard such as an in-toto statement wrapped in DSSE rather than inventing a certificate format.

The statement should include:
- Product and artifact identity.
- Artifact digest.
- Source repository identity and revision.
- Build provenance reference.
- Assessment profile and version.
- Assessment agent identity and version.
- Checks performed and their results.
- Policy digest.
- Assessment timestamp.
- Signing identity.
- Relevant limitations and exceptions.

Implement a separate verification CLI.

A customer should be able to run:

```bash
assurance verify certificate.dsse \
  --artifact my-service.tar
```

Verification should check:
- Cryptographic signature.
- Signer identity and trust root.
- Artifact digest.
- Certificate structure.
- Policy identity and version.
- Evidence integrity.
- Assessment result.
- Expiration and revocation information, where available.

The verifier must fail if the artifact differs from the one referenced in the certificate.

It must also distinguish:
- Invalid signature.
- Untrusted signer.
- Artifact mismatch.
- Failed assessment.
- Missing evidence.
- Expired or revoked certificate.

Deliverables:
- Certificate schema or standardized statement profile.
- Independent verification CLI.
- Documentation for third-party consumers.
- Tampering test suite.

**Exit criterion:** A customer can verify a certificate on a separate machine without access to the vendor's repository, CI system or our cloud.

## Phase 4 — Establish a credible trust model

**Goal:** Determine what the certificate can genuinely prove.

This is the most important technical research phase.

Investigate:
- Protected agent distribution and binary integrity.
- Signed and immutable assessment policies.
- GitHub Actions OIDC identity and workflow provenance.
- Protected CI workflows and isolated ephemeral runners.
- Signing keys held outside arbitrary pipeline scripts.
- KMS/HSM-backed signing.
- Hardware-backed attestation and trusted execution environments.
- Independent validation of submitted evidence.

Implement the strongest practical trust model that does not require moving source code or checks outside the vendor's infrastructure.

For the POC, clearly label the initial result as vendor-attested if that is the actual guarantee.

Create adversarial tests:
- Modify the assessment policy.
- Replace a scanner binary.
- Skip a required check.
- Change the artifact after assessment.
- Attempt to reuse a certificate for a different artifact.
- Attempt to sign fabricated evidence.
- Use an outdated or revoked agent version.

Document which attacks are prevented, detected or impossible to detect under the current trust model.

Deliverables:
- Threat model.
- Trust-level specification.
- Attack test results.
- Explicit list of guarantees and limitations.

**Exit criterion:** We can explain, with evidence, what a customer must trust and what the certificate independently verifies.

## Phase 5 — Minimal public trust infrastructure

**Goal:** Test whether a registry adds meaningful value.

Only build this after local assessment and verification work.

Possible functionality:
- Publish certificates and public metadata.
- Publish signed assessment profiles.
- Distribute trusted agent versions.
- Maintain signing identities and trust roots.
- Publish revocation information.
- Allow lookup by artifact digest.
- Generate a public verification page.

Keep private evidence local by default.

The system should not be required for basic certificate verification. A self-contained certificate and trust bundle should be sufficient for offline verification, subject to the availability of current revocation information.

Deliverables:
- Minimal registry API.
- Public certificate lookup.
- Policy distribution.
- Revocation mechanism.

**Exit criterion:** Registry functionality demonstrably improves discoverability or trust management without becoming a single point of failure for verification.

## Phase 6 — End-to-end demonstration

**Goal:** Validate the complete product experience.

Create two independent environments:

**Vendor environment**
- A sample Java/Spring Boot application.
- GitHub Actions pipeline.
- Docker build.
- Local assessment agent.
- Certificate generation.

**Customer environment**
- No access to the source repository.
- Receives the container image and certificate.
- Runs the verification CLI.
- Gets a clear pass/fail result and explanation.

Demonstrate:
1. A clean build passing all checks.
2. A vulnerable dependency causing an assessment failure.
3. A changed artifact failing verification.
4. A modified certificate failing signature verification.
5. An outdated or revoked certificate being rejected when current trust information is available.
6. Verification working without our cloud service.

Deliverables:
- Public demonstration repository.
- Recorded end-to-end workflow.
- Documentation.
- Example certificates and verification results.

**Exit criterion:** A technically competent third party understands what the certificate proves, can verify it independently, and finds the workflow useful.

---

# 6. Explicitly out of scope for the POC

Do not build these before validating demand:

- A complete SaaS dashboard.
- Multi-tenant enterprise administration.
- A large marketplace of assessment profiles.
- Support for every CI/CD provider.
- A proprietary vulnerability database.
- A complete compliance framework.
- Automatic remediation.
- Complex billing and subscription management.
- A hardware-backed execution platform.
- A custom cryptographic protocol.

These features may eventually be valuable, but they do not validate the central product hypothesis.

---

# 7. Evaluation criteria and go/no-go decision

After the end-to-end demonstration, evaluate the idea against the following criteria.

| Dimension | Question |
|---|---|
| Differentiation | Is there a meaningful gap versus Chainloop, Witness and SignPath? |
| Trust | Can the product make stronger or clearer guarantees than ordinary vendor-signed reports? |
| Portability | Can customers verify results without vendor-specific infrastructure? |
| Privacy | Can sensitive source code and evidence remain entirely on the vendor's infrastructure? |
| Adoption | Can integration be achieved with a small CI configuration change? |
| Usefulness | Does the certificate help customers make procurement or deployment decisions? |
| Economics | Is the product valuable enough to justify ongoing maintenance, policy updates and vulnerability intelligence? |

### Go criteria

Continue investing if:
- At least one clearly differentiated capability survives competitive research.
- A complete local assessment and independent verification flow works.
- The trust model is understandable and defensible.
- At least three potential software vendors or software buyers confirm that the problem is meaningful.
- At least one potential customer agrees to pilot the solution.

### No-go or pivot criteria

Stop or pivot if:
- Existing products already solve the problem adequately.
- The certificate is effectively just another SBOM plus scanner report.
- The trust model cannot support the claims customers expect.
- Customers see no value in the certificate beyond their existing CI reports.
- Integration and maintenance costs outweigh the value of the assurance provided.

A pivot could focus on a narrower area, such as standardized assurance profiles, artifact-bound verification, or a lightweight independent verification layer for existing attestations.

---

# 8. Suggested implementation boundaries

For the POC, optimize for simplicity and reuse rather than a large distributed architecture.

Suggested components:

```text
assurance/
├── cli/
├── assessment-engine/
├── check-adapters/
│   ├── sbom/
│   ├── vulnerabilities/
│   ├── secrets/
│   └── static-analysis/
├── policy-engine/
├── attestation/
├── signing/
├── verifier/
├── registry/             # Optional, later phase
└── examples/
    └── spring-boot-demo/
```

Prefer standard formats and existing tooling wherever possible.

Keep the assessment engine independent of the CLI and CI provider. This makes it easier to add integrations later without changing the core assessment logic.

---

# 9. Recommended execution order

Do not execute all phases as one large implementation project.

1. **Research:** Compare existing products and validate the gap.
2. **Specification:** Define one assurance profile and its guarantees.
3. **Local agent:** Run real checks and collect evidence.
4. **Certificate:** Bind evidence to an artifact and sign it.
5. **Verifier:** Verify it on a completely separate machine.
6. **Threat model:** Attack the implementation and document trust limitations.
7. **Demo:** Show the complete vendor-to-customer workflow.
8. **Customer validation:** Obtain feedback and pilot commitments.
9. **Decision:** Commit, pivot or abandon.

## Final principle

The product should not sell a badge saying "this software is secure".

It should provide a portable, cryptographically verifiable statement explaining:

**This exact artifact was assessed using this exact methodology, these checks produced these results, this evidence is intact, and these are the trust assumptions behind the assessment.**

The POC succeeds when that statement is genuinely useful to someone other than the person who generated it.