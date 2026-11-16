# Checking an Open Trust certificate: a guide for buyers

A vendor sends you software and an **Open Trust certificate** for it. This page explains what the certificate proves, what it does not, and how to check it yourself.

## What a certificate says

*This exact artifact (by digest) was assessed with this exact profile and these pinned tools. These were the results, and these risks were accepted. Here is how far you can trust that the assessment really ran as stated.*

It does **not** say the software is secure. The scanners find *known* vulnerabilities, leaked secrets and *pattern-matched* code flaws, nothing more. The checks are listed in [Supply-Chain Baseline v1](../profiles/supply-chain-baseline/v1/profile.md): SBOM, vulnerabilities, secrets, static analysis, build provenance and artifact binding.

## Check it

You need the artifact (an OCI image, as a file or as a registry reference pinned by digest, `registry/name@sha256:…`), the certificate (`certificate.sigstore.json`) and **your own** trust policy. The trust policy is your decision about whose certificates you accept. There is no default.

```bash
otrust verify certificate.sigstore.json --image image.oci.tar --trust-policy trust.yaml \
  --trusted-root trusted-root.json    # Sigstore public-good root: `gh attestation trusted-root`
  [--online]                          # also check the signed revocation list
  [--evidence otrust-out/]            # if the vendor shares the raw evidence
```

Verification needs no network when you pass the image as a file. A registry reference pulls it first, and the certificate must name that image (a different digest gives `ARTIFACT_MISMATCH`). `--online` adds the one other network call, which fetches the signed revocation list. `--evidence` re-checks the vendor's raw scan output against the certificate and re-runs the policy, which catches a summary that does not match its evidence.

A sample `trust.yaml` that accepts only the Open Trust assessor at a pinned version, assessing one vendor repository on a GitHub-hosted runner:

```yaml
minTrustLevel: L1+isolated-assessor
signers:
  - name: Acme svc, via the Open Trust assessor v0.1.4
    issuer: https://token.actions.githubusercontent.com
    sourceRepo: https://github.com/acme/svc
    sourceRef: refs/heads/main
    buildSigner: ^https://github\.com/dario-mr/open-trust/\.github/workflows/assess\.yml@<commit of v0.1.4>$
    requireHostedRunner: true
```

## Trust levels: how much the signature proves

The verifier works out the level **from the signature**. Whatever level the certificate claims is ignored. Set the minimum you accept with `minTrustLevel`.

| Level | What it proves | What it does not prove |
|---|---|---|
| `L1+isolated-assessor` | The published Open Trust assessor, at a pinned version, ran on a hosted runner for this repository and commit. The vendor could not add steps to it. *GitHub Actions only, today.* | That the vendor's source is the complete source of the artifact, or that the vendor did not hide something before the build |
| `L1+ci-identity` | The vendor's own CI pipeline, for this project, branch and commit, produced and signed the assessment. *GitLab CI and other OIDC-capable CIs.* | That the vendor did not change the assessment. Their pipeline is the signer, so it could sign made-up results. |
| `L1` | Whoever holds the vendor's key signed it. *Any CI.* | Anything about how or where the assessment ran |

Every level is **vendor-attested**. Open Trust does not audit the vendor. A higher level only removes ways the vendor could cheat.

## What the verifier catches

| Attempt | `L1+isolated-assessor` | `L1+ci-identity` | `L1` |
|---|---|---|---|
| Change the artifact after it was assessed, or reuse the certificate for another one | Caught | Caught | Caught |
| Edit the certificate | Caught | Caught | Caught |
| Skip a required check, or use a different policy | Caught | Caught | Caught |
| Claim a higher trust level than the signature supports | Caught | Caught | Caught |
| Sign from an unexpected project or branch | Caught | Caught | n/a |
| A revoked artifact, assessor or signer, or an expired certificate (30 days) | Caught | Caught | Caught |
| Assessment on a tampered self-hosted runner | Caught | Caught only where the CI reports the runner type | Not caught |
| Run a modified assessor, or sign made-up results | Caught | **Not caught** | **Not caught** |
| Hide a dependency or source before the scan | **Not caught** | **Not caught** | **Not caught** |

## Reading the result

The verifier prints every check, plus the exceptions the vendor accepted (each with a reason and an expiry date), any unmet requirements, and the certificate's limitations. **A PASSED result always shows these.** Read them, because an exception is a known risk the vendor chose to accept.

| Result | Exit | Meaning |
|---|---|---|
| `VERIFIED` | 0 | Signature, signer, artifact, trust level, revocation and expiry all check out, and the assessment PASSED |
| `ASSESSMENT_FAILED` | 10 | The certificate is genuine, but the assessment FAILED. The failed checks are listed. |
| `INVALID_SIGNATURE` | 11 | The certificate was altered, or not signed properly |
| `UNTRUSTED_SIGNER` | 12 | The signer is not one your trust policy accepts |
| `TRUST_LEVEL_TOO_LOW` | 13 | The signature proves less than your `minTrustLevel` |
| `ARTIFACT_MISMATCH` | 14 | The certificate is for a different artifact |
| `EVIDENCE_MISMATCH` / `EVIDENCE_MISSING` | 15 / 16 | The shared evidence does not match the certificate, or a file is missing |
| `EXPIRED` | 17 | Older than 30 days. Ask the vendor for a fresh assessment. |
| `REVOKED` | 18 | The artifact, the assessor binary or the signer was revoked |
| `POLICY_UNKNOWN` / `MALFORMED` | 19 / 20 | This verifier does not know the profile, or the certificate is not a valid Open Trust certificate |

## What to ask the vendor for

- The certificate for **each release**, at the highest level their CI supports.
- The evidence directory, if you want to re-run the policy yourself.
- An explanation for every exception.
