# Checking an Open Trust certificate: a guide for buyers

A vendor sends you software and an **Open Trust certificate** for it. This page explains what the certificate proves, what it does not, and how to check it yourself.

## What a certificate says

*This exact artifact (by digest) was assessed with this exact profile and these pinned tools. These were the results, and these risks were accepted. Here is how far you can trust that the assessment really ran as stated.*

It does **not** say the software is secure. The scanners find *known* vulnerabilities, leaked secrets and *pattern-matched* code flaws, nothing more. The checks are listed in [Supply-Chain Baseline v1](../profiles/supply-chain-baseline/v1/profile.md): SBOM, vulnerabilities, secrets, static analysis, build provenance and artifact binding.

## Get otrust

Download the binary for your platform from the [releases](https://github.com/dario-mr/open-trust/releases) and check it before you rely on it. With the GitHub CLI, this proves the binary was built by this repository's release workflow:

```bash
gh release download v0.1.9 -R dario-mr/open-trust -p otrust-linux-amd64   # or -darwin-arm64, …
gh attestation verify otrust-linux-amd64 -R dario-mr/open-trust \
  --signer-workflow dario-mr/open-trust/.github/workflows/release.yml
chmod +x otrust-linux-amd64 && mv otrust-linux-amd64 otrust
```

Without `gh`, compare the binary with `SHA256SUMS` from the same release (`sha256sum -c --ignore-missing SHA256SUMS`). That checks the download, not who built it.

## Check it

You need the artifact (an OCI image, as a file or as a registry reference pinned by digest, `registry/name@sha256:…`), the certificate (`certificate.sigstore.json`) and **your own** trust policy. The trust policy is your decision about whose certificates you accept. There is no default.

```bash
otrust verify certificate.sigstore.json --image image.oci.tar --trust-policy trust.yaml --online
  [--trusted-root root.json]          # instead of --online: fully offline (`gh attestation trusted-root > root.json`)
  [--evidence otrust-out/]            # if the vendor shares the raw evidence
  [--recheck]                         # scan the image yourself and compare (needs Docker)
  [--previous old.sigstore.json]      # list what changed since an earlier release
  [--report report.md]                # also write the report as Markdown, to pass on
```

`--online` fetches two things: Sigstore's trusted root (checked against the root built into otrust), needed to check a keyless certificate's signature, and the signed Open Trust revocation list. To verify with no network at all, save the trusted root once with `gh attestation trusted-root > root.json`, pass `--trusted-root root.json` instead of `--online`, and pass the image as a file. A registry reference pulls the image first, and the certificate must name that image (a different digest gives `ARTIFACT_MISMATCH`). `--evidence` re-checks the vendor's raw scan output against the certificate and re-runs the policy, which catches a summary that does not match its evidence.

### Re-check: don't take the vendor's word for the image

`--recheck` runs the profile's pinned SBOM and vulnerability scanners yourself, on the image you received, with today's vulnerability database (about 20 seconds plus the database download). It works the same whatever CI the vendor used and whatever trust level the certificate has, because it needs no trust in the vendor's pipeline.

- **A vulnerability that was public well before the vendor's scan but is missing from the certificate** gives `RECHECK_MISMATCH`. The vendor's scan should have found it. A vulnerability published less than 30 days before the vendor's scan counts as new instead, since severities are often re-rated in the first weeks.
- **With `--evidence`**, it also compares the packages in the image with the vendor's SBOM. Any difference gives `RECHECK_MISMATCH`.
- **A vulnerability published after the vendor's scan** is not the vendor's fault: an honest certificate for an image that fails today gives `OUTDATED`. This is the result to gate deployments on.

The re-check covers only the image checks. Secrets and static analysis need the source, which you don't have.

A sample `trust.yaml` that accepts only the Open Trust assessor at a pinned version, assessing one vendor repository on a GitHub-hosted runner:

```yaml
minTrustLevel: L1+isolated-assessor
signers:
  - name: Acme svc, via the Open Trust assessor v0.1.9
    issuer: https://token.actions.githubusercontent.com
    sourceRepo: https://github.com/acme/svc
    sourceRef: refs/heads/main
    buildSigner: ^https://github\.com/dario-mr/open-trust/\.github/workflows/assess\.yml@<commit of v0.1.9>$
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
| Under-report the image's packages or known vulnerabilities | Caught with `--recheck` | Caught with `--recheck` | Caught with `--recheck` |

## Reading the result

The report starts with the verdict and what it means for you, in one sentence. Then it lists:

- **What this proves**: the signer, the exact image, the source revision, the assessment date and the trust level in plain words, plus the evidence and re-check results if you asked for them.
- **The checks**, as the vendor's assessment reports them, with every finding.
- **Risks the vendor accepted**: each exception, with a reason and an expiry date, and any unmet requirements.
- **Your re-check** (`--recheck`) and the **changes since the previous certificate** (`--previous`): new and resolved findings, check results, source revision, trust level and exceptions. The previous certificate must pass your trust policy too; if your policy pins the assessor's commit, list the old assessor as a second signer.
- **What this does not prove**: the certificate's limitations and the limits of its trust level. **A PASSED result always shows these.** Read them, because an exception is a known risk the vendor chose to accept.

The last line is always the result code (`VERIFIED`, or `CODE: reason`), for scripts. `--report report.md` writes the same report as Markdown, ready to forward to your security or procurement team.

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
| `RECHECK_MISMATCH` | 21 | `--recheck`: your own scan contradicts the certificate (an unreported known vulnerability, or different packages) |
| `OUTDATED` | 22 | `--recheck`: the certificate is honest, but the image fails the profile with today's vulnerability data |

## What to ask the vendor for

- The certificate for **each release**, at the highest level their CI supports.
- The evidence directory, if you want to re-run the policy yourself.
- An explanation for every exception.
