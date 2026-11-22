# Open Trust verification: ASSESSMENT_FAILED

The certificate is genuine, but the image failed the assessment. Review the failed checks before you deploy it.

Certificate `gh/otrust-image-vulnerable/certificate.sigstore.json`, image `gh/image-vulnerable/image.oci.tar`.

> ASSESSMENT_FAILED: assessment result is FAILED

## What this proves

- ✔ Signed by "Open Trust assessor (78c55a0a2b31ae0fc480f675757681ad0b473d36) for open-trust-demo" from your trust policy (https://github.com/dario-mr/open-trust/.github/workflows/assess.yml@78c55a0a2b31ae0fc480f675757681ad0b473d36)
- ✔ For exactly this image: sha256:039ea714285369439b9d6f222f8781a5913bbb574f15db5646b61a9e475080c0
- ✔ Built from https://github.com/dario-mr/open-trust-demo @ 15ce3ae0b95d2b382b8a296770e35fe3a55ede89 (github)
- ✔ Assessed 2026-11-21T23:37:33Z with https://open-trust.dev/profiles/supply-chain-baseline/1.1.0, valid until 2026-12-21T23:37:33Z
- ✔ Trust level L1+isolated-assessor: the published Open Trust assessor ran unmodified on a hosted runner; the vendor could not add steps to it

## Checks, as the vendor's assessment reports them

- ✔ sbom PASSED
- ✘ vulns FAILED
  - CRITICAL CVE-2021-44228 in org.apache.logging.log4j:log4j-core@2.14.1 (fixed in: 2.15.0, 2.3.1, 2.12.2)
  - CRITICAL CVE-2021-45046 in org.apache.logging.log4j:log4j-core@2.14.1 (fixed in: 2.16.0, 2.12.2, 2.3.1)
  - HIGH CVE-2021-45105 in org.apache.logging.log4j:log4j-core@2.14.1 (fixed in: 2.12.3, 2.17.0, 2.3.1)
- ✔ secrets PASSED
- ⚠ sast WARN
  - semgrep reported 6 scan error(s)
- ✔ provenance PASSED
- ✔ subject_binding PASSED
- ℹ SAST rules p/default sha256:43b45d8719a2f40ca83a0b88750ca4bd3583baa9b48380ef9d28d4c51bae966e (1074 rules, fetched 2026-11-21T23:37:09Z)

## Risks the vendor accepted

- ✘ Unmet vulns: CRITICAL CVE-2021-44228 in org.apache.logging.log4j:log4j-core@2.14.1 (fixed in: 2.15.0, 2.3.1, 2.12.2)
- ✘ Unmet vulns: CRITICAL CVE-2021-45046 in org.apache.logging.log4j:log4j-core@2.14.1 (fixed in: 2.16.0, 2.12.2, 2.3.1)
- ✘ Unmet vulns: HIGH CVE-2021-45105 in org.apache.logging.log4j:log4j-core@2.14.1 (fixed in: 2.12.3, 2.17.0, 2.3.1)

## What this does not prove

- Scanners detect known vulnerabilities and pattern-matched code flaws only
- Does not prove the scanned source is the complete source of the artifact
- Vendor-attested (Level 1): the vendor controls the environment the assessment ran in
- That the image's packages and vulnerabilities are as the vendor reports: run with --recheck to scan it yourself

## Notes

- ℹ revocations checked against the signed Open Trust list (1 entry, valid until 2026-11-30T16:28:12Z)
