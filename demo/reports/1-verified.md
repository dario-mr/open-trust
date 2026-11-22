# Open Trust verification: VERIFIED

You can rely on this certificate, within the limits listed under "What this does not prove".

Certificate `gh/otrust-image-clean/certificate.sigstore.json`, image `gh/image-clean/image.oci.tar`.

## What this proves

- ✔ Signed by "Open Trust assessor (78c55a0a2b31ae0fc480f675757681ad0b473d36) for open-trust-demo" from your trust policy (https://github.com/dario-mr/open-trust/.github/workflows/assess.yml@78c55a0a2b31ae0fc480f675757681ad0b473d36)
- ✔ For exactly this image: sha256:d38134b6811e0b432e1b3f029cf5495fb69744029c784be325178a5b95a3b3db
- ✔ Built from https://github.com/dario-mr/open-trust-demo @ 15ce3ae0b95d2b382b8a296770e35fe3a55ede89 (github)
- ✔ Assessed 2026-11-21T23:37:33Z with https://open-trust.dev/profiles/supply-chain-baseline/1.1.0, valid until 2026-12-21T23:37:33Z
- ✔ Trust level L1+isolated-assessor: the published Open Trust assessor ran unmodified on a hosted runner; the vendor could not add steps to it
- ✔ The vendor's evidence matches its digests and re-evaluates to the same results
- ✔ Your own scan of the image agrees with the certificate, and its packages match the vendor's SBOM

## Checks, as the vendor's assessment reports them

- ✔ sbom PASSED
- ✔ vulns PASSED
- ✔ secrets PASSED
- ⚠ sast WARN
  - semgrep reported 6 scan error(s)
- ✔ provenance PASSED
- ✔ subject_binding PASSED
- ℹ SAST rules p/default sha256:43b45d8719a2f40ca83a0b88750ca4bd3583baa9b48380ef9d28d4c51bae966e (1074 rules, fetched 2026-11-21T23:37:09Z)

## Your re-check today: PASSED (your vulnerability DB 2026-11-21T13:02:47.203212637Z, the vendor's 2026-11-21T18:38:32.889609542Z)

- ✔ Nothing new, nothing missing

## What this does not prove

- Scanners detect known vulnerabilities and pattern-matched code flaws only
- Does not prove the scanned source is the complete source of the artifact
- Vendor-attested (Level 1): the vendor controls the environment the assessment ran in

## Notes

- ℹ revocations checked against the signed Open Trust list (1 entry, valid until 2026-11-30T16:28:12Z)
