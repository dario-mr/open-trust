# Open Trust verification: VERIFIED

You can rely on this certificate, within the limits listed under "What this does not prove".

Certificate `gh/otrust-image-clean/certificate.sigstore.json`, image `gh/image-clean/image.oci.tar`.

## What this proves

- ✔ Signed by "Open Trust assessor (09477585a21fdceacc434126c751fa018cad8c09) for open-trust-demo" from your trust policy (https://github.com/dario-mr/open-trust/.github/workflows/assess.yml@09477585a21fdceacc434126c751fa018cad8c09)
- ✔ For exactly this image: sha256:bfba50e2050a44429dca37b48bd98f8097f36541db12274fcdc17614cfe3392a
- ✔ Built from https://github.com/dario-mr/open-trust-demo @ a2a5809d9ff44c193f4916f8f57c9b7d6ef1d9a3 (github)
- ✔ Assessed 2026-11-22T15:19:53Z with https://open-trust.dev/profiles/supply-chain-baseline/1.2.0, valid until 2026-12-22T15:19:53Z
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
- ℹ SAST rules p/default sha256:43b45d8719a2f40ca83a0b88750ca4bd3583baa9b48380ef9d28d4c51bae966e (1074 rules, fetched 2026-11-22T15:19:30Z)

## Your re-check today: PASSED (your vulnerability DB 2026-11-22T07:05:02.616712326Z, the vendor's 2026-11-22T12:38:44.47270345Z)

- ✔ Nothing new, nothing missing

## What this does not prove

- Scanners detect known vulnerabilities and pattern-matched code flaws only
- Does not prove the scanned source is the complete source of the artifact
- Vendor-attested (Level 1): the vendor controls the environment the assessment ran in

## Notes

- ℹ revocations checked against the signed Open Trust list (1 entry, valid until 2026-11-30T16:28:12Z)
