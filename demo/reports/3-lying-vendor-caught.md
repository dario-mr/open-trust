# Open Trust verification: RECHECK_MISMATCH

Your own scan of the image contradicts the certificate: the vendor's results are not reliable for this image.

Certificate `lie.sigstore.json`, image `gh/image-vulnerable/image.oci.tar`.

> RECHECK_MISMATCH: 3 failing vulnerabilities were public long before the vendor's scan but are not in the certificate

## What this proves

- ✔ Signed by "Acme Jenkins key" from your trust policy (key e4IQc3UlmEqVC7z7NQw0/TMbrw8AP0hDeEV7wh0qwLM=)
- ✔ For exactly this image: sha256:039ea714285369439b9d6f222f8781a5913bbb574f15db5646b61a9e475080c0
- ✔ Built from https://github.com/dario-mr/open-trust-demo.git @ 15ce3ae0b95d2b382b8a296770e35fe3a55ede89 (generic)
- ✔ Assessed 2026-11-22T12:30:31Z with https://open-trust.dev/profiles/supply-chain-baseline/1.1.0, valid until 2026-12-22T12:30:31Z
- ✔ Trust level L1: whoever holds the vendor's key signed it
- ✘ Your own scan of the image contradicts the certificate

## Checks, as the vendor's assessment reports them

- ✔ sbom PASSED
- ✔ vulns PASSED
- ✔ secrets PASSED
- ⚠ sast WARN
  - semgrep reported 6 scan error(s)
- ⚠ provenance WARN
  - provenance is not signed
- ✔ subject_binding PASSED
- ℹ SAST rules p/default sha256:43b45d8719a2f40ca83a0b88750ca4bd3583baa9b48380ef9d28d4c51bae966e (1074 rules, fetched 2026-11-22T12:30:20Z)

## Your re-check today: FAILED (your vulnerability DB 2026-11-21T13:02:47.203212637Z, the vendor's 2026-11-21T13:02:47.203212637Z)

- ✘ Unreported, though public before the vendor's scan: CRITICAL CVE-2021-44228 in org.apache.logging.log4j:log4j-core@2.14.1 (fixed in: 2.15.0, 2.3.1, 2.12.2), published 2021-12-10
- ✘ Unreported, though public before the vendor's scan: CRITICAL CVE-2021-45046 in org.apache.logging.log4j:log4j-core@2.14.1 (fixed in: 2.16.0, 2.12.2, 2.3.1), published 2021-12-14
- ✘ Unreported, though public before the vendor's scan: HIGH CVE-2021-45105 in org.apache.logging.log4j:log4j-core@2.14.1 (fixed in: 2.12.3, 2.17.0, 2.3.1), published 2021-12-18

## What this does not prove

- Scanners detect known vulnerabilities and pattern-matched code flaws only
- Does not prove the scanned source is the complete source of the artifact
- Vendor-attested (Level 1): the vendor controls the environment the assessment ran in
- Signed with a vendor-held key: proves who signed, not which pipeline ran the assessment
- Anything about how or where the assessment ran: the key holder can sign any result (use --recheck)

## Notes

- ℹ revocations checked against the signed Open Trust list (1 entry, valid until 2026-11-30T16:28:12Z)
- ℹ re-check without --evidence: packages not compared with the vendor's SBOM
