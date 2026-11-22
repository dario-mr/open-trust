# Open Trust verification: ASSESSMENT_FAILED

The certificate is genuine, but the image failed the assessment. Review the failed checks before you deploy it.

Certificate `out-room16/certificate.sigstore.json`, image `room.oci.tar`.

> ASSESSMENT_FAILED: assessment result is FAILED

## What this proves

- ✔ Signed by "excalidraw-room vendor key" from your trust policy (key 3pHvnSOr3XB8d6BE+5BhvpD6xijTg5J03fW0coNBXO4=)
- ✔ For exactly this image: sha256:6d9fc4b67189b2cabff1fb31591eeb1faaf5c07abe11ba76ebf8376f13e1e6a5
- ✔ Built from https://github.com/excalidraw/excalidraw-room.git @ 03ff435860b508d7cd9e005cfc90f7977ae2a593 (generic)
- ✔ Assessed 2026-11-22T15:27:52Z with https://open-trust.dev/profiles/supply-chain-baseline/1.2.0, valid until 2026-12-22T15:27:52Z
- ✔ Trust level L1: whoever holds the vendor's key signed it
- ✔ The vendor's evidence matches its digests and re-evaluates to the same results

## Checks, as the vendor's assessment reports them

- ✔ sbom PASSED
- ✘ vulns FAILED (5 CRITICAL, 50 HIGH)
  - CRITICAL CVE-2021-44906 in minimist@1.2.5 (fixed in: 1.2.6, 0.2.4)
  - CRITICAL CVE-2022-37434 in zlib@1.2.12-r0 (fixed in: 1.2.12-r2)
  - CRITICAL CVE-2025-7783 in form-data@2.3.2 (fixed in: 2.5.4, 3.0.4, 4.0.4)
  - CRITICAL CVE-2026-59873 in tar@4.4.19 (fixed in: 7.5.19)
  - CRITICAL CVE-2026-90711 in proxy-addr@2.0.6 (fixed in: 2.0.8)
  - HIGH CVE-2020-28469 in glob-parent@5.1.1 (fixed in: 5.1.2)
  - HIGH CVE-2021-3807 in ansi-regex@3.0.0 (fixed in: 6.0.1, 5.0.1, 4.1.1, 3.0.1)
  - HIGH CVE-2021-3807 in ansi-regex@4.1.0 (fixed in: 6.0.1, 5.0.1, 4.1.1, 3.0.1)
  - HIGH CVE-2021-3807 in ansi-regex@5.0.0 (fixed in: 6.0.1, 5.0.1, 4.1.1, 3.0.1)
  - HIGH CVE-2022-24999 in qs@6.5.2 (fixed in: 6.10.3, 6.9.7, 6.8.3, 6.7.3, 6.6.1, 6.5.3, 6.4.1, 6.3.3, 6.2.4)
  - HIGH CVE-2022-24999 in qs@6.7.0 (fixed in: 6.10.3, 6.9.7, 6.8.3, 6.7.3, 6.6.1, 6.5.3, 6.4.1, 6.3.3, 6.2.4)
  - HIGH CVE-2022-25881 in http-cache-semantics@3.8.1 (fixed in: 4.1.1)
  - HIGH CVE-2022-25883 in semver@5.7.1 (fixed in: 7.5.2, 6.3.1, 5.7.2)
  - HIGH CVE-2022-25883 in semver@7.3.4 (fixed in: 7.5.2, 6.3.1, 5.7.2)
  - HIGH CVE-2022-3517 in minimatch@3.0.4 (fixed in: 3.0.5)
  - HIGH CVE-2022-38900 in decode-uri-component@0.2.0 (fixed in: 0.2.1)
  - HIGH CVE-2024-21538 in cross-spawn@5.1.0 (fixed in: 7.0.5, 6.0.6)
  - HIGH CVE-2024-21538 in cross-spawn@7.0.3 (fixed in: 7.0.5, 6.0.6)
  - HIGH CVE-2024-29415 in ip@1.1.5 (fixed in: none)
  - HIGH CVE-2024-37890 in ws@8.11.0 (fixed in: 5.2.4, 6.2.3, 7.5.10, 8.17.1)
  - HIGH CVE-2024-4068 in braces@3.0.2 (fixed in: 3.0.3)
  - HIGH CVE-2024-45296 in path-to-regexp@0.1.7 (fixed in: 1.9.0, 0.1.10, 8.0.0, 3.3.0, 6.3.0)
  - HIGH CVE-2024-45590 in body-parser@1.19.0 (fixed in: 1.20.3)
  - HIGH CVE-2024-52798 in path-to-regexp@0.1.7 (fixed in: 0.1.12)
  - HIGH CVE-2026-102276 in brace-expansion@1.1.11 (fixed in: 5.0.10, 3.0.7, 2.1.5, 1.1.19)
  - HIGH CVE-2026-102278 in brace-expansion@1.1.11 (fixed in: 5.0.11, 3.0.8, 2.1.6, 1.1.20)
  - HIGH CVE-2026-111181 in body-parser@1.19.0 (fixed in: 2.4.0, 1.20.9)
  - HIGH CVE-2026-118664 in decode-uri-component@0.2.0 (fixed in: 0.5.1)
  - HIGH CVE-2026-12143 in form-data@2.3.2 (fixed in: 2.5.6, 3.0.5, 4.0.6)
  - HIGH CVE-2026-13149 in brace-expansion@1.1.11 (fixed in: 5.0.7, 1.1.16, 2.1.2)
  - HIGH CVE-2026-14257 in brace-expansion@1.1.11 (fixed in: 5.0.8, 3.0.3, 2.1.3, 1.1.17)
  - HIGH CVE-2026-23745 in tar@4.4.19 (fixed in: 7.5.3)
  - HIGH CVE-2026-23950 in tar@4.4.19 (fixed in: 7.5.4)
  - HIGH CVE-2026-24842 in tar@4.4.19 (fixed in: 7.5.7)
  - HIGH CVE-2026-26960 in tar@4.4.19 (fixed in: 7.5.8)
  - HIGH CVE-2026-26996 in minimatch@3.0.4 (fixed in: 10.2.1, 9.0.6, 8.0.5, 7.4.7, 6.2.1, 5.1.7, 4.2.4, 3.1.3)
  - HIGH CVE-2026-27903 in minimatch@3.0.4 (fixed in: 10.2.3, 9.0.7, 8.0.6, 7.4.8, 6.2.2, 5.1.8, 4.2.5, 3.1.3)
  - HIGH CVE-2026-27904 in minimatch@3.0.4 (fixed in: 10.2.3, 9.0.7, 8.0.6, 7.4.8, 6.2.2, 5.1.8, 4.2.5, 3.1.4)
  - HIGH CVE-2026-29786 in tar@4.4.19 (fixed in: 7.5.10)
  - HIGH CVE-2026-31802 in tar@4.4.19 (fixed in: 7.5.11)
  - HIGH CVE-2026-32141 in flatted@3.1.1 (fixed in: 3.4.0)
  - HIGH CVE-2026-33151 in socket.io-parser@4.2.2 (fixed in: 3.3.5, 3.4.4, 4.2.6)
  - HIGH CVE-2026-33228 in flatted@3.1.1 (fixed in: 3.4.2)
  - HIGH CVE-2026-33671 in picomatch@2.2.2 (fixed in: 4.0.4, 3.0.2, 2.3.2)
  - HIGH CVE-2026-4800 in lodash@4.17.21 (fixed in: 4.18.0)
  - HIGH CVE-2026-4867 in path-to-regexp@0.1.7 (fixed in: 0.1.13)
  - HIGH CVE-2026-48779 in ws@8.11.0 (fixed in: 5.2.5, 6.2.4, 7.5.11, 8.21.0)
  - HIGH CVE-2026-59725 in engine.io@6.4.2 (fixed in: 6.6.7)
  - HIGH CVE-2026-59869 in js-yaml@3.14.1 (fixed in: 3.15.0, 4.3.0)
  - HIGH CVE-2026-59874 in tar@4.4.19 (fixed in: 7.5.18)
  - HIGH CVE-2026-69152 in brace-expansion@1.1.11 (fixed in: 1.1.18, 2.1.4, 3.0.6, 5.0.9)
  - HIGH CVE-2026-69185 in socket.io-parser@4.2.2 (fixed in: 4.2.7, 3.4.5, 3.3.6)
  - HIGH CVE-2026-73566 in tar@4.4.19 (fixed in: 7.5.21)
  - HIGH CVE-2026-84375 in js-yaml@3.14.1 (fixed in: 4.3.2, 3.15.2)
  - HIGH GHSA-5p4m-2wfm-xmqj in js-yaml@3.14.1 (fixed in: 4.3.1, 3.15.1)
- ✔ secrets PASSED
- ✘ sast FAILED (1 ERROR, 6 WARNING)
  - ERROR dockerfile.security.missing-user.missing-user at /src/Dockerfile:13
  - WARNING yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag at /src/.github/workflows/lint.yml:10
  - WARNING yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag at /src/.github/workflows/lint.yml:12
  - WARNING yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag at /src/.github/workflows/publish-docker.yml:12
  - WARNING yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag at /src/.github/workflows/publish-docker.yml:13
  - WARNING yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag at /src/.github/workflows/test.yml:10
  - WARNING yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag at /src/.github/workflows/test.yml:12
- ⚠ provenance WARN
  - provenance is not signed
- ✔ subject_binding PASSED
- ℹ SAST rules p/default sha256:9c76333af7c9555a45560d8398cf5fa03432d8f86ca4e458eac3686599fd8f1b (1074 rules, fetched 2026-11-22T15:27:47Z)

## Risks the vendor accepted

- ✘ Unmet sast: ERROR dockerfile.security.missing-user.missing-user at /src/Dockerfile:13
- ✘ Unmet vulns: CRITICAL CVE-2021-44906 in minimist@1.2.5 (fixed in: 1.2.6, 0.2.4)
- ✘ Unmet vulns: CRITICAL CVE-2022-37434 in zlib@1.2.12-r0 (fixed in: 1.2.12-r2)
- ✘ Unmet vulns: CRITICAL CVE-2025-7783 in form-data@2.3.2 (fixed in: 2.5.4, 3.0.4, 4.0.4)
- ✘ Unmet vulns: CRITICAL CVE-2026-59873 in tar@4.4.19 (fixed in: 7.5.19)
- ✘ Unmet vulns: CRITICAL CVE-2026-90711 in proxy-addr@2.0.6 (fixed in: 2.0.8)
- ✘ Unmet vulns: HIGH CVE-2020-28469 in glob-parent@5.1.1 (fixed in: 5.1.2)
- ✘ Unmet vulns: HIGH CVE-2021-3807 in ansi-regex@3.0.0 (fixed in: 6.0.1, 5.0.1, 4.1.1, 3.0.1)
- ✘ Unmet vulns: HIGH CVE-2021-3807 in ansi-regex@4.1.0 (fixed in: 6.0.1, 5.0.1, 4.1.1, 3.0.1)
- ✘ Unmet vulns: HIGH CVE-2021-3807 in ansi-regex@5.0.0 (fixed in: 6.0.1, 5.0.1, 4.1.1, 3.0.1)
- ✘ Unmet vulns: HIGH CVE-2022-24999 in qs@6.5.2 (fixed in: 6.10.3, 6.9.7, 6.8.3, 6.7.3, 6.6.1, 6.5.3, 6.4.1, 6.3.3, 6.2.4)
- ✘ Unmet vulns: HIGH CVE-2022-24999 in qs@6.7.0 (fixed in: 6.10.3, 6.9.7, 6.8.3, 6.7.3, 6.6.1, 6.5.3, 6.4.1, 6.3.3, 6.2.4)
- ✘ Unmet vulns: HIGH CVE-2022-25881 in http-cache-semantics@3.8.1 (fixed in: 4.1.1)
- ✘ Unmet vulns: HIGH CVE-2022-25883 in semver@5.7.1 (fixed in: 7.5.2, 6.3.1, 5.7.2)
- ✘ Unmet vulns: HIGH CVE-2022-25883 in semver@7.3.4 (fixed in: 7.5.2, 6.3.1, 5.7.2)
- ✘ Unmet vulns: HIGH CVE-2022-3517 in minimatch@3.0.4 (fixed in: 3.0.5)
- ✘ Unmet vulns: HIGH CVE-2022-38900 in decode-uri-component@0.2.0 (fixed in: 0.2.1)
- ✘ Unmet vulns: HIGH CVE-2024-21538 in cross-spawn@5.1.0 (fixed in: 7.0.5, 6.0.6)
- ✘ Unmet vulns: HIGH CVE-2024-21538 in cross-spawn@7.0.3 (fixed in: 7.0.5, 6.0.6)
- ✘ Unmet vulns: HIGH CVE-2024-37890 in ws@8.11.0 (fixed in: 5.2.4, 6.2.3, 7.5.10, 8.17.1)
- ✘ Unmet vulns: HIGH CVE-2024-4068 in braces@3.0.2 (fixed in: 3.0.3)
- ✘ Unmet vulns: HIGH CVE-2024-45296 in path-to-regexp@0.1.7 (fixed in: 1.9.0, 0.1.10, 8.0.0, 3.3.0, 6.3.0)
- ✘ Unmet vulns: HIGH CVE-2024-45590 in body-parser@1.19.0 (fixed in: 1.20.3)
- ✘ Unmet vulns: HIGH CVE-2024-52798 in path-to-regexp@0.1.7 (fixed in: 0.1.12)
- ✘ Unmet vulns: HIGH CVE-2026-102276 in brace-expansion@1.1.11 (fixed in: 5.0.10, 3.0.7, 2.1.5, 1.1.19)
- ✘ Unmet vulns: HIGH CVE-2026-102278 in brace-expansion@1.1.11 (fixed in: 5.0.11, 3.0.8, 2.1.6, 1.1.20)
- ✘ Unmet vulns: HIGH CVE-2026-111181 in body-parser@1.19.0 (fixed in: 2.4.0, 1.20.9)
- ✘ Unmet vulns: HIGH CVE-2026-118664 in decode-uri-component@0.2.0 (fixed in: 0.5.1)
- ✘ Unmet vulns: HIGH CVE-2026-12143 in form-data@2.3.2 (fixed in: 2.5.6, 3.0.5, 4.0.6)
- ✘ Unmet vulns: HIGH CVE-2026-13149 in brace-expansion@1.1.11 (fixed in: 5.0.7, 1.1.16, 2.1.2)
- ✘ Unmet vulns: HIGH CVE-2026-14257 in brace-expansion@1.1.11 (fixed in: 5.0.8, 3.0.3, 2.1.3, 1.1.17)
- ✘ Unmet vulns: HIGH CVE-2026-23745 in tar@4.4.19 (fixed in: 7.5.3)
- ✘ Unmet vulns: HIGH CVE-2026-23950 in tar@4.4.19 (fixed in: 7.5.4)
- ✘ Unmet vulns: HIGH CVE-2026-24842 in tar@4.4.19 (fixed in: 7.5.7)
- ✘ Unmet vulns: HIGH CVE-2026-26960 in tar@4.4.19 (fixed in: 7.5.8)
- ✘ Unmet vulns: HIGH CVE-2026-26996 in minimatch@3.0.4 (fixed in: 10.2.1, 9.0.6, 8.0.5, 7.4.7, 6.2.1, 5.1.7, 4.2.4, 3.1.3)
- ✘ Unmet vulns: HIGH CVE-2026-27903 in minimatch@3.0.4 (fixed in: 10.2.3, 9.0.7, 8.0.6, 7.4.8, 6.2.2, 5.1.8, 4.2.5, 3.1.3)
- ✘ Unmet vulns: HIGH CVE-2026-27904 in minimatch@3.0.4 (fixed in: 10.2.3, 9.0.7, 8.0.6, 7.4.8, 6.2.2, 5.1.8, 4.2.5, 3.1.4)
- ✘ Unmet vulns: HIGH CVE-2026-29786 in tar@4.4.19 (fixed in: 7.5.10)
- ✘ Unmet vulns: HIGH CVE-2026-31802 in tar@4.4.19 (fixed in: 7.5.11)
- ✘ Unmet vulns: HIGH CVE-2026-32141 in flatted@3.1.1 (fixed in: 3.4.0)
- ✘ Unmet vulns: HIGH CVE-2026-33151 in socket.io-parser@4.2.2 (fixed in: 3.3.5, 3.4.4, 4.2.6)
- ✘ Unmet vulns: HIGH CVE-2026-33228 in flatted@3.1.1 (fixed in: 3.4.2)
- ✘ Unmet vulns: HIGH CVE-2026-33671 in picomatch@2.2.2 (fixed in: 4.0.4, 3.0.2, 2.3.2)
- ✘ Unmet vulns: HIGH CVE-2026-4800 in lodash@4.17.21 (fixed in: 4.18.0)
- ✘ Unmet vulns: HIGH CVE-2026-4867 in path-to-regexp@0.1.7 (fixed in: 0.1.13)
- ✘ Unmet vulns: HIGH CVE-2026-48779 in ws@8.11.0 (fixed in: 5.2.5, 6.2.4, 7.5.11, 8.21.0)
- ✘ Unmet vulns: HIGH CVE-2026-59725 in engine.io@6.4.2 (fixed in: 6.6.7)
- ✘ Unmet vulns: HIGH CVE-2026-59869 in js-yaml@3.14.1 (fixed in: 3.15.0, 4.3.0)
- ✘ Unmet vulns: HIGH CVE-2026-59874 in tar@4.4.19 (fixed in: 7.5.18)
- ✘ Unmet vulns: HIGH CVE-2026-69152 in brace-expansion@1.1.11 (fixed in: 1.1.18, 2.1.4, 3.0.6, 5.0.9)
- ✘ Unmet vulns: HIGH CVE-2026-69185 in socket.io-parser@4.2.2 (fixed in: 4.2.7, 3.4.5, 3.3.6)
- ✘ Unmet vulns: HIGH CVE-2026-73566 in tar@4.4.19 (fixed in: 7.5.21)
- ✘ Unmet vulns: HIGH CVE-2026-84375 in js-yaml@3.14.1 (fixed in: 4.3.2, 3.15.2)
- ✘ Unmet vulns: HIGH GHSA-5p4m-2wfm-xmqj in js-yaml@3.14.1 (fixed in: 4.3.1, 3.15.1)

## What this does not prove

- Scanners detect known vulnerabilities and pattern-matched code flaws only
- Does not prove the scanned source is the complete source of the artifact
- Vendor-attested (Level 1): the vendor controls the environment the assessment ran in
- Signed with a vendor-held key: proves who signed, not which pipeline ran the assessment
- Anything about how or where the assessment ran: the key holder can sign any result (use --recheck)
- That the image's packages and vulnerabilities are as the vendor reports: run with --recheck to scan it yourself

## Notes

- ℹ no revocation list given: revocation not checked (use --online)
