# Conformance fixtures

`inputs/<case>/input.json` holds **real** tool output, produced by [`generate.sh`](generate.sh) with the pinned tools from [profile.md](../profile.md) §3.

| Case | Contents |
|---|---|
| `clean` | `commons-lang3` 3.20.0, plus a trivial `Main.java` |
| `vulnerable` | `log4j-core` 2.14.1; a SQL-injection `Main.java`; a **fake** private key in `config/deploy.pem` (random bytes, not a real key) |

To regenerate the inputs, run `./generate.sh`. Trivy's vulnerability DB changes daily, so the counts of newer CVEs may change. To run the tests, use `../test.sh`.

## Expected results (for checking by hand against profile.md)

**The independent-implementation exit check:** someone who has not read `policy.rego` applies profile.md §5–6 to each row and should get these results.

| Case | sbom | vulns | secrets | sast | provenance | subject_binding | Overall |
|---|---|---|---|---|---|---|---|
| `clean` | PASSED | PASSED | PASSED | PASSED | PASSED | PASSED | **PASSED** |
| `vulnerable` | PASSED | FAILED: CVE-2021-44228 (CRITICAL), CVE-2021-45046 (CRITICAL), CVE-2021-45105 (HIGH, fix exists). MEDIUMs ignored. | FAILED: private key | FAILED: formatted-sql-string (ERROR) | PASSED | PASSED | **FAILED** |

Variants are derived from the real inputs in `policy_test.rego`:

| Variant | Expected |
|---|---|
| clean without `evidence.sast` | sast FAILED, overall FAILED |
| clean, SBOM `components: []` | sbom FAILED |
| clean, vuln scan `ArtifactType: filesystem` | vulns FAILED |
| clean, one HIGH vuln with no `FixedVersion` | vulns WARN, overall PASSED |
| clean, one Semgrep WARNING | sast WARN, overall PASSED |
| clean, Semgrep `errors` non-empty | sast WARN |
| clean, `provenance.present: false` | provenance FAILED |
| clean, `provenance.signed: false` | provenance WARN, overall PASSED |
| clean, `assessed_digest` ≠ `digest` | subject_binding FAILED, overall FAILED |
| vulnerable + a valid exception for CVE-2021-44228 | that CVE is gone from unmet requirements, listed in `exceptions_applied`; overall still FAILED |
| vulnerable + valid exceptions for all 5 failing findings | overall PASSED, 5 exceptions applied |
| vulnerable + an **expired** exception | not applied, listed in `exceptions_ignored` |
| vulnerable + an exception with a blank reason | not applied, listed in `exceptions_ignored` |
| clean without provenance + an exception for provenance | still FAILED; the exception is ignored (not exceptable) |
