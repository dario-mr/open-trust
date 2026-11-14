# Supply-Chain Baseline v1

| | |
|---|---|
| Profile ID | `supply-chain-baseline` |
| Version | `1.0.0` (draft) |
| VSA level | `OPENTRUST_SCB_V1` |
| Policy | [`policy.rego`](policy.rego), package `otrust.scb.v1`, result at `data.otrust.scb.v1.decision`. The certificate records its SHA-256. |
| Conformance | [`fixtures/`](fixtures/), with expected results in [fixtures/README.md](fixtures/README.md). Run with `./test.sh`. |

## 1. What a PASSED certificate claims

For the exact artifact digest in the certificate subject:

1. An SBOM was generated **from the artifact itself**, and the SBOM is not empty.
2. That SBOM was scanned for known vulnerabilities. None are CRITICAL, and none are HIGH with a fix available, except those listed as exceptions.
3. The source revision was scanned for exposed secrets, and none were found, except those listed as exceptions.
4. The source was scanned with static analysis, and no ERROR-severity findings remain, except those listed as exceptions.
5. Build provenance exists for the artifact, and its subject matches the artifact.
6. The artifact digest that was assessed is the digest the certificate is about.
7. All of the above used the tool versions and this policy version, as recorded in the certificate.

The certificate always lists warnings, exceptions and unmet requirements. A PASSED result never hides them.

## 2. What it does **not** claim

- That the software is secure or free of vulnerabilities. The scanners find **known** issues and **pattern-matched** code flaws only.
- That the vendor is honest. What is proven depends on the trust level (§7).
- That the source scanned is the complete source of the artifact. The profile does not prove this.
- Anything about runtime behaviour, configuration, infrastructure or the vendor's organisation.
- Coverage of every bug class. For example, the default SAST rules miss some command-injection patterns (see §9).

## 3. Required tools

Container images are pinned by multi-arch index digest. Use the native platform for the runner. The machine-readable source of these pins is [`tools.json`](tools.json). It is embedded in `otrust` and read by `fixtures/generate.sh` and `test.sh`, so edit it there, not only here.

| Check | Tool | Version | Image |
|---|---|---|---|
| sbom | Syft | 1.55.0 | `anchore/syft@sha256:4cc92b64ca74ffca4c94d4c8fcc01f217731375300be14d0b6eeb2e82eaa110a` |
| vulns, secrets | Trivy | 0.76.1 | `aquasec/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c` |
| sast | Semgrep CE | 1.183.0 | `semgrep/semgrep@sha256:2e45517a85e13a9cca14a2a00df6bb48affd66b8ebfae1b0991cd57578362fb0` |
| policy | OPA | 1.22.0 | `openpolicyagent/opa@sha256:895872de1e8dc5b82e04f9410d2d1ada2f72d28fdcdba0e8789d91cfc27ec0d0` |

The reference invocations are in [`fixtures/generate.sh`](fixtures/generate.sh):

| Check | Command | Scans |
|---|---|---|
| sbom | `syft scan <image> -o cyclonedx-json` | the **artifact** |
| vulns | `trivy sbom --format json <sbom>` | **that SBOM** |
| secrets | `trivy fs --scanners secret --format json <src>` | the **source** at the assessed revision |
| sast | `semgrep scan --metrics=off --json --config p/java <src>` | the **source** at the assessed revision |

## 4. Policy input

The agent builds one JSON document. [`fixtures/inputs/*/input.json`](fixtures/inputs/) are real examples. `otrust assess` doesn't write it as one file. Instead, it writes `context.json` (everything except `evidence`) next to the raw evidence files. Both are bound to the certificate by digest, so a verifier given the evidence directory rebuilds this exact document and re-runs the policy.

```jsonc
{
  "now": "RFC 3339",                       // assessment time, used for exception expiry
  "subject":    { "digest": "sha256:…", "assessed_digest": "sha256:…" },
  "provenance": { "present": bool, "signed": bool, "signer_trusted": bool, "subject_match": bool },
  "evidence": {                            // raw tool output, verbatim
    "sbom": {…}, "vulns": {…}, "secrets": {…}, "sast": {…}
  },
  "exceptions": [ { "check": "…", "id": "…", "reason": "…", "expires": "RFC 3339" } ]
}
```

`subject` and `provenance` are computed by the agent, not by a scanner. A verifier given the evidence can re-run the policy and must get the same decision.

## 5. Rules

All six checks are required, and each one yields PASSED, WARN or FAILED.

| Check | FAILED when | WARN when |
|---|---|---|
| `sbom` | evidence missing; not CycloneDX; zero components | — |
| `vulns` | evidence missing; scan not run on the CycloneDX SBOM (`ArtifactType != cyclonedx`); any **CRITICAL**; any **HIGH with a `FixedVersion`** | HIGH with no fix available |
| `secrets` | evidence missing; **any** secret finding | — |
| `sast` | evidence missing; any Semgrep **ERROR** | any Semgrep WARNING; Semgrep reported scan errors (partial coverage) |
| `provenance` | not present; subject doesn't match the artifact | present but unsigned; signer not in the trust policy |
| `subject_binding` | digest missing; assessed digest ≠ certificate subject digest | — |

MEDIUM, LOW and UNKNOWN vulnerabilities, and Semgrep INFO findings, are ignored in v1.

**Overall result:** `FAILED` if any check is FAILED, otherwise `PASSED`. WARN checks still give an overall `PASSED`; they are visible in the check list.

## 6. Exceptions

- Exceptions are declared by the vendor (in the POC, in `.otrust/exceptions.yaml`) and passed through to `input.exceptions`.
- Only `vulns`, `secrets` and `sast` findings can be excepted. Structural failures (missing evidence, wrong format, provenance, subject binding) **never** can.

An exception applies only when **all** of these hold:
- `check` names an exceptable check;
- `id` equals the finding key (table below);
- `reason` is non-blank;
- `expires` is later than `now`.

| Check | Finding key | Example |
|---|---|---|
| `vulns` | vulnerability ID | `CVE-2021-44228` |
| `secrets` | `<target>#<rule id>` | `config/deploy.pem#private-key` |
| `sast` | Semgrep `check_id` (covers every location in v1) | `java.lang.security.audit.formatted-sql-string.formatted-sql-string` |

Applied exceptions are listed in `exceptions_applied`. Invalid, expired or non-exceptable ones are listed in `exceptions_ignored`. Both go into the certificate.

## 7. Trust level

Every certificate carries a trust level, which the verifier recomputes from the signature (poc-plan.md §3):

| Level | Meaning |
|---|---|
| `L1+isolated-assessor` | The assessment ran in our isolated workflow; the vendor's scripts could not alter it. GitHub Actions only, today. |
| `L1+ci-identity` | The vendor's identified CI pipeline ran and signed it. |
| `L1` | The vendor signed with a key. |

This profile's rules are identical at every level. Only how far a buyer can trust that the rules were actually applied changes.

## 8. Validity and versioning

- A certificate is valid for **30 days** from `timeVerified`. Vulnerability data ages, so re-assess at least monthly.
- A new profile version **never** changes an old certificate's result. Verifiers may require a minimum profile version.
- Patch version: wording or bug fixes that don't change any decision on the conformance fixtures. Minor version: new WARN conditions. Major version: any new FAIL condition, check or tool change.

## 9. Known gaps (v1 draft)

Found while generating the fixtures:

- **The Semgrep ruleset is not pinned by content.** `p/java` comes from the Semgrep registry at run time. A ruleset snapshot must be pinned, and its digest recorded, before v1.0.0 is final. This is still open after week 2. Before shipping it, check the licence terms of the registry rules for redistribution.
- **Vendor-controlled scanner configuration.** A `.semgrepignore` containing `*`, committed at any depth, made Semgrep scan zero files, which meant a vacuous SAST PASS. `otrust` now blanks every `.semgrepignore` for the scan by mounting an empty file over it read-only, and lists those files in the certificate (`tools.semgrep.neutralizedIgnoreFiles`). Other in-tree configuration that a scanner might honour has to be reviewed the same way whenever a tool is added or upgraded.
- **`p/java` did not flag** `Runtime.getRuntime().exec("sh -c " + input)` in the fixture. It flagged only the SQL injection. Claim 4 is limited to what the ruleset covers.
- **Trivy's JSON output does not record the vulnerability DB version.** `otrust` captures it separately with `trivy version --format json`. It stores the result as evidence (`trivy-db.json`) and in the certificate (`tools.trivy.db`).
- **BuildKit provenance** (`--provenance=mode=min`) is SLSA v0.2, unsigned, and has an empty `subject`. It is bound to the image only by the OCI index annotation `vnd.docker.reference.digest`. `otrust` accepts it as present, so the provenance check gives WARN (unsigned). A signed bundle passed with `--provenance` (e.g. GitHub `attest-build-provenance`) replaces it. The check then PASSES when the bundle is signed by CI of the assessed repository and names the image digest. It WARNs when the signer is another repository, and FAILs when the bundle names another artifact. A bundle that does not verify stops the assessment.
- Semgrep and Trivy report paths as the scanner saw them (container paths). Exception keys use those paths.
- Subject digests are only stable when builds are reproducible. The fixtures use `SOURCE_DATE_EPOCH=0` and `rewrite-timestamp=true`, and checksum-pinned `ADD`, and rebuilds give identical manifest digests. Vendor builds may not be reproducible. That is fine, because the certificate binds to whatever digest was built, but "rebuild and compare" is not available to buyers.
