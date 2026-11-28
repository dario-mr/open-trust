# Quality Baseline v1

| | |
|---|---|
| Profile ID | `quality-baseline` |
| Version | `1.0.0` (draft) |
| VSA level | `OPENTRUST_QUALITY_V1` |
| Policy | [`policy.rego`](policy.rego), package `otrust.quality.v1`, result at `data.otrust.quality.v1.decision`. The certificate records its SHA-256. |
| Tests | [`policy_test.rego`](policy_test.rego), run with `./test.sh` |

Where [Supply-Chain Baseline](../../supply-chain-baseline/v1/profile.md) asks *is it safe to run?*, this profile asks *can we legally and sustainably run it?* It needs no extra scan: `otrust assess` evaluates both profiles on the same evidence (the SBOM and the vulnerability scan) and signs one certificate for each.

## 1. What a PASSED certificate claims

For the exact artifact digest in the certificate subject:

1. **Licences.** No application dependency is licensed *only* under a strong copyleft licence (GPL, AGPL, SSPL), except those listed as exceptions.
2. **SBOM completeness.** The SBOM has components. Application dependencies without a version or package URL are reported.
3. **OS support.** The base image's operating system release still receives security fixes (not end of life, as the vulnerability scanner's data says).

Warnings, exceptions and unmet requirements are always listed, also on PASSED.

## 2. What it does **not** claim

- That the licences are right, or compatible with each other or with your use. They are what the SBOM tool found in package metadata: this is not a legal review.
- Anything about OS packages' licences. Distributions ship their own packages under their own terms (Debian's are often GPL), so only application dependencies are checked.
- That dependencies are maintained. No source of maintenance data is consulted.

## 3. Rules

| Check | FAILED when | WARN when |
|---|---|---|
| `licenses` | SBOM missing; an application dependency's every licence choice is strong copyleft | application dependencies with no detected licence (one summary line) |
| `sbom_completeness` | SBOM missing or empty | application dependencies without a version, or without a package URL |
| `os_support` | vulnerability scan missing; the OS release is end of life | — |

- **Application dependencies** are SBOM components of type `library` whose package URL is not an OS package (`deb`, `apk`, `rpm`, `alpm`).
- **Licence choices:** every licence entry, and every `OR` alternative in an expression, is a choice: `MIT OR GPL-2.0-only` passes. Strong copyleft means GPL (also given as a gnu.org URL), AGPL or SSPL; not LGPL, and not a GPL with an exception such as the Classpath exception.
- Syft finds no licences in Go binaries' module metadata, so a Go service warns about unknown licences for nearly every dependency.

## 4. Exceptions

Exceptions use the same file as Supply-Chain Baseline (`.otrust/exceptions.yaml`); each profile applies only those for its own checks, and an exception for a check no profile has is refused when the file is loaded.

| Check | Finding key | Example |
|---|---|---|
| `licenses` | the dependency's package URL, without qualifiers | `pkg:npm/foo@2.1.0` |
| `os_support` | `eosl:<family>-<release>` | `eosl:alpine-3.15.4` |
| `sbom_completeness` | `missing-version`, `missing-purl` | `missing-version` |

## 5. Validity and versioning

As Supply-Chain Baseline: valid for 30 days; a minor version adds WARN conditions, a major version FAIL conditions. The verifier knows only the current policy version.
