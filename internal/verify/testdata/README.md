# Test data

| File | What it is | Where it came from |
|---|---|---|
| `autogov-vsa.sigstore.json` | A real Sigstore bundle, keyless-signed in GitHub Actions by the reusable workflow `liatrio/autogov-workflows/.github/workflows/rw-verify.yaml` for source repo `liatrio/autogov` | The `vsa-PASSED.json` asset of the [liatrio/autogov v1.4.6](https://github.com/liatrio/autogov/releases/tag/v1.4.6) release (Apache-2.0) |
| `revocations.sigstore.json` | The real Open Trust revocation list (empty), signed keyless by `revocations.yml` on `main`, valid until 2026-11-30T16:23:33Z | The `revocations` release asset, 2026-11-16 (run 43906947084) |
| `public-good-trusted-root.json` | The Sigstore public-good trusted root (Fulcio CAs, Rekor and CT log keys) | The `rekor.sigstore.dev` line of `gh attestation trusted-root` output, 2026-11-14 |

They exercise the keyless path of `otrust verify`: certificate chain, SCT and transparency-log checks, identity matching against a trust policy, and trust-level derivation. Our own keyless signing only exists once CI support lands. The bundle's payload is autogov's VSA, not an Open Trust certificate, so verification ends at `MALFORMED` once the signature and identity checks have passed.

The trusted root has validity windows. If the public-good keys rotate, these tests keep passing, because the bundle's timestamps fall inside the old keys' windows.
