# Private repositories: certificates without publishing your repository

Your source and your scan evidence never leave your CI, whatever you choose here. What can leak is **metadata about who signed**.

## The problem with keyless signing

Keyless signing (the GitHub reusable assessor, the GitLab template, `--keyless` anywhere) gets a short-lived certificate from Sigstore's public Fulcio, and records it in Sigstore's **public** transparency log, Rekor. That entry contains your repository name, the commit, the workflow path and the run URL. It can't be removed, and anyone can search it. For a private repository, that is usually unacceptable.

## Use a signing key instead, ideally held in a KMS

A key-signed certificate has **no transparency-log entry at all**: it reaches only the buyers you hand it to. You can check this: `jq '.verificationMaterial.tlogEntries | length' certificate.sigstore.json` gives `null` or `0`.

Hold the key in a KMS, so the private key never exists outside it and every signature is in your cloud's audit log. `--key` takes a KMS URI wherever it takes a key file, with the same URIs and credentials as cosign:

| KMS | Create an ECDSA P-256 signing key | `--key` |
|---|---|---|
| AWS KMS | `aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY`, then `aws kms create-alias --alias-name alias/otrust --target-key-id <id>` | `awskms:///alias/otrust` |
| Google Cloud KMS | `gcloud kms keys create otrust --keyring <ring> --location <loc> --purpose asymmetric-signing --default-algorithm ec-sign-p256-sha256` | `gcpkms://projects/<p>/locations/<loc>/keyRings/<ring>/cryptoKeys/otrust/versions/1` |
| Azure Key Vault | `az keyvault key create --vault-name <vault> --name otrust --kty EC --curve P-256` | `azurekms://<vault>.vault.azure.net/otrust` |
| HashiCorp Vault | `vault secrets enable transit`, then `vault write -f transit/keys/otrust type=ecdsa-p256` | `hashivault://otrust` (with `VAULT_ADDR`, `VAULT_TOKEN`) |

Then:

```bash
otrust pubkey --key awskms:///alias/otrust > vendor.pub        # give this to buyers, once
otrust assess --key awskms:///alias/otrust --image image.oci.tar --source .
```

With the [generic script](../ci-templates/generic/otrust-assess.sh), set `OTRUST_KEY=awskms:///alias/otrust`. Give the CI job permission to *sign* with that one key, through your CI's OIDC federation with the cloud (for example `aws-actions/configure-aws-credentials`, `google-github-actions/auth`, or Azure workload identity), so no long-lived cloud secret sits in the CI either. The credentials come from each cloud's standard environment.

Tested: HashiCorp Vault, end to end ([demo/kms/vault.sh](../demo/kms/vault.sh), [results](../demo/kms/RESULTS.txt)). AWS, Google Cloud and Azure use sigstore's providers unchanged, but have not been run against a real account here.

A key file in your CI's secret store (`otrust keygen`) also works, with no KMS. It is weaker: any step in a pipeline that can read the secret can copy the key.

## What your buyers get, and what they give up

The certificate is `L1`: it proves the holder of your key signed it, not which pipeline ran or that the assessment wasn't changed. Tell buyers to:

- put `vendor.pub` in their trust policy (`publicKey: vendor.pub`);
- run `otrust verify --recheck`, which checks the image's packages and known vulnerabilities themselves, so for those checks they need no trust in your pipeline;
- ask you for the evidence directory if they want to re-run the policy on your scan output (`--evidence`). It contains your SBOM and scan results, but no source code.

The isolated assessor (`L1+isolated-assessor`) needs keyless signing, so it is not available for private repositories today. A private Fulcio and Rekor would make it possible without publishing anything; that is not built.

## Rotating or revoking the key

- **Rotate:** create a new key, publish its `vendor.pub`, and have buyers list both keys in their trust policy until old certificates expire (30 days).
- **Revoke:** buyers can reject a key with their own revocation list: `{"revoked": [{"signer": "<key hint>", "reason": "…"}]}` with `--revocations`. `otrust pubkey` prints the hint.
