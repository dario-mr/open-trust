#!/usr/bin/env bash
# Signs an assessment with a key held in HashiCorp Vault (transit engine, dev mode in Docker) and
# verifies it with the exported public key. The private key never leaves Vault, and a key-signed
# certificate puts nothing in a public transparency log: the private-repository path.
# Needs docker and go; assesses the image and source given as arguments (default: otrust itself).
#   demo/kms/vault.sh [image.oci.tar] [source-dir] | tee demo/kms/RESULTS.txt
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
work=${WORK:-$HOME/.cache/otrust-kms}
rm -rf "$work" && mkdir -p "$work"
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

go build -C "$repo" -o "$work/otrust" ./cmd/otrust
otrust=$work/otrust
image=${1:-}
src=${2:-$repo}
if [ -z "$image" ]; then
	# otrust itself as a small image, built from this checkout
	arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
	mkdir -p "$work/ctx" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -C "$repo" -trimpath -buildvcs=false -o "$work/ctx/otrust" ./cmd/otrust
	cp "$repo/Dockerfile" "$work/ctx/"
	docker buildx inspect otrust-oci >/dev/null 2>&1 || docker buildx create --name otrust-oci --driver docker-container >/dev/null
	docker buildx build -q --builder otrust-oci --provenance=mode=min --sbom=false --output "type=oci,dest=$work/image.oci.tar" "$work/ctx" >/dev/null
	image=$work/image.oci.tar
	src=$work/src && git clone -q "$repo" "$src"
fi

say "Vendor: a Vault transit key (ecdsa-p256) that never leaves Vault"
docker rm -f otrust-vault >/dev/null 2>&1 || true
# hashicorp/vault 1.21.1
docker run -d --name otrust-vault --cap-add IPC_LOCK -p 127.0.0.1:18200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=dev-only-token \
	hashicorp/vault:1.21.1 >/dev/null
trap 'docker rm -f otrust-vault >/dev/null 2>&1' EXIT
export VAULT_ADDR=http://127.0.0.1:18200 VAULT_TOKEN=dev-only-token
for i in $(seq 30); do curl -fs "$VAULT_ADDR/v1/sys/health" >/dev/null && break; sleep 1; done
curl -fs -H "X-Vault-Token: $VAULT_TOKEN" -X POST -d '{"type":"transit"}' "$VAULT_ADDR/v1/sys/mounts/transit" >/dev/null
curl -fs -H "X-Vault-Token: $VAULT_TOKEN" -X POST -d '{"type":"ecdsa-p256"}' "$VAULT_ADDR/v1/transit/keys/otrust" >/dev/null
echo "key hashivault://otrust created"

say "Vendor: export the public key for buyers"
"$otrust" pubkey --key hashivault://otrust > "$work/vendor.pub"
cat "$work/vendor.pub"

say "Vendor: assess, signing through Vault"
"$otrust" assess --key hashivault://otrust --image "$image" --name example.com/kms-signed --source "$src" --out "$work/out" | sed 's/^/  /'
jq -r '"tlog entries in the bundle: \(.verificationMaterial.tlogEntries // [] | length)"' "$work/out/certificate.sigstore.json"

say "Buyer: verify with the vendor's public key, offline"
printf 'signers:\n  - name: Acme (key in Vault)\n    publicKey: vendor.pub\n' > "$work/trust.yaml"
"$otrust" verify "$work/out/certificate.sigstore.json" --image "$image" --trust-policy "$work/trust.yaml" --evidence "$work/out" | sed 's/^/  /'
