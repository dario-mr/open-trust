#!/usr/bin/env bash
# The customer-side demo (poc-plan.md §7). It downloads the released otrust and checks its
# attestation, fetches the latest open-trust-demo certificates from GitHub and GitLab, and runs each
# scenario, comparing the verify result with the expected one.
# Needs gh, glab, docker, jq and openssl. Writes into $WORK (default: ~/.cache/otrust-demo, which Docker
# Desktop and colima share with their VM by default; /tmp often is not).
#   demo/scenarios.sh | tee demo/RESULTS.txt
set -uo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
VERSION=${VERSION:-v0.1.16}
DEMO=dario-mr/open-trust-demo
work=${WORK:-$HOME/.cache/otrust-demo}
rm -rf "$work" && mkdir -p "$work" && cd "$work" || exit 2
root=$repo/internal/verify/testdata/public-good-trusted-root.json
os=$(uname -s | tr A-Z a-z)
arch=$(uname -m); [ "$arch" = x86_64 ] && arch=amd64; [ "$arch" = aarch64 ] && arch=arm64
pass=0 fail=0

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
# scenario <title> <expected verify result> <command…>
scenario() {
	local title=$1 want=$2; shift 2
	say "$title"
	echo "\$ ${*/#$work\//}"
	out=$("$@" 2>&1)
	echo "$out" | sed 's/^/  /'
	got=$(echo "$out" | grep -Eo '^(VERIFIED|[A-Z_]+):' | tail -1 | tr -d :)
	[ -z "$got" ] && got=$(echo "$out" | grep -Eo '^VERIFIED$' | tail -1)
	if [ "$got" = "$want" ]; then echo "→ $got, as expected"; pass=$((pass + 1)); else echo "→ got '$got', expected $want"; fail=$((fail + 1)); fi
}

say "Setup: the released otrust $VERSION, checked against its build provenance"
gh release download "$VERSION" -R dario-mr/open-trust -p "otrust-$os-$arch" -p "otrust-linux-$arch" -p SHA256SUMS --clobber || exit 2
gh attestation verify "otrust-$os-$arch" -R dario-mr/open-trust --signer-workflow dario-mr/open-trust/.github/workflows/release.yml | tail -3 || exit 2
[ "$os" = linux ] || gh attestation verify "otrust-linux-$arch" -R dario-mr/open-trust --signer-workflow dario-mr/open-trust/.github/workflows/release.yml >/dev/null || exit 2
chmod +x otrust-*
otrust=$work/otrust-$os-$arch

say "Setup: the vendor's artifacts (GitHub: latest run; GitLab: latest pipeline on main) and trust policies"
run=$(gh run list -R $DEMO -w "build and assess" -s success -L 1 --json databaseId -q '.[0].databaseId')
echo "GitHub run $run"
mkdir -p gh gl
gh run download "$run" -R $DEMO -D gh -n image-clean -n otrust-image-clean -n image-vulnerable -n otrust-image-vulnerable || exit 2
(cd gl && glab job artifact main assess-clean -R $DEMO >/dev/null && glab job artifact main "build: [clean]" -R $DEMO >/dev/null) || exit 2
for f in trust.yaml trust-gitlab.yaml; do gh api "repos/$DEMO/contents/$f" -q .content | base64 -d > "$f"; done
v() { "$otrust" verify "$@" --trusted-root "$root"; }

# a buyer pulls the image they deploy from the vendor's registry, pinned by digest
subj() { jq -r '.dsseEnvelope.payload|@base64d|fromjson|"sha256:"+.subject[0].digest.sha256' "$1"; }
scenario "1a. Clean pass on GitHub: the isolated assessor (image pulled from ghcr.io by digest)" VERIFIED \
	v gh/otrust-image-clean/certificate.sigstore.json --image "ghcr.io/$DEMO@$(subj gh/otrust-image-clean/certificate.sigstore.json)" --trust-policy trust.yaml --evidence gh/otrust-image-clean
scenario "1b. The same app on GitLab: the vendor's own pipeline signs, so only ci-identity (image from the GitLab registry)" VERIFIED \
	v gl/otrust-out/certificate.sigstore.json --image "registry.gitlab.com/$DEMO@$(subj gl/otrust-out/certificate.sigstore.json)" --trust-policy trust-gitlab.yaml --evidence gl/otrust-out
scenario "1d. Re-check: the buyer scans the image themselves and compares packages with the vendor's SBOM" VERIFIED \
	v gh/otrust-image-clean/certificate.sigstore.json --image gh/image-clean/image.oci.tar --trust-policy trust.yaml --evidence gh/otrust-image-clean --recheck
scenario "1e. No certificate file: verify by image reference alone (the certificate is attached to the ghcr.io image)" VERIFIED \
	v --image "ghcr.io/$DEMO@$(subj gh/otrust-image-clean/certificate.sigstore.json)" --trust-policy trust.yaml
scenario "1f. The same on GitLab's registry" VERIFIED \
	v --image "registry.gitlab.com/$DEMO@$(subj gl/otrust-out/certificate.sigstore.json)" --trust-policy trust-gitlab.yaml
sed 's/^minTrustLevel: .*/minTrustLevel: L1+isolated-assessor/' trust-gitlab.yaml > trust-gitlab-strict.yaml
scenario "1c. A buyer who demands the isolated assessor rejects the GitLab certificate" TRUST_LEVEL_TOO_LOW \
	v gl/otrust-out/certificate.sigstore.json --image gl/image-clean.oci.tar --trust-policy trust-gitlab-strict.yaml
scenario "2. A vulnerable dependency (log4j 2.14.1) fails the assessment" ASSESSMENT_FAILED \
	v gh/otrust-image-vulnerable/certificate.sigstore.json --image gh/image-vulnerable/image.oci.tar --trust-policy trust.yaml

scenario "3. A changed image: the clean certificate presented with the vulnerable image" ARTIFACT_MISMATCH \
	v gh/otrust-image-clean/certificate.sigstore.json --image gh/image-vulnerable/image.oci.tar --trust-policy trust.yaml

# flip FAILED to PASSED in the signed payload of the vulnerable certificate
jq '.dsseEnvelope.payload |= (@base64d | sub("\"verificationResult\": *\"FAILED\""; "\"verificationResult\": \"PASSED\"") | @base64)' \
	gh/otrust-image-vulnerable/certificate.sigstore.json > edited.sigstore.json
scenario "4. An edited certificate: FAILED rewritten to PASSED" INVALID_SIGNATURE \
	v edited.sigstore.json --image gh/image-vulnerable/image.oci.tar --trust-policy trust.yaml

echo "{\"revoked\":[{\"subject\":\"$(jq -r '.dsseEnvelope.payload|@base64d|fromjson|.subject[0].digest.sha256' gh/otrust-image-clean/certificate.sigstore.json | sed 's/^/sha256:/')\",\"reason\":\"recalled by our security team\"}]}" > my-revocations.json
scenario "5a. Revoked by the buyer's own list" REVOKED \
	v gh/otrust-image-clean/certificate.sigstore.json --image gh/image-clean/image.oci.tar --trust-policy trust.yaml --revocations my-revocations.json
scenario "5b. The signed Open Trust revocation list (--online) is checked, and the current certificate passes" VERIFIED \
	v gh/otrust-image-clean/certificate.sigstore.json --image gh/image-clean/image.oci.tar --trust-policy trust.yaml --online

say "6. A key-signed run from a CI with no OIDC identity (a 'Jenkins' job), assessing the same image"
rev=$(jq -r '.dsseEnvelope.payload|@base64d|fromjson|.predicate["https://open-trust.dev/assessment/v0.1"].ci.revision' gh/otrust-image-clean/certificate.sigstore.json)
rm -rf src && git clone -q "https://github.com/$DEMO.git" src && git -C src -c advice.detachedHead=false checkout -q "$rev"
"$otrust" keygen --out jenkins >/dev/null
"$otrust" assess --key jenkins.key --image gh/image-clean/image.oci.tar --name example.com/open-trust-demo:clean --source src --out jenkins-out | sed 's/^/  /'
printf 'signers:\n  - name: Acme Jenkins key\n    publicKey: jenkins.pub\n' > trust-key.yaml
scenario "6a. Verified, at the level a key can prove" VERIFIED \
	v jenkins-out/certificate.sigstore.json --image gh/image-clean/image.oci.tar --trust-policy trust-key.yaml --evidence jenkins-out
(printf 'minTrustLevel: L1+ci-identity\n'; cat trust-key.yaml) > trust-key-strict.yaml
scenario "6b. A buyer requiring a CI identity rejects it" TRUST_LEVEL_TOO_LOW \
	v jenkins-out/certificate.sigstore.json --image gh/image-clean/image.oci.tar --trust-policy trust-key-strict.yaml

# A key holder can sign anything: re-sign the clean statement for the vulnerable image (DSSE PAE, ECDSA P-256)
jq -c --arg d "$(subj gh/otrust-image-vulnerable/certificate.sigstore.json | cut -d: -f2)" '.subject[0].digest.sha256=$d' jenkins-out/statement.json > lie.json
t=application/vnd.in-toto+json
{ printf 'DSSEv1 %d %s %d ' ${#t} $t "$(wc -c < lie.json)"; cat lie.json; } | openssl dgst -sha256 -sign jenkins.key -out lie.sig
jq --rawfile p lie.json --arg s "$(base64 < lie.sig | tr -d '\n')" '.dsseEnvelope.payload=($p|@base64) | .dsseEnvelope.signatures[0].sig=$s' \
	jenkins-out/certificate.sigstore.json > lie.sigstore.json
scenario "6c. The key holder signs a clean result for the log4j image: the signature alone cannot tell" VERIFIED \
	v lie.sigstore.json --image gh/image-vulnerable/image.oci.tar --trust-policy trust-key.yaml
scenario "6d. The buyer's re-check catches it: Log4Shell was public years before the scan" RECHECK_MISMATCH \
	v lie.sigstore.json --image gh/image-vulnerable/image.oci.tar --trust-policy trust-key.yaml --recheck

# golang:1.27.4-alpine, only as a small Linux userland: the otrust binary is static
docker pull -q golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf >/dev/null
cp "$root" root.json
scenario "7. Fully offline: no network in the container" VERIFIED \
	docker run --rm --network none -v "$work:/w:ro" -w /w \
	golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf \
	"/w/otrust-linux-$arch" verify gh/otrust-image-clean/certificate.sigstore.json --image gh/image-clean/image.oci.tar \
	--trust-policy trust.yaml --trusted-root root.json --evidence gh/otrust-image-clean

say "Summary: $pass as expected, $fail not (work dir $work)"
[ "$fail" = 0 ]
