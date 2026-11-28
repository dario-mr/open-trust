#!/usr/bin/env bash
# Runs the open-trust-demo Jenkinsfile in a real, local Jenkins, then verifies its certificate as a buyer.
# The Jenkins container uses the host's docker daemon through its socket (docker-outside-of-docker), so
# JENKINS_HOME is mounted at the same path inside and out: the scanner containers mount workspace paths.
# Needs docker, gh, curl and jq. Writes into $WORK (default ~/.cache/otrust-jenkins, which Docker
# Desktop and colima share with their VM).
#   demo/jenkins/run.sh | tee demo/jenkins/RESULTS.txt        KEEP=1 leaves Jenkins running on :18080
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
VERSION=${VERSION:-v0.1.18}
work=${WORK:-$HOME/.cache/otrust-jenkins}
jh=$work/home
url=http://localhost:18080
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

rm -rf "$work" && mkdir -p "$jh" && cd "$work" || exit 2
os=$(uname -s | tr A-Z a-z)
arch=$(uname -m); [ "$arch" = x86_64 ] && arch=amd64; [ "$arch" = aarch64 ] && arch=arm64

say "Setup: the released otrust $VERSION for the buyer, checked against its build provenance"
gh release download "$VERSION" -R dario-mr/open-trust -p "otrust-$os-$arch" -O otrust || exit 2
gh attestation verify otrust -R dario-mr/open-trust --signer-workflow dario-mr/open-trust/.github/workflows/release.yml | tail -1 || exit 2
chmod +x otrust

say "Vendor: a signing key, stored in Jenkins as a secret file credential"
./otrust keygen --out vendor

say "Vendor: start Jenkins $(sed -n 's/^FROM jenkins\/jenkins:\([^@]*\).*/\1/p' "$here/Dockerfile")"
docker rm -f otrust-jenkins >/dev/null 2>&1
docker build -q -t otrust-jenkins "$here" >/dev/null || exit 2
docker run -d --name otrust-jenkins -u root -p 127.0.0.1:18080:8080 \
	-v /var/run/docker.sock:/var/run/docker.sock -v "$jh:$jh" -e JENKINS_HOME="$jh" \
	-v "$work/vendor.key:/run/otrust/vendor.key:ro" \
	-e JAVA_OPTS="-Djenkins.install.runSetupWizard=false -Dhudson.security.csrf.GlobalCrumbIssuerConfiguration.DISABLE_CSRF_PROTECTION=true" \
	otrust-jenkins >/dev/null || exit 2
[ -n "${KEEP:-}" ] || trap 'docker rm -f otrust-jenkins >/dev/null 2>&1' EXIT
for i in $(seq 90); do curl -fs "$url/job/open-trust-demo/api/json" >/dev/null && break; sleep 2; done
curl -fs "$url/job/open-trust-demo/api/json" >/dev/null || { docker logs otrust-jenkins | tail -30; exit 2; }

say "Vendor: build job open-trust-demo (Jenkinsfile from github.com/dario-mr/open-trust-demo, main)"
curl -fs -X POST "$url/job/open-trust-demo/build" || exit 2
for i in $(seq 360); do
	b=$(curl -fs "$url/job/open-trust-demo/1/api/json" 2>/dev/null) && [ "$(jq -r .building <<<"$b")" = false ] && break
	sleep 5
done
curl -fs "$url/job/open-trust-demo/1/consoleText" | grep -vE '^\s*$' | sed 's/^/  /'
result=$(jq -r .result <<<"$b")
echo "→ Jenkins build #1: $result"
[ "$result" = SUCCESS ] || exit 1

ws=$jh/workspace/open-trust-demo
cert=$ws/otrust-out/certificate.sigstore.json
printf 'signers:\n  - name: Acme Jenkins key\n    publicKey: vendor.pub\n' > trust.yaml
say "Buyer: what the certificate records about the Jenkins run"
jq '.dsseEnvelope.payload|@base64d|fromjson|.predicate["https://open-trust.dev/assessment/v0.1"]|{ci, trustLevel, agentDigest}' "$cert"

pass=0 fail=0
scenario() {
	local title=$1 want=$2; shift 2
	say "$title"
	out=$("$@" 2>&1); echo "$out" | sed 's/^/  /'
	got=$(echo "$out" | tail -1 | grep -Eo '^[A-Z_]+')
	if [ "$got" = "$want" ]; then echo "→ $got, as expected"; pass=$((pass + 1)); else echo "→ got '$got', expected $want"; fail=$((fail + 1)); fi
}
scenario "Buyer: verify the Jenkins certificate with the shared evidence" VERIFIED \
	./otrust verify "$cert" --image "$ws/image.oci.tar" --trust-policy trust.yaml --evidence "$ws/otrust-out"
scenario "Buyer: re-check the image themselves" VERIFIED \
	./otrust verify "$cert" --image "$ws/image.oci.tar" --trust-policy trust.yaml --evidence "$ws/otrust-out" --recheck

say "Summary: Jenkins build $result; $pass as expected, $fail not (work dir $work)"
[ "$fail" = 0 ]
