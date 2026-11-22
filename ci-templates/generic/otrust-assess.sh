#!/bin/sh
# Open Trust assessment for any CI: Jenkins, Azure DevOps, TeamCity, Bamboo, Buildkite, CircleCI, …
# Download it pinned to a commit and run it after the image is built:
#
#   curl -fsSLo otrust-assess.sh https://raw.githubusercontent.com/dario-mr/open-trust/<sha>/ci-templates/generic/otrust-assess.sh
#   OTRUST_IMAGE=image.oci.tar OTRUST_KEY=/path/to/vendor.key sh otrust-assess.sh
#
# Inputs (environment):
#   OTRUST_VERSION   otrust release to use, e.g. v0.1.16 (required)
#   OTRUST_SHA256    sha256 of otrust-<os>-<arch> for that release (required), or one pin per platform for
#                    mixed agent pools: OTRUST_SHA256_LINUX_AMD64, OTRUST_SHA256_LINUX_ARM64, … Check each
#                    binary once with `gh attestation verify otrust-linux-amd64 -R dario-mr/open-trust` and
#                    pin its digest: the CI then needs no gh, and a swapped download fails here.
#   OTRUST_IMAGE     OCI layout (directory or tar), or a registry image pinned by digest (required)
#   OTRUST_SUBJECT   subject name recorded in the certificate, e.g. registry.example.com/acme/svc
#   OTRUST_KEY       ECDSA P-256 private key file from the CI's secret store, or a KMS key URI
#                    (awskms://, gcpkms://, azurekms://, hashivault://; otrust v0.1.16+): trust level L1.
#                    Key-signed certificates publish nothing, so use this for private repositories.
#                    Unset with SIGSTORE_ID_TOKEN set (Buildkite, CircleCI, …): keyless, L1+ci-identity.
#   OTRUST_SOURCE    source tree at the built revision (default .)
#   OTRUST_OUT       output directory (default ./otrust-out)
#   OTRUST_FAIL_ON_FAILED  "true" (default) fails the job when the assessment FAILED
#   OTRUST_SCANNERS  "docker" (default), or "local" for agents without docker (e.g. Kubernetes pods):
#                    Syft and Trivy come from their pinned release archives, and Semgrep must be on PATH
#                    at the pinned version (`pipx install semgrep==1.183.0`; otrust v0.1.16+)
#   OTRUST_ATTACH    "true" attaches the certificate to OTRUST_IMAGE in its registry (needs a registry
#                    reference and push access; otrust v0.1.16+), so buyers verify by reference alone
#
# Needs curl, and docker unless OTRUST_SCANNERS=local; by default the scanners run in pinned containers. The image and OTRUST_OUT must be on
# paths the docker daemon sees at the same path: with a mounted docker socket (docker-outside-of-docker,
# common on Jenkins), keep the workspace on a volume mounted at the same path on the host.
set -eu

: "${OTRUST_VERSION:?set OTRUST_VERSION, e.g. v0.1.16}"
: "${OTRUST_IMAGE:?set OTRUST_IMAGE to an OCI layout or name@sha256:...}"
OTRUST_SOURCE=${OTRUST_SOURCE:-.}
OTRUST_OUT=${OTRUST_OUT:-$PWD/otrust-out}
OTRUST_FAIL_ON_FAILED=${OTRUST_FAIL_ON_FAILED:-true}

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case $(uname -m) in x86_64 | amd64) arch=amd64 ;; aarch64 | arm64) arch=arm64 ;; *) echo "unsupported CPU $(uname -m)" >&2; exit 2 ;; esac
pin=OTRUST_SHA256_$(echo "${os}_$arch" | tr '[:lower:]' '[:upper:]')
want=${OTRUST_SHA256:-$(eval "printf %s \"\${$pin:-}\"")}
[ -n "$want" ] || { echo "set OTRUST_SHA256 (or $pin) to the sha256 of otrust-$os-$arch $OTRUST_VERSION" >&2; exit 2; }
bin=${OTRUST_BIN:-$PWD/.otrust-bin/otrust}
mkdir -p "$(dirname "$bin")"
curl -fsSL --retry 3 -o "$bin" "https://github.com/dario-mr/open-trust/releases/download/$OTRUST_VERSION/otrust-$os-$arch"
if command -v sha256sum >/dev/null; then got=$(sha256sum "$bin" | cut -d' ' -f1); else got=$(shasum -a 256 "$bin" | cut -d' ' -f1); fi
[ "$got" = "$want" ] || { echo "otrust-$os-$arch $OTRUST_VERSION has sha256 $got, expected $want" >&2; exit 2; }
chmod +x "$bin"

if [ -n "${OTRUST_KEY:-}" ]; then
	set -- --key "$OTRUST_KEY"
elif [ -n "${SIGSTORE_ID_TOKEN:-}" ]; then
	set -- --keyless
else
	echo "set OTRUST_KEY (a signing key from your CI's secret store) or SIGSTORE_ID_TOKEN" >&2
	exit 2
fi

set +e
[ "${OTRUST_ATTACH:-}" = true ] && set -- "$@" --attach
set -- "$@" --scanners "${OTRUST_SCANNERS:-docker}"
"$bin" assess "$@" --image "$OTRUST_IMAGE" ${OTRUST_SUBJECT:+--name "$OTRUST_SUBJECT"} --source "$OTRUST_SOURCE" --out "$OTRUST_OUT"
code=$?
set -e
if [ "$code" = 1 ] && [ "$OTRUST_FAIL_ON_FAILED" != "true" ]; then
	echo "Assessment FAILED (recorded in the certificate)"
	code=0
fi
exit $code
