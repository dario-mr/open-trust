#!/usr/bin/env bash
# Regenerates the fixture evidence from real tool runs. The tool invocations here are the
# reference for the Week 2 adapters: same images, same flags.
# Needs: docker with buildx, jq. Network: Maven Central, Trivy DB, Semgrep registry.
set -euo pipefail
cd "$(dirname "$0")"
FX=$PWD

TOOLS=../tools.json   # single source of tool pins, also embedded in otrust
SYFT=$(jq -r .syft.image $TOOLS)
TRIVY=$(jq -r .trivy.image $TOOLS)
SEMGREP=$(jq -r .semgrep.image $TOOLS)
SEMGREP_CONFIG=$(jq -r .semgrep.config $TOOLS)   # shortcut: registry ruleset is not pinned by content; record/pin a ruleset digest before v1.0.0 is final

run() { docker run --rm --platform "linux/$(uname -m | sed s/x86_64/amd64/)" -v "$FX:/fx" -v otrust-cache:/cache "$@"; }

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
rm -rf evidence  # older layout
for c in clean vulnerable; do
  out=build/$c; mkdir -p "$out" "inputs/$c"
  # Reproducible OCI layout (D12): jars are checksum-pinned in the Dockerfile, timestamps normalised,
  # so the subject digest is the same on every rebuild.
  SOURCE_DATE_EPOCH=0 docker buildx build -q --provenance=mode=min --sbom=false \
    --output "type=oci,dest=build/$c.oci.tar,rewrite-timestamp=true" "src/$c" >/dev/null
  # The subject is the image manifest; with provenance attached, index.json points at a nested index.
  idx=$(tar -xOf "build/$c.oci.tar" index.json | jq -r '.manifests[0].digest')
  digest=$(tar -xOf "build/$c.oci.tar" "blobs/sha256/${idx#sha256:}" |
    jq -r '[.manifests[] | select(.annotations["vnd.docker.reference.type"] != "attestation-manifest")] | if length == 1 then .[0].digest else error("expected one image manifest") end')

  run "$SYFT" scan "oci-archive:/fx/build/$c.oci.tar" -o cyclonedx-json -q > "$out/sbom.cdx.json"
  run -e TRIVY_CACHE_DIR=/cache/trivy "$TRIVY" sbom --quiet --format json "/fx/$out/sbom.cdx.json" > "$out/vulns.json"
  run -e TRIVY_CACHE_DIR=/cache/trivy "$TRIVY" fs --quiet --offline-scan --scanners secret --format json "/fx/src/$c/app" > "$out/secrets.json"
  # semgrep exits 1 when it has findings; that is a result, not an error
  run -e SEMGREP_SEND_METRICS=off "$SEMGREP" semgrep scan --metrics=off --quiet --json --config "$SEMGREP_CONFIG" "/fx/src/$c/app" > "$out/sast.json" || [ $? -eq 1 ]

  # The exact policy input otrust will build: raw tool outputs verbatim under .evidence,
  # plus the values otrust computes itself (subject binding, provenance status).
  jq -n --arg d "$digest" --arg now "$NOW" \
    --slurpfile sbom "$out/sbom.cdx.json" --slurpfile vulns "$out/vulns.json" \
    --slurpfile secrets "$out/secrets.json" --slurpfile sast "$out/sast.json" '{
    now: $now,
    subject: { digest: $d, assessed_digest: $d },
    provenance: { present: true, signed: true, signer_trusted: true, subject_match: true },
    evidence: { sbom: $sbom[0], vulns: $vulns[0], secrets: $secrets[0], sast: $sast[0] },
    exceptions: []
  }' > "inputs/$c/input.json"
done
echo "fixtures regenerated in $FX/inputs"
