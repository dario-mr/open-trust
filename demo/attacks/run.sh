#!/usr/bin/env bash
# Live attacks on real CI (poc-plan.md §6), from github.com/dario-mr/open-trust-attacks: runs its
# workflows (attaching a self-hosted runner in docker for the second one), then verifies every
# certificate as a buyer with strict and with looser trust policies and checks the expected result.
# The verifier is built from this checkout. Needs gh (with admin on the attacks repo), docker, go, jq.
#   demo/attacks/run.sh | tee demo/attacks/RESULTS.txt      SKIP_RUNS=1 verifies the latest runs only
set -uo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
R=dario-mr/open-trust-attacks
work=${WORK:-$HOME/.cache/otrust-attacks}
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
run_workflow() { # <file> → prints the run id once it has finished
	gh workflow run "$1" -R $R >/dev/null || return 1
	sleep 15
	local id; id=$(gh run list -R $R -w "${1%.yml}" -L 1 --json databaseId -q '.[0].databaseId')
	gh run watch "$id" -R $R >/dev/null 2>&1
	echo "$id"
}

mkdir -p "$work" && cd "$work" || exit 2
if [ -z "${SKIP_RUNS:-}" ]; then
	say "Vendor: attacks on GitHub-hosted runners"
	A=$(run_workflow attacks.yml) || exit 2

	say "Vendor: attach a self-hosted runner labelled ubuntu-24.04 (the isolated assessor's runs-on)"
	rm -rf "$work/work" && mkdir -p "$work/work"
	tok=$(gh api -X POST repos/$R/actions/runners/registration-token -q .token) || exit 2
	docker rm -f otrust-runner >/dev/null 2>&1
	# actions-runner 2.338.2; docker-outside-of-docker, so the work dir has the same path inside and out
	docker run -d --name otrust-runner -u root -e RUNNER_ALLOW_RUNASROOT=1 \
		-v /var/run/docker.sock:/var/run/docker.sock -v "$work/work:$work/work" \
		ghcr.io/actions/actions-runner@sha256:6d0b2d80d80f143f77dcb676e50920100bbb547e39e883454d57f45ab8c31300 \
		bash -c "./config.sh --unattended --url https://github.com/$R --token $tok --name otrust-attack-runner --labels otrust-attack,ubuntu-24.04 --work $work/work --replace && ./run.sh" >/dev/null
	detach() {
		id=$(gh api repos/$R/actions/runners -q '.runners[]|select(.name=="otrust-attack-runner")|.id' 2>/dev/null)
		[ -n "$id" ] && gh api -X DELETE "repos/$R/actions/runners/$id"
		docker rm -f otrust-runner buildx_buildkit_otrust-attack0 >/dev/null 2>&1
	}
	trap detach EXIT
	for i in $(seq 40); do gh api repos/$R/actions/runners -q '.runners[].status' | grep -q online && break; sleep 3; done
	B=$(run_workflow self-hosted.yml) || exit 2
	detach; trap - EXIT
else
	A=$(gh run list -R $R -w attacks -s success -L 1 --json databaseId -q '.[0].databaseId')
	B=$(gh run list -R $R -w self-hosted -s success -L 1 --json databaseId -q '.[0].databaseId')
fi
echo "runs: attacks $A, self-hosted $B"
say "Where each job ran"
for id in $A $B; do gh api "repos/$R/actions/runs/$id/jobs" -q '.jobs[]|"  \(.name): \(.conclusion) on \(.runner_name)"'; done
hijack_runner=$(gh api "repos/$R/actions/runs/$B/jobs" -q '.jobs[]|select(.name|startswith("hijack"))|.runner_name')

rm -rf v && mkdir v && cd v || exit 2
gh run download "$A" -R $R -D a && gh run download "$B" -R $R -D b || exit 2
go build -C "$repo" -o "$PWD/otrust" ./cmd/otrust || exit 2

base='    issuer: https://token.actions.githubusercontent.com
    sourceRepo: https://github.com/dario-mr/open-trust-attacks
    sourceRef: refs/heads/main'
pin=09477585a21fdceacc434126c751fa018cad8c09 # the assessor at v0.1.16
printf 'minTrustLevel: L1+isolated-assessor\nsigners:\n  - name: the assessor at v0.1.16, pinned by commit\n%s\n    buildSigner: ^https://github\\.com/dario-mr/open-trust/\\.github/workflows/assess\\.yml@%s$\n    requireHostedRunner: true\n' "$base" $pin > strict.yaml
printf 'minTrustLevel: L1+isolated-assessor\nsigners:\n  - name: the assessor at any ref\n%s\n    buildSigner: ^https://github\\.com/dario-mr/open-trust/\\.github/workflows/assess\\.yml@\n    requireHostedRunner: true\n' "$base" > anyref.yaml
(printf 'minAgentVersion: 0.1.16\n'; cat anyref.yaml) > anyref-min.yaml
printf 'minTrustLevel: L1+ci-identity\nsigners:\n  - name: the vendor CI, hosted runners\n%s\n    requireHostedRunner: true\n' "$base" > ci-hosted.yaml
printf 'minTrustLevel: L1+ci-identity\nsigners:\n  - name: the vendor CI, any runner\n%s\n' "$base" > ci-any.yaml

pass=0 fail=0
check() { # <cert dir> <image> <policy> <expected> <what it shows>
	local out got level
	out=$(./otrust verify "$1/certificate.sigstore.json" --image "$2" --trust-policy "$3" --online 2>&1)
	got=$(echo "$out" | tail -1 | grep -Eo '^[A-Z_]+')
	level=$(echo "$out" | grep -o 'Trust level [^:]*' | head -1 | cut -d' ' -f3)
	if [ "$got" = "$4" ]; then mark="✔"; pass=$((pass + 1)); else mark="✘ expected $4"; fail=$((fail + 1)); fi
	printf '  %s %-22s %-14s %-17s %-20s %s\n' "$mark" "$(echo "$1" | sed "s|^[ab]/otrust-||; s|/otrust-out||")" "${3%.yaml}" "$got" "${level:--}" "$5"
	[ "$got" = "$4" ] || echo "$out" | tail -1 | sed 's/^/      /'
}
ia=a/image/image.oci.tar ib=b/otrust-own-self-hosted/image.oci.tar
say "Buyer: every certificate, verified (attack, policy, result, trust level the signature proves)"
check a/otrust-assessor-current $ia strict.yaml VERIFIED "control: the pinned assessor, used honestly"
check a/otrust-assessor-main $ia strict.yaml UNTRUSTED_SIGNER "moving ref @main: not the pinned commit"
check a/otrust-assessor-prev $ia strict.yaml UNTRUSTED_SIGNER "older assessor (0.1.15): not the pinned commit"
check a/otrust-assessor-old $ia strict.yaml UNTRUSTED_SIGNER "outdated assessor (v0.1.4): not the pinned commit"
check a/otrust-own-pipeline $ia strict.yaml UNTRUSTED_SIGNER "vendor's own job signs: not the assessor"
check b/otrust-own-self-hosted/otrust-out $ib strict.yaml UNTRUSTED_SIGNER "vendor's own job on a vendor runner"
check b/otrust-hijack b/image/image.oci.tar strict.yaml VERIFIED "hijack failed: GitHub ran the assessor on $hijack_runner"
check a/otrust-assessor-main $ia anyref.yaml VERIFIED "a buyer accepting any ref takes @main (our own main)"
check a/otrust-assessor-old $ia anyref.yaml POLICY_UNKNOWN "a v0.1.4 assessor uses an earlier profile: refused"
check a/otrust-assessor-prev $ia anyref.yaml VERIFIED "…but an older assessor of the current profile passes: the gap"
check a/otrust-assessor-prev $ia anyref-min.yaml AGENT_OUTDATED "closed by minAgentVersion: 0.1.16"
check a/otrust-assessor-current $ia anyref-min.yaml VERIFIED "…which still accepts the current one"
check b/otrust-own-self-hosted/otrust-out $ib ci-hosted.yaml UNTRUSTED_SIGNER "ci-identity buyer requiring hosted runners: runner_environment self-hosted"
check a/otrust-own-pipeline $ia ci-hosted.yaml VERIFIED "ci-identity means the vendor's pipeline signs: accepted, at that level"
check b/otrust-own-self-hosted/otrust-out $ib ci-any.yaml VERIFIED "without requireHostedRunner, a vendor runner is accepted too"

case "$hijack_runner" in otrust-attack-runner) echo "  ✘ the isolated assessor ran on the vendor's runner"; fail=$((fail + 1)) ;; esac
say "Summary: $pass as expected, $fail not (work dir $work)"
[ "$fail" = 0 ]
