#!/usr/bin/env bash
# Releases otrust: bumps the version, tags, waits for the release workflow (build, self-assessment,
# certificate), re-pins the CI templates and the demo repository (GitHub and GitLab) to the new
# release, waits for the demo pipelines, and records the buyer demo and the Jenkins run.
#   scripts/release.sh 0.1.18            DEMO_DIR (default ../open-trust-demo), SKIP_RECORD=1
# Needs gh, glab, jq, perl, go, docker; git pushes with the configured credentials.
# Only the pin rewriting is sourced by the tests: RELEASE_LIB=1 . scripts/release.sh
set -euo pipefail

R=dario-mr/open-trust DEMO=dario-mr/open-trust-demo
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

# replace <file> <old> <new>: literal, every occurrence, word-bounded (v0.1.1 never matches v0.1.17)
replace() { OLD=$2 NEW=$3 perl -pi -e 's/(?<![\w.])\Q$ENV{OLD}\E(?![\w.])/$ENV{NEW}/g' "$1"; }

# sums <SHA256SUMS> <platform> → that binary's sha256
sums() { awk -v f="otrust-$2" '$2 == f {print $1}' "$1"; }

# bump <dir> <old> <new>: the version otrust reports, and the docs and demos that name the release
bump() {
	local d=$1 old=$2 new=$3 f
	perl -pi -e "s/const Version = \"\Q$old\E\"/const Version = \"$new\"/" "$d/internal/assess/assess.go"
	for f in demo/scenarios.sh demo/jenkins/run.sh; do replace "$d/$f" "v$old" "v$new"; done
	perl -pi -e "s/assessor v\Q$old\E\$/assessor v$new/; s/<commit of v\Q$old\E>/<commit of v$new>/; s/gh release download v\Q$old\E /gh release download v$new /" "$d/docs/consumer-guide.md"
}

# pin_templates <dir> <old> <new> <old SHA256SUMS> <new SHA256SUMS>
pin_templates() {
	local d=$1 old=$2 new=$3 f p
	for f in ci-templates/jenkins/Jenkinsfile ci-templates/azure-devops/azure-pipelines.yml ci-templates/generic/otrust-assess.sh; do
		replace "$d/$f" "v$old" "v$new"
		for p in linux-amd64 linux-arm64; do replace "$d/$f" "$(sums "$4" $p)" "$(sums "$5" $p)"; done
	done
}

# pin_demo <dir> <old> <new> <old SHA256SUMS> <new SHA256SUMS> <old release commit> <new release commit> <new template commit>
pin_demo() {
	local d=$1 f p oldtpl
	oldtpl=$(perl -ne 'print $1 if m{open-trust/([0-9a-f]{40})/ci-templates/generic}' "$d/Jenkinsfile")
	for f in .github/workflows/build.yml .gitlab-ci.yml Jenkinsfile README.md trust.yaml; do
		replace "$d/$f" "v$2" "v$3"
		replace "$d/$f" "$6" "$7"
		replace "$d/$f" "$oldtpl" "$8"
		for p in linux-amd64 linux-arm64; do replace "$d/$f" "$(sums "$4" $p)" "$(sums "$5" $p)"; done
	done
}

[ -n "${RELEASE_LIB:-}" ] && return 0

new=${1:?usage: scripts/release.sh <version, e.g. 0.1.18>}
new=${new#v}
demo=${DEMO_DIR:-$repo/../open-trust-demo}
old=$(sed -n 's/^const Version = "\(.*\)"/\1/p' "$repo/internal/assess/assess.go")
work=$(mktemp -d) && trap 'rm -rf "$work"' EXIT
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# wait_run <repo> <workflow> <branch or tag>: the latest run there, until completed; rerun failed jobs once
wait_run() {
	local id='' i
	for i in $(seq 40); do
		id=$(gh run list -R "$1" -w "$2" -b "$3" -L 1 --json databaseId -q '.[0].databaseId // empty')
		[ -n "$id" ] && break
		sleep 5
	done
	[ -n "$id" ] || { echo "no $2 run for $3"; return 1; }
	gh run watch "$id" -R "$1" --exit-status >/dev/null 2>&1 && return 0
	echo "run $id failed; re-running its failed jobs once (registries and Sigstore fail transiently)"
	gh run rerun "$id" -R "$1" --failed && sleep 20
	gh run watch "$id" -R "$1" --exit-status >/dev/null 2>&1 || { gh run view "$id" -R "$1" --log-failed | tail -20; return 1; }
}

say "otrust $old → $new"
cd "$repo"
[ -z "$(git status --porcelain)" ] || { echo "working tree not clean"; exit 1; }
[ -z "$(git -C "$demo" status --porcelain)" ] || { echo "$demo not clean"; exit 1; }
gh release download "v$old" -R $R -p SHA256SUMS -O "$work/old.sums"
oldrel=$(git rev-parse "v$old^{commit}")
go test ./... >/dev/null

say "Tag v$new and wait for the release (build, self-assessment, certificate)"
bump "$repo" "$old" "$new"
git commit -qam "Release v$new"
git push -q origin main
git tag -a "v$new" -m "v$new"
git push -q origin "v$new"
newrel=$(git rev-parse "v$new^{commit}")
wait_run $R release "v$new"
gh release download "v$new" -R $R -p SHA256SUMS -O "$work/new.sums"

say "Templates pin v$new"
pin_templates "$repo" "$old" "$new" "$work/old.sums" "$work/new.sums"
git commit -qam "Templates use v$new"
git push -q origin main
tpl=$(git rev-parse HEAD)

say "Demo repository pins v$new; wait for its GitHub and GitLab pipelines"
pin_demo "$demo" "$old" "$new" "$work/old.sums" "$work/new.sums" "$oldrel" "$newrel" "$tpl"
git -C "$demo" commit -qam "Assess with Open Trust v$new"
git -C "$demo" push -q origin main
git -C "$demo" push -q gitlab main
wait_run $DEMO "build and assess" main
for i in $(seq 90); do
	s=$(glab ci list -R $DEMO 2>/dev/null | sed -n 4p)
	case "$s" in *running* | *pending* | *created*) sleep 20 ;; *) break ;; esac
done
case "$s" in *success*) ;; *) echo "GitLab pipeline: $s"; exit 1 ;; esac

[ -n "${SKIP_RECORD:-}" ] && { say "Released v$new (recordings skipped)"; exit 0; }
say "Record the buyer demo and the Jenkins run"
demo/scenarios.sh >demo/RESULTS.txt 2>&1 || { tail -5 demo/RESULTS.txt; exit 1; }
demo/jenkins/run.sh >demo/jenkins/RESULTS.txt 2>&1 || { tail -5 demo/jenkins/RESULTS.txt; exit 1; }
tail -1 demo/RESULTS.txt demo/jenkins/RESULTS.txt
git commit -qam "Record the v$new demo runs"
git push -q origin main
say "Released v$new"
