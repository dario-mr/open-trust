#!/usr/bin/env bash
# Replays the v0.1.16 → v0.1.17 release with scripts/release.sh's pin rewriting and compares the
# result with the commits made by hand then. Needs gh (for the two releases' SHA256SUMS).
#   scripts/release_test.sh            DEMO_DIR (default ../open-trust-demo)
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
demo=${DEMO_DIR:-$repo/../open-trust-demo}
RELEASE_LIB=1 . "$repo/scripts/release.sh"
w=$(mktemp -d) && trap 'git -C "$repo" worktree prune; git -C "$demo" worktree prune; rm -rf "$w"' EXIT
gh release download v0.1.16 -R dario-mr/open-trust -p SHA256SUMS -O "$w/old.sums"
gh release download v0.1.17 -R dario-mr/open-trust -p SHA256SUMS -O "$w/new.sums"
fail=0
# replay <repo> <commit made by hand> <rewrite command…>: rewrite its parent, compare with it
replay() {
	local r=$1 c=$2; shift 2
	git -C "$r" worktree add -q --detach "$w/t" "$c^"
	"$@" "$w/t"
	if git -C "$w/t" diff --quiet "$c"; then echo "✔ $(git -C "$r" log -1 --format=%s "$c")"
	else echo "✘ $(git -C "$r" log -1 --format=%s "$c")"; git -C "$w/t" diff "$c" | head -30; fail=1; fi
	git -C "$r" worktree remove --force "$w/t"
}
bump_() { bump "$1" 0.1.16 0.1.17; }
pin_templates_() { pin_templates "$1" 0.1.16 0.1.17 "$w/old.sums" "$w/new.sums"; }
pin_demo_() { pin_demo "$1" 0.1.16 0.1.17 "$w/old.sums" "$w/new.sums" "$(git -C "$repo" rev-parse v0.1.16^{commit})" \
	"$(git -C "$repo" rev-parse v0.1.17^{commit})" "$(ref "$repo" 'Templates use v0.1.17')"; }
ref() { git -C "$1" log --format=%H --grep="^$2\$" -1; }
replay "$repo" "$(ref "$repo" 'Release v0.1.17: otrust policy')" bump_ 
replay "$repo" "$(ref "$repo" 'Templates use v0.1.17')" pin_templates_
replay "$demo" "$(ref "$demo" 'Assess with Open Trust v0.1.17')" pin_demo_
exit $fail
