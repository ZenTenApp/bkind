#!/usr/bin/env bash
#
# Rename the khatru module and package to a new home.
#
#   scripts/rename-khatru.sh github.com/you/bkind --check   # show what would change
#   scripts/rename-khatru.sh github.com/you/bkind           # do it
#
# Phase 2 of TAKEOVER.md. Idempotent: re-running after a successful rename is a
# no-op, so it can be committed and reused for the docs site or downstream forks.
#
# What it does NOT do, on purpose:
#   - touch /tmp/khatru-* paths in the examples (harmless, cosmetic)
#   - rename the "khatru29" reference in docs/core/routing.md (a third-party package)
#   - decide your version tag (see TAKEOVER.md: start at v1.0.0)

set -euo pipefail

usage() {
	sed -n '2,16p' "$0" | sed 's|^# \{0,1\}||'
	exit 2
}

NEW="${1:-}"
CHECK=false
for arg in "$@"; do
	case "$arg" in
	--check) CHECK=true ;;
	-h | --help) usage ;;
	-*) echo "unknown flag: $arg" >&2; usage ;;
	esac
done
[[ -n "$NEW" && "$NEW" != --* ]] || usage

OLD='github.com/fiatjaf/khatru'
NEW_PKG="$(basename "$NEW")"

if [[ ! "$NEW" =~ ^[a-z0-9.-]+\.[a-z]{2,}/[A-Za-z0-9._/-]+$ ]]; then
	echo "not a plausible module path: $NEW" >&2
	echo "expected something like github.com/you/bkind" >&2
	exit 2
fi
if [[ ! "$NEW_PKG" =~ ^[a-z][a-z0-9]*$ ]]; then
	echo "package name derived from the path is not a valid Go identifier: $NEW_PKG" >&2
	exit 2
fi

cd "$(git rev-parse --show-toplevel)"
if [[ -n "$(git status --porcelain)" && "$CHECK" == false ]]; then
	echo "working tree is dirty; commit or stash first (or use --check)" >&2
	exit 1
fi
if ! grep -q "^module $OLD$" go.mod; then
	echo "go.mod does not declare module $OLD; already renamed?" >&2
	grep '^module ' go.mod >&2
	exit 1
fi

run() {
	if [[ "$CHECK" == true ]]; then
		echo "  would run: $*"
	else
		"$@"
	fi
}

echo "renaming $OLD -> $NEW (package $NEW_PKG)"

# 1. import paths, then qualified identifiers. The second substitution is what
#    makes importers compile: replacing only the path leaves "undefined: khatru".
mapfile -t gofiles < <(grep -rl 'github.com/fiatjaf/khatru\|\bkhatru\.\|^package khatru' --include='*.go' .)
echo "  ${#gofiles[@]} go files"
run sed -i "s|$OLD|$NEW|g" "${gofiles[@]}"
run sed -i "s|\bkhatru\.|$NEW_PKG.|g" "${gofiles[@]}"

# 2. package clauses, including external test packages
run sed -i "s|^package khatru$|package $NEW_PKG|" "${gofiles[@]}"
run sed -i "s|^package khatru_test$|package ${NEW_PKG}_test|" "${gofiles[@]}"

# 3. the module line
run sed -i "s|^module $OLD$|module $NEW|" go.mod

# 4. library identity strings: log prefix, NIP-11 software URL
run sed -i "s|\"\[khatru-relay\] \"|\"[$NEW_PKG] \"|" relay.go

# 5. docs: module and repo URLs only. Prose is deliberately left alone: after the
# takeover "khatru" survives in provenance sentences and nowhere else (NAMING.md),
# and no sed can tell a credit line from a stale mention. The residuals below are
# the review list.
mapfile -t mdfiles < <(grep -ril 'khatru' --include='*.md' . || true)
echo "  ${#mdfiles[@]} markdown files"
if [[ ${#mdfiles[@]} -gt 0 ]]; then
	run sed -i "s|$OLD|$NEW|g; s|fiatjaf.com/nostr/khatru|$NEW|g" "${mdfiles[@]}"
fi

if [[ "$CHECK" == true ]]; then
	echo "dry run: nothing written"
	exit 0
fi

gofmt -w "${gofiles[@]}"

echo "verifying"
go build ./... || {
	echo "build failed: see TAKEOVER.md, the qualified-identifier rewrite is the usual cause" >&2
	exit 1
}
go vet ./...
go test ./... 2>&1 | grep -v 'no test files' || true

echo
echo "remaining khatru references (review each):"
grep -rn 'khatru' --include='*.go' --include='*.md' . | grep -v '^./.git' || echo "  none"
echo
echo "  code hits must be gone; prose hits keep only provenance (NAMING.md):"
echo "    NOTICE, CREDITS, CHANGELOG, docs/history/  -> keep"
echo "    anything else                               -> rename to B Kind"
echo
echo "done. next: TAKEOVER.md phase 3 (tag v1.0.0 after a fresh-consumer go get check)."
