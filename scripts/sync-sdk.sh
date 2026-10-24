#!/usr/bin/env bash
# Vendor the single-source lmcode-cpp header and pin both its commit and content hash.
set -eu
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="${LMCODE_CPP:-$HERE/../lmcode-cpp}"
LOCK="$HERE/sdk.lock"
HEADER="$HERE/cpp/dslvm.hpp"
hash() { sha256sum "$1" | cut -c1-64; }
if [ "${1:-}" = "--verify" ]; then
  [ -f "$LOCK" ] || { echo "sdk.lock missing" >&2; exit 1; }
  want="$(sed -n 's/^sha256=//p' "$LOCK")"
  have="$(hash "$HEADER")"
  [ "$want" = "$have" ] || { echo "cpp/dslvm.hpp sha256 $have differs from sdk.lock $want: run scripts/sync-sdk.sh" >&2; exit 1; }
  echo "cpp/dslvm.hpp matches sdk.lock ($(sed -n 's/^commit=//p' "$LOCK"))"
  exit 0
fi
[ -f "$SDK/include/dslvm.hpp" ] || { echo "lmcode-cpp checkout not found at $SDK (set LMCODE_CPP)" >&2; exit 1; }
ref="${LMCODE_CPP_REF:-origin/main}"
commit="$(git -C "$SDK" rev-parse "$ref")"
git -C "$SDK" show "$commit:include/dslvm.hpp" > "$HEADER"
printf 'repo=https://github.com/lmctl-ai/lmcode-cpp\ncommit=%s\nsha256=%s\n' "$commit" "$(hash "$HEADER")" > "$LOCK"
echo "synced cpp/dslvm.hpp from lmcode-cpp $commit"
