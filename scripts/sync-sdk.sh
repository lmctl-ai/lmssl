#!/usr/bin/env bash
# Vendor the VM and every SDK catalog header from one pinned commit.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="${LMCODE_CPP:-$HERE/../lmcode-cpp}"
LOCK="$HERE/sdk.lock"
hash() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -c1-64; }
if [ "${1:-}" = "--verify" ]; then
  [ -f "$LOCK" ] || { echo "sdk.lock missing" >&2; exit 1; }
  count=0
  while IFS='=' read -r key want; do
    case "$key" in
      sha256.*)
        file="${key#sha256.}"
        [ -f "$HERE/$file" ] && [ "$(hash "$HERE/$file")" = "$want" ] || { echo "$file differs from sdk.lock: run scripts/sync-sdk.sh" >&2; exit 1; }
        count=$((count+1)) ;;
    esac
  done < "$LOCK"
  [ "$count" -gt 0 ] || { echo "sdk.lock has no per-file hashes" >&2; exit 1; }
  for file in "$HERE/cpp/dslvm.hpp" "$HERE"/cpp/stdlib/*.hpp "$HERE/cpp/std/lmcode-std.schema.json" "$HERE/scripts/merge-std.py"; do
    [ -f "$file" ] || { echo "missing SDK header: $file" >&2; exit 1; }
    relative="${file#"$HERE/"}"
    want="$(awk -F= -v key="sha256.$relative" '$1 == key {print $2}' "$LOCK")"
    [ "$want" = "$(hash "$file")" ] || { echo "$relative is not pinned in sdk.lock" >&2; exit 1; }
  done
  echo "$count SDK headers match sdk.lock"
  exit 0
fi
ref="${LMCODE_CPP_REF:-origin/main}"
commit="$(git -C "$SDK" rev-parse "$ref")"
mkdir -p "$HERE/cpp/stdlib" "$HERE/cpp/std"
printf 'repo=https://github.com/lmctl-ai/lmcode-cpp\ncommit=%s\n' "$commit" > "$LOCK"
while IFS= read -r source; do
  case "$source" in include/dslvm.hpp) target=cpp/dslvm.hpp ;; stdlib/*.hpp) target="cpp/$source" ;; std/lmcode-std.schema.json) target="cpp/$source" ;; scripts/merge-std.py) target="$source" ;; *) continue ;; esac
  git -C "$SDK" show "$commit:$source" > "$HERE/$target"
  printf 'sha256.%s=%s\n' "$target" "$(hash "$HERE/$target")" >> "$LOCK"
done < <(git -C "$SDK" ls-tree -r --name-only "$commit" -- include/dslvm.hpp stdlib/ std/lmcode-std.schema.json scripts/merge-std.py)
echo "synced SDK headers from lmcode-cpp $commit"
