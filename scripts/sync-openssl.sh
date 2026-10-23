#!/usr/bin/env bash
# Fetch the OpenSSL release pinned in openssl.lock into third_party/openssl (shallow clone of the tag),
# or verify an existing checkout. `scripts/sync-openssl.sh --update TAG` re-pins to another release tag.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$HERE/openssl.lock"
DEST="$HERE/third_party/openssl"
get() { sed -n "s/^$1=//p" "$LOCK"; }
if [ "${1:-}" = "--update" ]; then
  tag="${2:?tag, e.g. openssl-4.0.3}"
  commit="$(git ls-remote https://github.com/openssl/openssl.git "refs/tags/$tag^{}" | cut -f1)"
  [ -n "$commit" ] || commit="$(git ls-remote https://github.com/openssl/openssl.git "refs/tags/$tag" | cut -f1)"
  [ -n "$commit" ] || { echo "no such tag: $tag" >&2; exit 1; }
  printf 'repo=https://github.com/openssl/openssl.git\ntag=%s\ncommit=%s\n' "$tag" "$commit" > "$LOCK"
fi
tag="$(get tag)"; want="$(get commit)"; repo="$(get repo)"
if [ ! -d "$DEST/.git" ]; then
  mkdir -p "$HERE/third_party"
  git clone --quiet --depth 1 --branch "$tag" "$repo" "$DEST"
fi
have="$(git -C "$DEST" rev-parse HEAD)"
if [ "$have" != "$want" ]; then
  echo "third_party/openssl is at $have but openssl.lock pins $want ($tag)" >&2
  exit 1
fi
if [ "${1:-}" = "--verify" ]; then echo "third_party/openssl matches openssl.lock ($tag)"; fi
