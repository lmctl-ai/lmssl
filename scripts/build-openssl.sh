#!/usr/bin/env bash
# Build the pinned OpenSSL (third_party/openssl) as static libraries and repackage the `openssl`
# command line so lmssl can link it: usage: scripts/build-openssl.sh BUILD_DIR [JOBS]
# Produces in BUILD_DIR: libcrypto.a libssl.a apps/libapps.a liblmssl_cli.a
# liblmssl_cli.a holds every app object of apps/openssl, with apps/openssl.c's main() renamed
# to lmssl_openssl_main so that lmssl's own main() can dispatch to it.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$HERE/third_party/openssl"
BUILD="${1:?build dir}"
JOBS="${2:-4}"
[ -f "$SRC/Configure" ] || { echo "third_party/openssl missing: run scripts/sync-openssl.sh" >&2; exit 1; }
mkdir -p "$BUILD"
BUILD="$(cd "$BUILD" && pwd)"
cd "$BUILD"

EXE=""; O=".o"; TARGET=(); EXTRA=()
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) EXE=".exe"; O=".obj"; TARGET=(mingw64) ;;
  Linux) EXTRA=(-static) ;;
esac

PERL=perl

if [ ! -f Makefile ]; then
  # no-dso/no-shared: one static link; no-module: providers are built in; no-tests/no-docs: smaller, faster.
  "$PERL" "$SRC/Configure" ${TARGET[@]+"${TARGET[@]}"} no-shared no-dso no-tests no-docs no-module no-afalgeng \
    enable-ssl-trace --libdir=lib ${EXTRA[@]+"${EXTRA[@]}"}
fi

MAKE=make; command -v make >/dev/null 2>&1 || MAKE=mingw32-make
$MAKE -j"$JOBS" build_libs
rm -f apps/openssl-bin-openssl$O   # a previous run left the renamed-main object; rebuild the stock one
$MAKE -j"$JOBS" "apps/openssl$EXE"

# Recompile only apps/openssl.c with main renamed (a command-line CPPFLAGS applies to this one target).
rm -f apps/openssl-bin-openssl$O
$MAKE "apps/openssl-bin-openssl$O" "CPPFLAGS=-Dmain=lmssl_openssl_main"

rm -f liblmssl_cli.a
objs=(apps/openssl-bin-*$O apps/lib/openssl-bin-*$O)
ar rcs liblmssl_cli.a "${objs[@]}"
ranlib liblmssl_cli.a 2>/dev/null || true
ls -l libcrypto.a libssl.a apps/libapps.a liblmssl_cli.a
