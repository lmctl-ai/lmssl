#!/usr/bin/env bash
# Select by emitted bytecode capability, not CLI version or schema support alone.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -n "${LMSCRIPT_BIN:-}" ]; then
  printf '%s\n' "$LMSCRIPT_BIN"
  exit 0
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lmssl-compiler-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# A native (mingw) python cannot see MSYS /tmp paths: hand it drive-letter paths when cygpath exists.
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi; }
candidate="$(command -v lmscript || true)"
# JSON string quoting also supports checkouts whose paths contain spaces/quotes.
python3 - "$(native "$HERE/schema/lmssl.dsl.json")" "$(native "$WORK")" <<'PY'
import json,pathlib,sys
work=pathlib.Path(sys.argv[2])
(work/'probe.lms').write_text('p = _dsl_ schema='+json.dumps(sys.argv[1])+';\nwhile (false) {}\nend _dsl_\nsavedsl(p, '+json.dumps(str(work/'probe.dslb'))+');\n')
PY
if [ -n "$candidate" ] &&
   "$candidate" --dsl-signatures "$HERE/schema/lmssl.dsl.json" > /dev/null 2>&1 &&
   "$candidate" "$WORK/probe.lms" "$WORK/probe.dslb" > /dev/null 2>&1 &&
   python3 - "$(native "$WORK/probe.dslb")" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1])
sys.exit(0 if p.is_file() and p.read_bytes()[:6] == b'DSLB\x00\x05' else 1)
PY
then
  printf '%s\n' "$candidate"
else
  echo "error: no DSL v5 compiler found; install @lmctl-ai/lmctl so lmscript is on PATH, or set LMSCRIPT_BIN" >&2
  exit 2
fi
