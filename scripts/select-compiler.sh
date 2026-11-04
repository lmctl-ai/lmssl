#!/usr/bin/env bash
set -euo pipefail
MIN_VERSION="0.2.454"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lmcode-compiler-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) WORK="$(cd "$WORK" && pwd -W | tr '\\' '/')" ;;
esac
candidate="${LMSCRIPT_BIN:-}"
if [[ -z "$candidate" ]]; then candidate="$(command -v lmscript || true)"; fi
if [[ -z "$candidate" ]]; then echo "error: no lmscript compiler found; install @lmctl-ai/lmctl >= $MIN_VERSION or set LMSCRIPT_BIN" >&2; exit 2; fi
# Validate capabilities, not the package version: the compiler must check an
# _lmcode_ block against a raw host schema and know run_lmcode. It writes no
# bytecode files any more; test.sh checks the v6 header and schema hash on the
# private program files the host receives.
SCHEMA="$WORK/implicit-std.schema.json"
cat > "$SCHEMA" <<'JSON'
{"dsl.schema":2,"name":"implicit_std_probe","types":{},"functions":{},"context":{}}
JSON
python3 - "$SCHEMA" "$WORK" <<'PY'
import json, pathlib, sys
schema, work = sys.argv[1:]
pathlib.Path(work, 'probe-lmcode.lms').write_text(
    f'p = _lmcode_ schema={json.dumps(schema)};\n'
    'let value = <<~STD_PROBE;\n'
    '  raw ${not_an_outer_field} "quotes"\n'
    '  STD_PROBE\n'
    'let n = str_len(value);\n'
    'end _lmcode_\n'
    'r = run_lmcode(p, {command: ["lmssl", "--lmcode", "$DSLFILE"]});\n')
PY
"$candidate" --check "$WORK/probe-lmcode.lms" >"$WORK/compiler.out" 2>"$WORK/compiler.err" || { cat "$WORK/compiler.err" >&2; echo "error: compiler cannot check an _lmcode_ block with run_lmcode against the host schema" >&2; exit 2; }
"$candidate" --lmcode-signatures "$SCHEMA" | grep -Fq 'fn str_len(string) -> int' || { echo "error: compiler inspection surface lacks implicit std fn str_len(string) -> int" >&2; exit 2; }
printf '%s\n' "$candidate"
