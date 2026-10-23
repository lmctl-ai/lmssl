#!/usr/bin/env bash
# Build lmssl and run every check. Needs: cmake, a C/C++ toolchain, perl, make, and lmscript (@lmctl-ai/lmctl, DSL v5).
# The network example (https-steps against a public site) is skipped unless LMSSL_NETWORK=1.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
BUILD_DIR="${BUILD_DIR:-build}"
EXE=""
UNAME_S="$(uname -s)"
case "$UNAME_S" in MINGW*|MSYS*|CYGWIN*) EXE=".exe";; esac
HOST="$BUILD_DIR/lmssl$EXE"
TIMEOUT_CMD=timeout
command -v timeout >/dev/null 2>&1 || TIMEOUT_CMD=gtimeout
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lmssl-test-XXXXXX")"
SERVERS=()
cleanup() {
  for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT
case "$UNAME_S" in MINGW*|MSYS*|CYGWIN*) WORK="$(cd "$WORK" && pwd -W | tr '\\' '/')";; esac
pass=0
ok(){ pass=$((pass+1)); echo "ok $pass - $1"; }
fail(){ echo "FAIL: $*" >&2; exit 1; }

LMSCRIPT="$(scripts/select-compiler.sh)"
scripts/sync-sdk.sh --verify >/dev/null || fail "SDK header pin mismatch"
ok "SDK header matches sdk.lock"
scripts/sync-openssl.sh --verify >/dev/null || fail "OpenSSL pin mismatch"
ok "third_party/openssl matches openssl.lock"

cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release > "$WORK/cmake.log" 2>&1 || { cat "$WORK/cmake.log"; fail "cmake configure"; }
cmake --build "$BUILD_DIR" -j 4 > "$WORK/build.log" 2>&1 || { tail -50 "$WORK/build.log"; fail "build"; }
[ -x "$HOST" ] || fail "no $HOST"
ok "lmssl built ($(wc -c < "$HOST" | tr -d ' ') bytes)"

if [ "$UNAME_S" = Linux ] && command -v ldd >/dev/null; then
  LDD_OUT="$(ldd "$HOST" 2>&1 || true)"
  case "$LDD_OUT" in *"not a dynamic executable"*|*"statically linked"*) ;; *) fail "binary is not fully static: $LDD_OUT";; esac
  ok "fully static (ldd)"
fi

# ---- version and schema protocol
"$HOST" --version | grep -q '^lmssl [0-9]' || fail "--version"
ok "--version"
"$HOST" --dsl-schema --json > "$WORK/schema.json"
cmp -s "$WORK/schema.json" schema/lmssl.dsl.json || fail "embedded schema differs from schema/lmssl.dsl.json"
ok "--dsl-schema --json is byte-identical to the schema file"
"$HOST" --dsl-signatures | tr -d '\r' > "$WORK/host.sig"
"$LMSCRIPT" --dsl-signatures schema/lmssl.dsl.json | tr -d '\r' > "$WORK/schema.sig"
diff "$WORK/host.sig" "$WORK/schema.sig" > /dev/null || { diff "$WORK/host.sig" "$WORK/schema.sig" | head; fail "registry and schema signatures differ"; }
ok "host registry signatures equal the compiler's view of the schema ($(wc -l < "$WORK/host.sig" | tr -d ' ') entries)"

# ---- it is still the OpenSSL command line
"$HOST" version | grep -q '^OpenSSL 4' || fail "openssl version"
[ "$(printf abc | "$HOST" dgst -sha256 -r | cut -d' ' -f1)" = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad ] || fail "openssl dgst"
"$HOST" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$WORK/k.pem" -out "$WORK/c.pem" \
  -subj "/CN=cli.test" -days 2 > /dev/null 2>&1 || fail "openssl req -x509 (embedded default openssl.cnf)"
"$HOST" x509 -in "$WORK/c.pem" -noout -subject | grep -q 'cli.test' || fail "openssl x509"
ok "OpenSSL commands work (version, dgst, req -x509, x509)"

# ---- DSL helpers
compile() { "$LMSCRIPT" "$1" "$2" > "$WORK/compile.log" 2>&1 || { cat "$WORK/compile.log"; fail "compile $1"; }; }
run() { "$HOST" --dsl "$@"; }
expect_exit() { # want-code description cmd...
  local want="$1" what="$2"; shift 2
  set +e; "$@" > "$WORK/out.txt" 2> "$WORK/err.txt"; local rc=$?; set -e
  [ "$rc" = "$want" ] || { cat "$WORK/out.txt" "$WORK/err.txt"; fail "$what: exit $rc, wanted $want"; }
}

# ---- examples
compile examples/crypto-basics.lms "$WORK/crypto.dslb"
run "$WORK/crypto.dslb" > "$WORK/crypto.txt" || fail "crypto-basics"
grep -q '^ok  sha256(abc) = ba7816bf' "$WORK/crypto.txt" && grep -q '^ok  open = attack at dawn' "$WORK/crypto.txt" || fail "crypto-basics output"
ok "example crypto-basics (digest, HMAC, PBKDF2, AEAD, signatures)"

compile examples/selfsigned-wildcard.lms "$WORK/wild.dslb"
run "$WORK/wild.dslb" "$WORK/wild" > "$WORK/wild.txt" || fail "selfsigned-wildcard"
grep -q 'matches www.example.test: yes' "$WORK/wild.txt" && grep -q 'matches a.b.example.test: no' "$WORK/wild.txt" || fail "wildcard matching output"
"$HOST" x509 -in "$WORK/wild/cert.pem" -noout -ext subjectAltName | grep -q 'DNS:\*\.example\.test' || fail "openssl x509 reads the wildcard SAN"
"$HOST" verify -CAfile "$WORK/wild/cert.pem" "$WORK/wild/cert.pem" > /dev/null || fail "openssl verify of the self-signed wildcard"
[ "$("$HOST" pkey -in "$WORK/wild/key.pem" -pubout | "$HOST" dgst -sha256 -r | cut -d' ' -f1)" != "" ] || fail "openssl pkey reads the key"
if [ "$UNAME_S" != "${UNAME_S#MINGW}" ]; then :; else
  [ "$(stat -c %a "$WORK/wild/key.pem" 2>/dev/null || stat -f %Lp "$WORK/wild/key.pem")" = 600 ] || fail "private key must be mode 600"
fi
ok "example selfsigned-wildcard (output verified by the openssl CLI half of the same binary)"

compile examples/ca-and-leaf.lms "$WORK/pki.dslb"
run "$WORK/pki.dslb" "$WORK/pki" > "$WORK/pki.txt" || fail "ca-and-leaf"
grep -q 'signed by an impostor CA:        false' "$WORK/pki.txt" || fail "ca-and-leaf output"
"$HOST" verify -CAfile "$WORK/pki/ca.pem" "$WORK/pki/server.pem" > /dev/null || fail "openssl verify of the leaf against the DSL-made CA"
"$HOST" req -in "$WORK/pki/server.csr" -noout -verify > /dev/null 2>&1 || fail "openssl req -verify of the DSL-made CSR"
ok "example ca-and-leaf (chain verified by openssl verify, CSR by openssl req -verify)"

# ---- TLS between two lmssl processes: serve-https.lms + https-steps.lms with a redirect
compile examples/serve-https.lms "$WORK/serve.dslb"
compile examples/https-steps.lms "$WORK/steps.dslb"
rm -rf "$WORK/server"
run "$WORK/serve.dslb" 0 2 "$WORK/server" > "$WORK/serve.log" 2>&1 &
SERVERS+=($!)
for _ in $(seq 1 100); do [ -s "$WORK/server/port" ] && break; sleep 0.1; done
PORT="$(cat "$WORK/server/port")"
[ -n "$PORT" ] || fail "server did not start: $(cat "$WORK/serve.log")"
$TIMEOUT_CMD 60 "$HOST" --dsl "$WORK/steps.dslb" localhost "$PORT" /old "$WORK/server/cert.pem" > "$WORK/steps.txt" || { cat "$WORK/steps.txt" "$WORK/serve.log"; fail "https-steps against the local server"; }
grep -q 'HTTP/1.1 302 Found' "$WORK/steps.txt" && grep -q 'request 2: https://localhost:'"$PORT"'/new' "$WORK/steps.txt" \
  && grep -q 'HTTP/1.1 200 OK' "$WORK/steps.txt" && grep -q 'verification: ok' "$WORK/steps.txt" \
  && grep -q 'ClientHello' "$WORK/steps.txt" && grep -q 'sni:      localhost' "$WORK/steps.txt" || { cat "$WORK/steps.txt"; fail "https-steps output"; }
wait "${SERVERS[0]}" 2>/dev/null || true
ok "examples serve-https + https-steps (TCP, TLS 1.3 handshake trace, chain, redirect, HTTP over TLS)"

# ---- the OpenSSL s_client half talks to a DSL-made server too
rm -rf "$WORK/server2"
run "$WORK/serve.dslb" 0 1 "$WORK/server2" > "$WORK/serve2.log" 2>&1 &
SERVERS+=($!)
for _ in $(seq 1 100); do [ -s "$WORK/server2/port" ] && break; sleep 0.1; done
PORT2="$(cat "$WORK/server2/port")"
printf 'GET /x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' | $TIMEOUT_CMD 30 "$HOST" s_client -connect "localhost:$PORT2" \
  -servername localhost -CAfile "$WORK/server2/cert.pem" -verify_hostname localhost -quiet > "$WORK/sclient.txt" 2>&1 || true
grep -q 'hello from lmssl' "$WORK/sclient.txt" || { cat "$WORK/sclient.txt"; fail "openssl s_client against the DSL server"; }
ok "openssl s_client (same binary) talks to the DSL TLS server"

# ---- mutual TLS
compile tests/serve-mtls.lms "$WORK/smtls.dslb"
compile tests/mtls.lms "$WORK/mtls.dslb"
rm -rf "$WORK/mtls"
run "$WORK/smtls.dslb" 0 "$WORK/mtls" > "$WORK/smtls.log" 2>&1 &
SERVERS+=($!)
for _ in $(seq 1 100); do [ -s "$WORK/mtls/port" ] && break; sleep 0.1; done
$TIMEOUT_CMD 30 "$HOST" --dsl "$WORK/mtls.dslb" "$(cat "$WORK/mtls/port")" "$WORK/mtls" > "$WORK/mtls.txt" || { cat "$WORK/mtls.txt" "$WORK/smtls.log"; fail "mutual TLS"; }
grep -q 'server says: hello CN=alice,O=clients' "$WORK/mtls.txt" || { cat "$WORK/mtls.txt"; fail "mutual TLS identity"; }
ok "mutual TLS (server requires and reads the client certificate)"

# ---- failure paths and exit codes
compile tests/fail-app.lms "$WORK/fapp.dslb"
expect_exit 4 "out.fail" "$HOST" --dsl "$WORK/fapp.dslb"
grep -q 'deliberate application failure' "$WORK/err.txt" || fail "app failure message"
expect_exit 4 "out.fail --json" "$HOST" --json --dsl "$WORK/fapp.dslb"
grep -q '"phase": "app"' "$WORK/out.txt" && [ "$(wc -l < "$WORK/out.txt" | tr -d ' ')" = 1 ] || { cat "$WORK/out.txt"; fail "--json prints exactly one result line"; }
ok "out.fail exits 4; --json keeps stdout to one result line"

compile tests/fail-aead.lms "$WORK/faead.dslb"
expect_exit 3 "tampered AEAD" "$HOST" --dsl "$WORK/faead.dslb"
grep -q 'authentication failed' "$WORK/err.txt" || fail "AEAD message"
ok "tampered AEAD message is rejected (exit 3)"

rm -rf "$WORK/server3"
run "$WORK/serve.dslb" 0 1 "$WORK/server3" > "$WORK/serve3.log" 2>&1 &
SERVERS+=($!)
for _ in $(seq 1 100); do [ -s "$WORK/server3/port" ] && break; sleep 0.1; done
compile tests/fail-trust.lms "$WORK/ftrust.dslb"
expect_exit 3 "untrusted server" "$HOST" --dsl "$WORK/ftrust.dslb" "$(cat "$WORK/server3/port")"
grep -q 'certificate verify' "$WORK/err.txt" || { cat "$WORK/err.txt"; fail "trust failure message"; }
ok "client without trust anchors refuses a self-signed server (exit 3)"

rm -rf "$WORK/server4"
run "$WORK/serve.dslb" 0 1 "$WORK/server4" > "$WORK/serve4.log" 2>&1 &
SERVERS+=($!)
for _ in $(seq 1 100); do [ -s "$WORK/server4/port" ] && break; sleep 0.1; done
compile tests/fail-hostname.lms "$WORK/fhost.dslb"
expect_exit 3 "wrong host name" "$HOST" --dsl "$WORK/fhost.dslb" "$(cat "$WORK/server4/port")" "$WORK/server4/cert.pem"
grep -q 'hostname mismatch\|certificate verify' "$WORK/err.txt" || { cat "$WORK/err.txt"; fail "hostname failure message"; }
ok "trusted chain with the wrong host name is refused (exit 3)"

# ---- loader refusals happen before anything runs
printf 'DSLB' > "$WORK/trunc.dslb"
expect_exit 3 "truncated bytecode" "$HOST" --dsl "$WORK/trunc.dslb"
expect_exit 3 "missing bytecode" "$HOST" --dsl "$WORK/does-not-exist.dslb"
cat > "$WORK/other.schema.json" <<'EOF'
{"dsl.schema": 2, "name": "other", "types": {"T": {"methods": {"go": [{"params": [], "returns": "void"}]}}}, "functions": {}, "context": {"t": "T"}}
EOF
cat > "$WORK/other.lms" <<EOF
p = _dsl_ schema="$WORK/other.schema.json";
t.go();
end _dsl_
savedsl(p, "$WORK/other.dslb");
EOF
"$LMSCRIPT" "$WORK/other.lms" > /dev/null 2>&1 || fail "compile other schema"
expect_exit 3 "foreign schema" "$HOST" --dsl "$WORK/other.dslb"
grep -qi 'schema' "$WORK/err.txt" || { cat "$WORK/err.txt"; fail "schema mismatch message"; }
ok "truncated, missing and foreign-schema bytecode are refused (exit 3)"

if [ "${LMSSL_NETWORK:-0}" = 1 ]; then
  $TIMEOUT_CMD 90 "$HOST" --dsl "$WORK/steps.dslb" google.com > "$WORK/net.txt" || { cat "$WORK/net.txt"; fail "https-steps google.com"; }
  grep -q 'verification: ok' "$WORK/net.txt" && grep -q 'HTTP/1.1 [23]' "$WORK/net.txt" || { cat "$WORK/net.txt"; fail "google.com output"; }
  ok "network: https-steps google.com (system trust store, redirect)"
fi
echo "PASS $pass checks"
