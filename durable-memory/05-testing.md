# 05 — Testing

`./test.sh` is the whole suite (19 checks without the network, 20 with `LMSSL_NETWORK=1`). It builds first, so it also
proves the OpenSSL build and the link.

| Group | What it proves |
| --- | --- |
| pins | `sdk.lock` hash of `cpp/dslvm.hpp`; `openssl.lock` commit equals `third_party/openssl` HEAD |
| build | configure + build succeeds; on Linux `ldd` reports "not a dynamic executable" |
| protocol | `--version`; `--lmcode-schema --json` is byte-identical to the schema file; host signatures equal `lmscript --lmcode-signatures` |
| CLI half | `version`, `dgst`, `req -x509` (needs the embedded `openssl.cnf`), `x509` work from the same binary |
| examples | each example is compiled and run; outputs are checked, then **cross-checked by the other half**: `openssl verify` of the DSL-made chain, `x509 -ext subjectAltName` of the wildcard, `req -verify` of the DSL-made CSR, key file mode 0600 |
| TLS | `serve-https` + `https-steps` with a redirect (`/old` -> `/new`), handshake trace and chain; `s_client` (CLI half) against the DSL server; mutual TLS where the server reads the client certificate subject |
| failures | `out.fail` exit 4 and the one-line `--json` result; tampered AEAD exit 3; client with no trust anchors refuses a self-signed server; trusted chain with a wrong host name refuses; truncated, missing and foreign-schema bytecode refused exit 3 |
| network | optional: `https-steps` against `google.com` through the OS trust store, including the redirect |

Servers started by the test are background lmssl processes on port 0; the test waits for the `DIR/port` file they write,
and an exit trap kills any still running.

## Sanitizers

The host compiles standalone against the built archives, so an ASan/UBSan build is one command:

```sh
g++ -std=c++17 -g -fsanitize=address,undefined -Icpp -Ibuild/generated -Ibuild/openssl/include -Ithird_party/openssl/include \
  -DLMSSL_VERSION='"x"' cpp/main.cpp cpp/host.cpp build/openssl/liblmssl_cli.a build/openssl/apps/libapps.a \
  build/openssl/libssl.a build/openssl/libcrypto.a -lpthread -ldl -o /tmp/lmssl-asan
```

Run the examples with it (the OpenSSL archives are not instrumented, which is fine for host bugs).

## Bugs the pipeline caught while building this

- **Dangling lambda captures.** `register_host` registers closures that captured `[&]` locals (`strlist`, the registration
  helper `g`). They survive `register_host`'s return, so any call crashed (segfault on the first `str_list()` /
  `ssl.args()`). ASan pinpointed it as `stack-buffer-overflow` in the closure. Rule now: closures capture shared state by
  value (`strlist`) or through the `shared_ptr<Reg>` kept alive in `Host::arena`.
- **Conn.peer after TLS upgrade.** The server example printed the peer address after `ctx.accept(conn)`; the plain
  `Conn` was already owned by the `SSL`. Addresses are now captured when the connection is created.
- **`--json` phase for `out.fail`.** The SDK standard reports phase `app` for APP_FAIL; the first version said `run`.
- **`ldd` under `pipefail`.** `ldd` of a static binary exits 1; the check captures the output with `|| true`.
- **Wrong expected base64** in `crypto-basics` (`"lmssl"` is `bG1zc2w=`): the script's own check caught the author.
- **OpenSSL 4.0 API changes** listed in 02.

## Adding a check

Compile a `.lms` with `compile file.lms $WORK/x.dslb`, run it with `run $WORK/x.dslb ARGS`, assert on stdout, and where
possible validate the artefact with the CLI half (`"$HOST" x509 ...`). Use `expect_exit CODE description cmd...` for failures.
