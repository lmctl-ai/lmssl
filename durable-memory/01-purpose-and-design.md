# 01 — Purpose and design

## What it is

`lmssl` is one statically linked executable with two faces:

1. **The OpenSSL command line.** `lmssl x509 ...`, `lmssl s_client ...`, `lmssl req ...` behave like `openssl`: the
   code is OpenSSL's own `apps/` directory, unmodified, compiled and linked in.
2. **A DSL host.** `lmssl --dsl FILE.dslb [ARGS]` loads lmscript `_dsl_` bytecode, verifies it against the embedded
   schema (`schema/lmssl.dsl.json`) and runs it against libcrypto/libssl through a small typed object API.

The aim is **understanding**, not convenience. Every step that `openssl req -x509` or `curl https://...` hides is one
named call in the DSL (`gen_ec`, `new_cert`, `san`, `sign_self`, `net.connect`, `ctx.connect`, `tls.chain_at`, ...), and
the examples print what each step produced. lmssl is deliberately not a curl replacement: no cookies, no chunked
decoding, no connection reuse, no proxies.

## Dispatch (cpp/main.cpp)

```
argv[1] in {--version, --dsl-schema, --dsl-signatures, --dsl, --json}  -> lmssl's own handling
anything else (including none)                                         -> lmssl_openssl_main(argc, argv)
```

`lmssl_openssl_main` is `main` of `apps/openssl.c` renamed at compile time (see 02). The few option names that lmssl
claims all start with `--`, which no OpenSSL command uses as its first word, so there is no ambiguity. `lmssl version`
and `lmssl --version` therefore differ on purpose: the first is OpenSSL's, the second prints `lmssl X.Y.Z (OpenSSL ...)`
because lmscript's `install="github:..."` compares the first two words with the release tag.

`ensure_config()` runs before the OpenSSL half: a static binary has no `OPENSSLDIR`, and `openssl req` aborts without a
config file. If `OPENSSL_CONF` is unset and `<default cert area>/openssl.cnf` does not exist, the stock `apps/openssl.cnf`
(embedded at configure time by CMake) is written to a temp file, `OPENSSL_CONF` points at it, and `atexit` removes it.

## Host-vs-script boundary

Following the SDK rules (bytecode is trusted; the host owns policy):

- The host owns every object: handles are `shared_ptr<void>` entries in `Host::arena`, freed when the run ends. Scripts
  hold handles in locals only; they cannot be stored or compared.
- Secrets never become script-visible by accident: `Key.pem()` exists (the educational point is seeing the key), but
  `Key.save` writes mode 0600 and `Fs.write_private` does the same for arbitrary data.
- Failures are exceptions: any `std::exception` thrown by a method becomes `dslvm::Error("Type.method: message")` with
  the OpenSSL error queue appended (`fail()` in `host.cpp`). A script cannot catch it; the run ends with exit 3.
  `Out.fail(msg)` throws code `APP_FAIL` and ends with exit 4 (phase `app` in `--json` mode).
- The DSL has no collections, so lists are host objects (`StrList.len/at/add/join`), the same pattern lmhtml uses, and
  `for (x in list)` works on any object with `len()` and `at(i)`.

## Output protocol

Human mode (default): `Out.line/text` go to stdout; errors go to stderr as `lmssl: ...`; exit 0/3/4.
`--json` mode: stdout carries exactly one line `{"ok": true, "result": null}` or `{"ok": false, "phase": ..., "code": ...,
"message": ..., "line": N, "column": C}` as in the SDK's result-line standard, and `Out.line/text` write to stderr so the
single-line rule holds. Compile failures are lmscript's (exit 2).

## Why Apache-2.0

OpenSSL 3 and later are Apache-2.0. A static binary that contains OpenSSL must carry its license and NOTICE
obligations; choosing Apache-2.0 for lmssl's own code keeps one license for the whole distribution. The SDK header is
MIT (compatible); its notice is in `THIRD_PARTY_NOTICES.md`.
